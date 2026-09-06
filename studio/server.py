#!/usr/bin/env python3
"""
GP-150 Studio - a local browser UI for building custom Valeton HTFW firmware.

    python server.py [firmware.bin]

Opens the UI in your browser. The HTTP bit is just how the window gets drawn:
it binds loopback only, and there is no network access anywhere in this file.

Depends only on Pillow plus the sibling tools (htfw_tool, lzo1x, lzodll).
Repacking an LZO-packed image (V1.1.1 and later) needs Valeton Suite installed,
because it borrows that install's minilzo_plugin.dll to compress.
"""

import base64
import ctypes
import io
import json
import os
import struct
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:                                   # only used to speed up stride search
    import numpy as _np
except Exception:
    _np = None
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'tools'))
sys.path.insert(0, HERE)

from PIL import Image                      # noqa: E402
import htfw_tool                            # noqa: E402
import gfx_index                            # noqa: E402
import gif_tool                             # noqa: E402
import gp150                                # noqa: E402

PORT = 8765

# Valeton Suite ships its artwork as ordinary PNGs. They are the same images the
# firmware carries, at much higher resolution, so they make the natural source
# when replacing a slot. Read-only, and never copied anywhere by this tool.
_SUITE_TAIL = os.path.join('Valeton Suite', 'data', 'flutter_assets',
                           'assets', 'image')
SUITE_ASSETS = [
    os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'),
                 'Valeton Suite', _SUITE_TAIL),
    os.path.join(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'),
                 'Valeton Suite', _SUITE_TAIL),
]


FONT_DIR = os.path.join(HERE, 'fonts')


def sysfonts():
    """The pedal's own menu typefaces.

    They live in the SDRAM half of section b, which is copied there at boot -
    which is why every earlier search for them, run at the flash base, came back
    empty. `tools/lv_font.py` has the whole story.
    """
    import lv_font
    img = lv_font.Image(fw=PROJECT.fw, body=PROJECT.body)
    out = []
    for k, d in enumerate(lv_font.find(img)):
        f = lv_font.Font(img, d)
        b0, ln = f.span()
        out.append({'i': k, 'dsc': d, 'glyphs': f.count - 1, 'bpp': f.bpp,
                    'height': f.height(), 'bitmap': b0, 'blob': ln,
                    'ascii': f.n_ascii})
    return img, out


CAPTIONS = os.path.join(HERE, 'captions.json')


def read_captions():
    """What each tile's word says, once somebody has told us.

    The words are pictures, so nothing in the file spells them out; typing
    them in is a one-time job, and keeping them here is what turns "change the
    font of every label" into one click on the second run."""
    try:
        with open(CAPTIONS, 'r', encoding='utf-8') as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except Exception:                                         # noqa: BLE001
        return {}


def write_captions(d):
    with open(CAPTIONS, 'w', encoding='utf-8') as fh:
        json.dump(d, fh, ensure_ascii=False, indent=1, sort_keys=True)


def fonts_available():
    """Fonts to draw with: whatever has been uploaded into studio/fonts, then
    what Windows already has. Nothing is copied out of the system directory -
    the file is opened where it lies."""
    out = []
    for d, tag in ((FONT_DIR, 'yours'),
                   (os.path.join(os.environ.get('WINDIR', r'C:\Windows'),
                                 'Fonts'), 'system')):
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if f.lower().endswith(('.ttf', '.otf')):
                out.append({'name': os.path.splitext(f)[0], 'file': f,
                            'path': os.path.join(d, f), 'where': tag})
    return out


def _rgb(v):
    v = (v or '').lstrip('#')
    if len(v) == 3:
        v = ''.join(c * 2 for c in v)
    try:
        return (int(v[0:2], 16), int(v[2:4], 16), int(v[4:6], 16))
    except Exception:                                 # noqa: BLE001
        return (255, 255, 255)


def assets_root():
    for p in SUITE_ASSETS:
        if os.path.isdir(p):
            return p
    return None


# --------------------------------------------------------------------------
# pixel format: 3 bytes per pixel -- little-endian RGB565 first, THEN the alpha
# byte. Settled against the firmware's own image descriptors (tools/gfx_index.py):
# once a descriptor gives the exact first pixel of an image, only this order
# renders the artwork in its real colours. Read alpha-first -- which is what
# these notes said before, and what the earlier hand-checked offsets encoded by
# sitting one byte early -- every picture comes out olive and its alpha is the
# neighbouring pixel's red channel.
# --------------------------------------------------------------------------

def decode_image(buf, off, w, h):
    return gfx_index.decode(buf, off, w, h)


def encode_image(im, w, h, original=None, preserve_alpha=True):
    return gfx_index.encode(im, w, h, original, preserve_alpha)


# --------------------------------------------------------------------------

class Project(object):
    def __init__(self):
        self.path = None
        self.fw = None
        self.body = None          # mutable copy of the unpacked payload
        self.orig = None          # pristine copy, for preserve-alpha and revert
        self.regions = []
        self.images = []
        self.gifs = []
        self.strings = []
        self.edits = 0

    # ---- loading -------------------------------------------------------
    def load(self, path):
        blob = open(path, 'rb').read()
        fw = htfw_tool.Firmware(blob)
        if fw.body is None:
            raise RuntimeError("payload is packed and could not be unpacked")
        self.path = path
        self.fw = fw
        self.orig = bytes(fw.body)
        self.body = bytearray(fw.body)
        self.edits = 0
        self.scan_gifs()
        self.scan_images()
        self.scan_regions()
        self.scan_strings()
        return self.summary()

    def summary(self):
        f = self.fw
        return {
            'path': self.path,
            'model': f.model,
            'version': 'V%d.%d.%d' % f.ver,
            'packed': bool(f.packed),
            'file_size': len(f.blob),
            'payload_size': len(self.body),
            'sections': [{'tag': s.tag, 'flash': s.flash, 'off': s.off,
                          'len': s.len, 'crc': s.crc} for s in f.sections],
            'regions': self.regions,
            'images': len(self.images),
            'gifs': self.gifs,
            'strings': len(self.strings),
            'edits': self.edits,
        }

    # ---- graphics ------------------------------------------------------
    def scan_regions(self):
        """Find graphics by the alpha-plane signature, then estimate row stride."""
        body = self.body
        secs = {s.tag: s for s in self.fw.sections}
        b = secs.get('b')
        if b is None:
            self.regions = []
            return
        lo, hi = b.off, b.off + b.len
        BLK = 6144
        runs = []
        cur = None
        for a in range(lo, hi - BLK, BLK):
            # A pixel is [alpha][RGB565 lo][RGB565 hi]: the alpha byte is the one
            # that is nearly always fully transparent or fully opaque. Any phase
            # clearing the bar marks this block as graphics; which phase it is
            # gets decided later, over the whole run, because two phases can sit
            # within a couple of percent of each other and deciding per block
            # would chop one region into several.
            frac = [self._alpha_frac(a + ph, a + BLK) for ph in (0, 1, 2)]
            # The phase is sticky. A block joins the run in progress as long as
            # that run's phase still holds here, and only a phase that stops
            # working starts a new region. Deciding afresh per block would chop
            # one region into several wherever two phases score within a point
            # of each other; never deciding at all would merge neighbours.
            if cur is not None and a - cur[1] <= BLK * 2 and frac[cur[2]] > 0.80:
                cur[1] = a + BLK
                continue
            best = max((0, 1, 2), key=lambda ph: frac[ph])
            if frac[best] > 0.80:
                if cur:
                    runs.append(cur)
                cur = [a, a + BLK, best]
        if cur:
            runs.append(cur)
        runs = [r for r in runs if r[1] - r[0] >= 24576]

        # Phase holds a run together, but neighbouring regions of different
        # widths share a phase, so a run still has to be cut wherever the row
        # stride changes - the width is the thing that must be constant inside
        # a region, and one width imposed on two of them is what tears the
        # picture.
        out = []
        for a, bb, ph in runs:
            # ph is where the alpha byte sits; a pixel starts one byte on from
            # there (alpha is the third byte, so ph+1 == ph-2 modulo the pixel).
            a += ph + 1                  # start on a whole pixel
            if self._is_constant(a, bb):
                continue                  # erased flash: 0xFF end to end
            if self._looks_like_audio(a, bb):
                continue
            for a0, a1, w in self.width_runs(a, bb):
                if a1 - a0 < 6144:
                    continue
                # A run can change phase part way through - the 32-wide icon
                # sheet does, at row 304, and everything past that point comes
                # out fringed if the whole run is read at one alignment. So walk
                # it and cut wherever the alignment changes.
                for b0, b1, ph in self.phase_runs(a0, a1, w):
                    if b1 - b0 < 6144:
                        continue
                    # phase first (which byte starts a pixel), then the column
                    # origin - doing it the other way round leaves the halves of
                    # a split run framed for the alignment they no longer have
                    # best_phase answers with the byte that starts a whole
                    # pixel, so it is added as it stands
                    b0 += ph
                    b0 = self._align(b0, b1, w)
                    # Last word on the byte phase, measured on the region that
                    # actually came out rather than on the block it started as:
                    # the run can have been cut and rotated since, and being one
                    # byte out is what puts a magenta rim on everything.
                    b0 += self.best_phase(b0, min((b1 - b0) // 3, 20000))
                    out.append({'id': len(out), 'off': b0, 'end': b1,
                                'bytes': b1 - b0, 'width': w,
                                'rows': (b1 - b0) // (w * 3),
                                'name': 'region %d @0x%06X' % (len(out), b0)})
        self.regions = out

    def _is_constant(self, start, end):
        """Erased flash is 0xFF from end to end. It passes the alpha test
        perfectly - every byte is 0 or 255 - and then any width fits it equally
        well, so it turns up in the region list as a large imaginary image."""
        win = self.body[start:min(end, start + 200000)]
        if not win:
            return True
        if _np is not None:
            x = _np.frombuffer(bytes(win), dtype=_np.uint8)
            return float(x.std()) < 0.5
        first = win[0]
        return all(v == first for v in win[::97])

    def _looks_like_audio(self, start, end):
        """Reject 16-bit PCM. Quiet audio is full of 0x00/0xFF sign-extension
        bytes, so it passes the alpha test and gets offered as an image - and
        the firmware keeps waveforms in section b alongside the artwork, so
        this is not hypothetical: painting over one destroys sound, silently.

        Audio has that structure at a period of two bytes, a picture has it at
        three. Whichever period explains the data better says which it is.
        """
        # Sample a contiguous window at full density. Thinning the walk is the
        # obvious optimisation and it is wrong here: pick the stride per period
        # and the two searches can land on the same step - 48 for both 2 and 3 -
        # so they read identical bytes and every region scores as a tie.
        win = self.body[start:min(end, start + 300000)]

        def flat(phase, period):
            if _np is not None:
                x = _np.frombuffer(bytes(win), dtype=_np.uint8)[phase::period]
                return float(_np.mean((x == 0) | (x == 255))) if x.size else 0.0
            n = k = 0
            for o in range(phase, len(win), period):
                v = win[o]
                n += 1
                if v == 0 or v == 255:
                    k += 1
            return k / n if n else 0.0
        p2 = max(flat(ph, 2) for ph in (0, 1))
        p3 = max(flat(ph, 3) for ph in (0, 1, 2))
        return p2 > p3 + 0.05

    def _alpha_frac(self, start, end):
        """How often the byte at this phase is fully 0 or fully 255 - the
        fingerprint of an alpha channel."""
        body = self.body
        n = k = 0
        step = max(3, ((end - start) // 3000) * 3 or 3)
        for o in range(start, end, step):
            v = body[o]
            n += 1
            if v == 0 or v == 255:
                k += 1
        return k / n if n else 0.0

    def _width_scores(self, off, win_px, lo=8, hi=400):
        """Row-difference score for every candidate width over one window of the
        alpha plane, plus the window's spread. Returns (scores, std)."""
        # the alpha plane is the third byte of every pixel
        al = bytes(self.body[off + 2:off + 2 + win_px * 3:3])
        if len(al) < 64:
            return None, 0.0
        if _np is None:
            x = list(al)
            n = len(x)
            mean = sum(x) / n
            std = (sum((v - mean) ** 2 for v in x) / n) ** 0.5
            sc = {}
            for w in range(lo, min(hi, n - 1) + 1):
                sc[w] = sum(abs(x[i] - x[i + w])
                            for i in range(0, n - w, 7)) / max(len(range(0, n - w, 7)), 1)
            return sc, std
        x = _np.frombuffer(al, dtype=_np.uint8).astype(_np.int16)
        sc = {}
        for w in range(lo, min(hi, len(x) - 1) + 1):
            sc[w] = float(_np.abs(x[:len(x) - w] - x[w:]).mean())
        return sc, float(x.std())

    def alpha_width(self, off, n, lo=8, hi=400):
        """Pixel width of the images at `off`, measured on the alpha plane -
        every third byte from the region's first whole pixel.

        Alpha is the silhouette; the colour bytes are noise for this purpose,
        and including them is what made the estimate wobble from window to
        window and shatter one region into dozens of fragments.
        """
        sc, _ = self._width_scores(off, min(n // 3, 8192), lo, hi)
        if not sc:
            return 0
        return min(sc, key=sc.get)

    # A window only starts a new sub-region when its own best width beats the
    # running one by this much. Measured, not guessed: without hysteresis the
    # payload splits into 36 pieces, at 1.35 into 25, and at 1.8 into 19 - and
    # only at 1.8 do the three real groups of the big artwork region come out
    # as 112 / 80 / 48 instead of being cut apart by transitional windows.
    WIDTH_HYSTERESIS = 1.8

    # Tuned against the image, not guessed. The probe is 1024 pixels: at 4096 a
    # region keeps ~50 rows of the next group inside it, which is what put blue
    # streaks and noise under the drum kit. A window only starts a new run when
    # its own best width beats the running one by this much, a window flatter
    # than MIN_STD has nothing to measure and inherits its neighbour's answer,
    # and a run shorter than MIN_RUN windows is absorbed rather than kept - that
    # last one takes the payload from 47 fragments to 29 real groups.
    WIN_PX = 1024
    WIDTH_HYSTERESIS = 1.8
    MIN_STD = 12.0
    MIN_RUN = 3

    def phase_runs(self, off, end, w, block_rows=16):
        """Cut a run wherever the pixel alignment changes. Returns
        (start, end, phase) spans."""
        stride = w * 3
        rows = (end - off) // stride
        if rows < block_rows * 2:
            return [(off, end, self.best_phase(off, min((end - off) // 3, 40000)))]
        marks = []
        prev = None
        for r in range(0, rows - block_rows + 1, block_rows):
            ph = self.best_phase(off + r * stride, block_rows * w)
            if ph is None:
                ph = prev
            marks.append(ph if ph is not None else 0)
            prev = marks[-1]
        spans = []
        i = 0
        while i < len(marks):
            j = i
            while j + 1 < len(marks) and marks[j + 1] == marks[i]:
                j += 1
            s0 = off + i * block_rows * stride
            s1 = end if j + 1 >= len(marks) else off + (j + 1) * block_rows * stride
            spans.append((s0, s1, marks[i]))
            i = j + 1
        return spans

    def fringe(self, off, npx):
        """How colourful the visible pixels are.

        This is the measure that matches what the eye judges. Read a monochrome
        icon sheet one byte out of alignment and the alpha byte lands in the
        colour's low bits, so a white icon comes back with a magenta and cyan
        rim; read it correctly and every visible pixel is grey and this returns
        0.0 exactly. The bimodality test it replaces could not see the
        difference - it scored the aligned and misaligned readings 0.988 against
        0.984, a tie - while this one scores them 0.0 against 102.9.
        """
        if _np is None:
            return None
        buf = bytes(self.body[off:off + npx * 3])
        if len(buf) < npx * 3:
            return None
        a = _np.frombuffer(buf, dtype=_np.uint8).reshape(-1, 3)
        vis = a[:, 2] > 32
        if int(vis.sum()) < 24:
            return None
        v = (a[vis, 0].astype(_np.uint16) | (a[vis, 1].astype(_np.uint16) << 8))
        r = ((v >> 11) & 0x1F) * 255 // 31
        g = ((v >> 5) & 0x3F) * 255 // 63
        b = (v & 0x1F) * 255 // 31
        rgb = _np.stack([r, g, b]).astype(_np.float64)
        return float((rgb.max(0) - rgb.min(0)).mean())

    def alphaness(self, off, npx):
        """How much the third byte of every pixel from `off` behaves like an
        alpha channel: fully transparent or fully opaque, almost always."""
        if _np is None:
            return None
        raw = bytes(self.body[off + 2:off + 2 + npx * 3:3])
        if len(raw) < 64:
            return None
        a = _np.frombuffer(raw, dtype=_np.uint8)
        return float(((a == 0) | (a == 255)).mean())

    def best_phase(self, off, npx, margin=0.05):
        """Which byte offset starts a whole pixel here.

        The alpha plane is the test: a pixel is [colour lo][colour hi][alpha],
        and only at the right phase does that third byte read as a silhouette -
        0 or 255 nearly everywhere. It separates cleanly where the colour-based
        test does not: on the pedal sheet at 0x27C0DA the three phases score
        0.21, 0.21 and 0.95.

        Colour is the tiebreaker rather than the test. Read one byte out, an
        alpha of 0xFF lands in the colour's low bits and pins blue, so a grey
        icon comes back with a magenta rim - but a photograph is colourful at
        every phase, which is why that measure alone once left three of these
        regions two bytes short.
        """
        vals = [self.alphaness(off + d, npx) for d in (0, 1, 2)]
        if all(v is not None for v in vals):
            b = max(range(3), key=lambda i: vals[i])
            others = max(vals[i] for i in range(3) if i != b)
            if vals[b] - others >= margin:
                return b
        fr = []
        for d in (0, 1, 2):
            v = self.fringe(off + d, npx)
            fr.append(1e9 if v is None else v)
        b = min(range(3), key=lambda i: fr[i])
        others = min(fr[i] for i in range(3) if i != b)
        if b != 0 and fr[b] < others * 0.6:
            return b
        return 0

    def _align(self, off, end, w, rows=400):
        """Rotate the frame so that images stop being cut in half.

        A run's start comes out of a windowed search, so it lands near the image
        boundary but not on it, and the frame then slices every object in the
        sheet - that is the "AMP" cut down the middle. With the width known the
        only freedom left is the start modulo w, and the honest test is the seam
        the frame edge creates: pick the rotation where column 0 and column w-1
        are most alike, because in a correctly framed sheet those two columns are
        margin. Alpha is weighted heavily - a transparent margin is the strongest
        evidence there is.
        """
        if _np is None or w < 4:
            return off
        npx = min((end - off) // 3, 200000)
        if npx < w * 8:
            return off
        raw = bytes(self.body[off:off + npx * 3])
        x = _np.frombuffer(raw, dtype=_np.uint8)
        if len(x) < npx * 3:
            return off
        al = x[2::3].astype(_np.float64)
        col = (x[0::3].astype(_np.uint16)
               | (x[1::3].astype(_np.uint16) << 8)).astype(_np.float64)
        # The seam a frame edge makes at shift s is the average of |P[i]-P[i+w-1]|
        # over i congruent to s modulo w. Computing that difference once and
        # binning it by residue costs one pass instead of one pass per shift.
        k = w - 1
        d = (_np.abs(col[:npx - k] - col[k:npx])
             + _np.abs(al[:npx - k] - al[k:npx]) * 40.0)
        idx = _np.arange(len(d)) % w
        tot = _np.bincount(idx, weights=d, minlength=w)
        cnt = _np.bincount(idx, minlength=w).astype(_np.float64)
        cnt[cnt == 0] = 1.0
        return off + int((tot / cnt).argmin()) * 3

    def width_runs(self, off, end, win_px=None):
        """Split a region into stretches that share one width. Regions hold
        groups of differently sized images packed with no separator, so one
        width imposed on all of them tears the picture and a bulk replace at
        that width smears across the lot."""
        win_px = win_px or self.WIN_PX
        total_px = (end - off) // 3
        if total_px < win_px:
            w = self.alpha_width(off, end - off)
            return [(off, end, w)] if w >= 4 else []
        marks = []
        prev = None
        for a in range(0, total_px - win_px + 1, win_px):
            sc, std = self._width_scores(off + a * 3, win_px)
            if not sc or std < self.MIN_STD:
                marks.append(prev)
                continue
            best = min(sc, key=sc.get)
            if prev is not None and sc.get(prev, 1e9) <= sc[best] * self.WIDTH_HYSTERESIS:
                marks.append(prev)
            else:
                prev = best
                marks.append(prev)
        first = next((w for w in marks if w is not None), None)
        if first is None:
            w = self.alpha_width(off, end - off)
            return [(off, end, w)] if w >= 4 else []
        marks = [w if w is not None else first for w in marks]
        runs = []
        for w in marks:
            if runs and runs[-1][1] == w:
                runs[-1][0] += 1
            else:
                runs.append([1, w])
        # absorb slivers, then merge neighbours that ended up the same width
        keep = []
        for c, w in runs:
            if keep and c < self.MIN_RUN:
                keep[-1][0] += c
            else:
                keep.append([c, w])
        merged = []
        for c, w in keep:
            if merged and merged[-1][1] == w:
                merged[-1][0] += c
            else:
                merged.append([c, w])
        out = []
        at = 0
        for i, (c, w) in enumerate(merged):
            a0 = off + at * win_px * 3
            at += c
            a1 = end if i == len(merged) - 1 else off + at * win_px * 3
            if w >= 4:
                a0 = self._align(a0, a1, w)
                out.append((a0, a1, w))
        return out

    # ---- strings -------------------------------------------------------
    # A string table is a *chain*: NUL-terminated printable runs packed one
    # after another, each starting within a few padding bytes of the previous
    # terminator. That is what the firmware's tables actually look like, and it
    # is why an isolated printable run inside code never qualifies - earlier
    # per-string heuristics let those through and mangled the real entries.
    _OK = set(range(32, 127)) | {10}
    _ALLOWED = set(" .+-/%:&()!?,'#\n")

    @classmethod
    def _texty(cls, t):
        """True / False / None, where None means 'no opinion' - single glyphs are
        legitimate table entries but carry no evidence either way."""
        if len(t) < 2:
            return None
        if any(not (c.isalnum() or c in cls._ALLOWED) for c in t):
            return False
        letters = sum(c.isalpha() for c in t)
        return letters >= 1 and letters / len(t) >= 0.34

    def _chain(self, body, i, hi):
        """Read one candidate table starting at i. Returns (entries, next_off)."""
        chain = []
        j = i
        while j < hi:
            k = j
            while k < hi and body[k] in self._OK:
                k += 1
            if k >= hi or body[k] != 0 or not (1 <= k - j <= 80):
                break
            chain.append((j, k - j, bytes(body[j:k]).decode('latin1')))
            m = k
            while m < hi and body[m] == 0:
                m += 1
            if m - k > 8:          # a long NUL gap ends the table
                j = m
                break
            j = m
        return chain, j

    def scan_strings(self, min_len=8, min_good=0.7):
        body = self.body
        secs = {s.tag: s for s in self.fw.sections}
        b = secs.get('b')
        if b is None:
            self.strings = []
            return
        lo, hi = b.off, b.off + b.len
        out = []
        i = lo + 1
        while i < hi:
            if body[i] in self._OK and body[i - 1] == 0:
                chain, nxt = self._chain(body, i, hi)
                if len(chain) >= min_len:
                    judged = [v for v in (self._texty(t) for _, _, t in chain)
                              if v is not None]
                    distinct = len({t for _, _, t in chain})
                    # mostly real words, and not one fragment repeated at a
                    # regular stride - that shape is code, not a table
                    if (judged and sum(judged) / len(judged) >= min_good
                            and distinct / len(chain) >= 0.4):
                        base = chain[0][0]
                        for n, (off, ln, t) in enumerate(chain):
                            nxt_off = chain[n + 1][0] if n + 1 < len(chain) else off + ln + 1
                            out.append({'id': len(out), 'off': off, 'len': ln,
                                        'room': max(ln, nxt_off - off - 1),
                                        'text': t, 'table': base})
                    i = nxt
                    continue
            i += 1
        self.strings = out

    # ---- editing -------------------------------------------------------
    def put_image(self, off, w, h, im, preserve_alpha):
        n = w * h * 3
        if off < 0 or off + n > len(self.body):
            raise ValueError("image would run past the payload")
        sec = self.section_of(off)
        if sec is None or off + n > sec.off + sec.len:
            raise ValueError("image would cross a section boundary")
        self._check_span(off, n, 'replacing that image')
        original = self.orig[off:off + n]
        self.body[off:off + n] = encode_image(im, w, h, original, preserve_alpha)
        self.edits += 1

    def draw_text(self, off, w, h, text, font_path=None, size=0, color=(255, 255, 255),
                  align='center', over=True, keep_alpha=False, outline=0,
                  outline_color=(0, 0, 0), preview=False, dy=0):
        """Draw text into one image slot with a font of your choosing.

        The pedal's own UI font is not in this file - see the Font tab - so this
        does the thing that is actually possible: it renders with any TrueType
        or OpenType font on your machine straight into the artwork, which is
        what putting your own lettering on a pedal icon or a logo tile needs.

        `over` composites onto the picture that is there; with it off the slot
        is cleared to transparent first and only the text remains. `size` 0
        means "as large as fits".
        """
        from PIL import ImageDraw, ImageFont
        n = w * h * 3
        if off < 0 or off + n > len(self.body):
            raise ValueError("that slot is not inside the payload")
        base = gfx_index.decode(self.body, off, w, h) if over             else Image.new('RGBA', (w, h), (0, 0, 0, 0))
        im = base.convert('RGBA')
        if text:
            font = self._font(font_path, size, text, w, h, outline)
            d = ImageDraw.Draw(im)
            box = d.textbbox((0, 0), text, font=font, stroke_width=outline)
            tw, th = box[2] - box[0], box[3] - box[1]
            x = {'left': 0, 'right': w - tw}.get(align, (w - tw) // 2) - box[0]
            y = (h - th) // 2 - box[1] + int(dy)
            d.text((x, y), text, font=font, fill=tuple(color) + (255,),
                   stroke_width=outline, stroke_fill=tuple(outline_color) + (255,))
        if preview:
            return im
        self._check_span(off, n, 'writing that text')
        original = self.orig[off:off + n]
        self.body[off:off + n] = gfx_index.encode(im, w, h, original, keep_alpha)
        self.edits += 1
        return im

    @staticmethod
    def _font(path, size, text, w, h, outline=0):
        from PIL import ImageDraw, ImageFont
        if not path:
            return ImageFont.load_default()
        if size:
            return ImageFont.truetype(path, size)
        # "as large as fits": grow until the text stops fitting the slot
        best = ImageFont.truetype(path, 8)
        probe = Image.new('L', (1, 1))
        d = ImageDraw.Draw(probe)
        for pt in range(8, max(10, h * 3)):
            f = ImageFont.truetype(path, pt)
            b = d.textbbox((0, 0), text, font=f, stroke_width=outline)
            if b[2] - b[0] > w - 2 or b[3] - b[1] > h - 2:
                break
            best = f
        return best

    def put_string(self, off, text):
        s = next((x for x in self.strings if x['off'] == off), None)
        if s is None:
            raise ValueError("no known string at 0x%X" % off)
        raw = text.encode('latin1', 'replace')
        if len(raw) > s['room']:
            raise ValueError("too long: %d bytes, room for %d" % (len(raw), s['room']))
        self.body[off:off + s['room'] + 1] = raw + b'\0' * (s['room'] + 1 - len(raw))
        s['text'] = text
        s['len'] = len(raw)
        self.edits += 1

    @staticmethod
    def _sub(text, find, repl, case):
        """Plain substring replace. Deliberately not a regex: the user types a
        literal label like "Stomp", and a stray "." or "(" in it must not turn
        into a wildcard."""
        if case:
            return text.replace(find, repl)
        out, low, lf = [], text.lower(), find.lower()
        i = 0
        while True:
            j = low.find(lf, i)
            if j < 0:
                out.append(text[i:])
                return "".join(out)
            out.append(text[i:j])
            out.append(repl)
            i = j + len(lf)

    def replace_in_strings(self, find, repl, case=False, offs=None):
        """Substring replace across the string table. A string is rewritten only
        when the result still fits its room, so a rebuild can never shift bytes;
        anything that would overflow is reported back untouched."""
        if not find:
            raise ValueError("nothing to find")
        done, skipped = [], []
        for s in list(self.strings):
            if offs is not None and s['off'] not in offs:
                continue
            new = self._sub(s['text'], find, repl, case)
            if new == s['text']:
                continue
            need = len(new.encode('latin1', 'replace'))
            if need > s['room']:
                skipped.append({'off': s['off'], 'text': s['text'],
                                'want': new, 'need': need, 'room': s['room']})
                continue
            was = s['text']          # put_string overwrites s['text']
            self.put_string(s['off'], new)
            done.append({'off': s['off'], 'was': was, 'now': new})
        return {'changed': len(done), 'items': done, 'skipped': skipped}

    # ---- the firmware's own index --------------------------------------
    # Every stored image carries a 12-byte descriptor with its width and height
    # (tools/gfx_index.py). That replaces the hand-checked list this used to
    # keep: geometry is read, not estimated, so there is nothing to sift and
    # nothing to nudge. The region scan below still runs, for the artwork that
    # has no descriptor.
    def scan_images(self):
        try:
            blobs = gfx_index.scan(self.orig)
        except Exception:                         # noqa: BLE001
            self.images = []
            return
        out = []
        for b in blobs:
            d = b.as_dict()
            d['id'] = len(out)
            d['grade'] = gfx_index.grade(self.orig, b)
            d['filled'] = d['grade'] != 'junk'
            d['name'] = '%dx%d @0x%06X' % (b.w, b.h, b.off)
            out.append(d)
        self.images = out

    def scan_gifs(self):
        """The boot animation is an ordinary GIF sitting in section b, indexed
        by nothing - found by its own magic and walked to its trailer."""
        try:
            self.gifs = gif_tool.find(self.orig)
        except Exception:                             # noqa: BLE001
            self.gifs = []
        for i, g in enumerate(self.gifs):
            g['id'] = i

    def put_gif(self, which, data):
        """Same slot, same length. A GIF reader stops at the trailer, so a
        smaller replacement is padded with zeros it will never look at."""
        if which >= len(self.gifs):
            raise ValueError("no GIF %d in this image" % which)
        g = self.gifs[which]
        if data[:6] not in gif_tool.MAGIC:
            raise ValueError("that file is not a GIF")
        if len(data) > g['len']:
            raise ValueError("replacement is %d bytes and the slot holds %d - "
                             "fewer frames or fewer colours"
                             % (len(data), g['len']))
        pad = bytes(g['len'] - len(data))
        self._check_span(g['off'], g['len'], 'replacing the animation')
        self.body[g['off']:g['off'] + g['len']] = data + pad
        self.edits += 1
        return {'off': g['off'], 'used': len(data), 'room': g['len']}

    def curated(self):
        """The indexed images, artwork first. The descriptors are the
        allocator's, so blocks it never filled are in the file with perfectly
        good geometry and leftover bytes inside; they are graded, not dropped,
        and Studio keeps them behind a toggle."""
        order = {'art': 0, 'unsure': 1, 'junk': 2}
        return sorted(self.images, key=lambda d: (order.get(d['grade'], 3), d['off']))

    def label_score(self, off, w, h):
        """Is this tile lettering, or is it a picture?

        Lettering has a particular shape as data: most of the tile is empty,
        what is drawn is one colour plus the grey of its own antialiasing, and
        the ink does not reach the edges the way a photograph or a gradient
        does. A picture fails all three. This is what lets the Font tab list
        the captions on their own instead of all sixty-odd assets.
        """
        try:
            im = decode_image(self.body, off, w, h).convert('RGBA')
        except Exception:                                     # noqa: BLE001
            return {'text_like': False, 'ink': 0.0, 'colours': 0}
        px = im.load()
        ink = 0
        hues = {}
        edge = 0
        for y in range(h):
            for x in range(w):
                r, g, b, a = px[x, y]
                if a < 128:
                    continue
                ink += 1
                if x == 0 or y == 0 or x == w - 1 or y == h - 1:
                    edge += 1
                mx, mn = max(r, g, b), min(r, g, b)
                # grey is antialiasing, not a colour of its own
                key = 'grey' if mx - mn < 24 else (r >> 5, g >> 5, b >> 5)
                hues[key] = hues.get(key, 0) + 1
        n = float(w * h) or 1.0
        cover = ink / n
        colours = len([k for k, v in hues.items() if v > max(4, ink * 0.01)])
        border = edge / float(2 * (w + h)) if w and h else 1.0
        text_like = (0.02 <= cover <= 0.55 and colours <= 3 and border < 0.35)
        return {'text_like': bool(text_like), 'ink': round(cover, 3),
                'colours': colours, 'border': round(border, 3)}

    # ---- the lettering that is already in the artwork ------------------
    #
    # The block tiles - AMP, CAB, DLY, DST, EQ, MOD, NR, PRE, RVB, VOL, WAH,
    # NAM - are pictures of a pedal with a word printed on it. The word is
    # part of the picture, so re-typefacing the interface means finding that
    # word inside the tile, wiping it, and printing it again in another face.
    # Which is what these two do.

    @staticmethod
    def _lum(r, g, b):
        return 0.299 * r + 0.587 * g + 0.114 * b

    def word_box(self, off, w, h, im=None, thr=34):
        """Where the word sits inside a tile, or None if there is no word.

        Letters are separate blobs, so this finds every blob of ink that
        contrasts with the tile's body colour, then keeps the group of blobs
        that share a baseline - which is what a word is. Blobs that are too
        tall, too wide or too high up the tile are the pedal's own knobs and
        plate, and are dropped before the grouping.
        """
        from collections import Counter, deque
        if im is None:
            try:
                im = decode_image(self.body, off, w, h).convert('RGBA')
            except Exception:                                 # noqa: BLE001
                return None
        px = im.load()
        c = Counter()
        for y in range(h):
            for x in range(w):
                if px[x, y][3] > 200:
                    c[px[x, y][:3]] += 1
        if not c:
            return None
        bl = self._lum(*c.most_common(1)[0][0])
        ink = [[(px[x, y][3] > 150 and abs(self._lum(*px[x, y][:3]) - bl) > thr)
                for x in range(w)] for y in range(h)]
        seen = [[False] * w for _ in range(h)]
        comps = []
        for y in range(h):
            for x in range(w):
                if not ink[y][x] or seen[y][x]:
                    continue
                q = deque([(x, y)])
                seen[y][x] = True
                pts = []
                while q:
                    cx, cy = q.popleft()
                    pts.append((cx, cy))
                    for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1),
                                   (1, 1), (-1, -1), (1, -1), (-1, 1)):
                        nx, ny = cx + dx, cy + dy
                        if 0 <= nx < w and 0 <= ny < h and ink[ny][nx] \
                                and not seen[ny][nx]:
                            seen[ny][nx] = True
                            q.append((nx, ny))
                xs = [p[0] for p in pts]
                ys = [p[1] for p in pts]
                comps.append((min(xs), min(ys), max(xs) + 1, max(ys) + 1, len(pts)))
        g = [c0 for c0 in comps
             if 1 <= c0[2] - c0[0] <= w * 0.55 and 3 <= c0[3] - c0[1] <= h * 0.35
             and c0[4] >= 3 and c0[1] >= h * 0.35]
        if len(g) < 2:
            return None
        best = None
        for seed in g:
            hs = seed[3] - seed[1]
            line = [c0 for c0 in g
                    if min(c0[3], seed[3]) - max(c0[1], seed[1])
                    >= 0.6 * min(c0[3] - c0[1], hs)
                    and 0.55 * hs <= c0[3] - c0[1] <= 1.8 * hs]
            if len(line) < 2:
                continue
            box = (min(c0[0] for c0 in line), min(c0[1] for c0 in line),
                   max(c0[2] for c0 in line), max(c0[3] for c0 in line))
            sc = (len(line), box[2] - box[0], box[1])
            if best is None or sc > best[0]:
                best = (sc, box)
        if best is None or best[1][2] - best[1][0] < 8:
            return None
        return list(best[1])

    def retypeset(self, off, w, h, text, box=None, font_path=None, color=None,
                  pad=1, preview=False, dy=0, grow=0):
        """Print a word again, in another face, where the old one was.

        The ink colour and the colour behind it are read off the tile itself,
        so a grey tile stays grey and a coloured one keeps its own colour -
        this is a change of typeface, not of palette. The new word is fitted
        into the old word's box, so it takes the same room on the screen.
        """
        from PIL import ImageDraw, ImageFont
        im = decode_image(self.body, off, w, h).convert('RGBA')
        if box is None:
            box = self.word_box(off, w, h, im)
        if box is None:
            raise ValueError("no lettering found in the image at 0x%X" % off)
        x0, y0, x1, y1 = [int(v) for v in box]
        px = im.load()
        # what is behind the word: the commonest opaque colour in the ring
        # around its box, which is the tile's own body
        from collections import Counter
        ring = Counter()
        for y in range(max(0, y0 - 2), min(h, y1 + 2)):
            for x in range(max(0, x0 - 3), min(w, x1 + 3)):
                if x0 <= x < x1 and y0 <= y < y1:
                    continue
                p = px[x, y]
                if p[3] > 200:
                    ring[p] += 1
        if not ring:
            raise ValueError("nothing to read the background from at 0x%X" % off)
        back = ring.most_common(1)[0][0]
        bl = self._lum(*back[:3])
        # and the word's own colour: the mean of the pixels that are not it
        acc, n = [0, 0, 0], 0
        for y in range(y0, y1):
            for x in range(x0, x1):
                p = px[x, y]
                if p[3] > 150 and abs(self._lum(*p[:3]) - bl) > 34:
                    acc[0] += p[0]; acc[1] += p[1]; acc[2] += p[2]; n += 1
        ink = color or (tuple(v // n for v in acc) if n else (255, 255, 255))
        # wipe, keeping each pixel's own alpha so nothing punches a hole
        for y in range(max(0, y0 - pad), min(h, y1 + pad)):
            for x in range(max(0, x0 - pad), min(w, x1 + pad)):
                px[x, y] = (back[0], back[1], back[2], px[x, y][3])
        bw, bh = (x1 - x0) + 2 * grow, (y1 - y0) + 2 * grow
        dr = ImageDraw.Draw(im)
        f = self._font(font_path, 0, text, max(bw, 4), max(bh, 4))
        dr.text(((x0 + x1) // 2, (y0 + y1) // 2 + dy), text, font=f,
                anchor='mm', fill=tuple(ink))
        if preview:
            return im
        self.put_image(off, w, h, im, True)
        return {'box': [x0, y0, x1, y1], 'ink': list(ink), 'back': list(back[:3])}

    def detect_icons(self, off, end, w, min_h=6, gap=1):
        """Split a graphics region into individual images.

        The firmware stores icons back to back with fully transparent rows
        between them, so a run of rows that carries any ink is one image. This
        is what makes the region legible: rendered as one continuous strip it
        reads as torn garbage, because a strip glues unrelated images together
        and runs straight through whatever non-image data follows them.
        """
        stride = w * 3
        rows = (end - off) // stride
        if rows < 1:
            return []
        body = self.body
        ink = bytearray(rows)
        for r in range(rows):
            base = off + r * stride
            ink[r] = 1 if any(body[base:base + stride]) else 0
        out = []
        r = 0
        while r < rows:
            if not ink[r]:
                r += 1
                continue
            s = r
            blank = 0
            while r < rows and (ink[r] or blank < gap):
                blank = 0 if ink[r] else blank + 1
                r += 1
            e = r - blank
            if e - s >= min_h:
                out.append({'off': off + s * stride, 'w': w, 'h': e - s,
                            'row': s})
        return out

    def section_of(self, off):
        for s in self.fw.sections:
            if s.off <= off < s.off + s.len:
                return s
        return None

    def revert(self):
        self.body = bytearray(self.orig)
        self.edits = 0
        self.scan_strings()

    # ---- build ---------------------------------------------------------
    def protected(self):
        """The 12 bytes in front of every indexed image. They are the heap's
        own block headers and the firmware reads them: a build that wrote over
        them booted, ran, and drew colour static where every icon should be.
        Nothing here may write into one."""
        return [(d['hdr'], d['hdr'] + gfx_index.HDR) for d in self.images]

    def _check_span(self, off, n, what='that write'):
        for a, b in self.protected():
            if off < b and a < off + n:
                raise ValueError(
                    "%s would run over the image descriptor at 0x%06X. Those "
                    "twelve bytes carry the width, the height and the block's "
                    "address, and the firmware needs them - overwriting them "
                    "is what turns the icons into static." % (what, a))

    def targets(self, scope=None, ids=None, regions=True):
        """Every asset a bulk edit should reach, as (label, off, w, h).

        `ids` picks indexed images by their own id - that is what the screen
        editor sends when you have selected two icons and want only those
        recoloured. `regions` includes the artwork with no descriptor.

        The indexed images first, because those are exact, then whatever the
        region scan turns up outside them - a region is taken whole, since
        inside it nothing says where one picture ends.
        """
        out = []
        blocks = sorted((d['hdr'], d['off'] + d['size']) for d in self.images)
        if ids is not None:
            ids = set(int(i) for i in ids)
            for d in self.images:
                if d['id'] in ids:
                    out.append(('image %d' % d['id'], d['off'], d['w'], d['h']))
            return out
        for d in self.images:
            if d['grade'] == 'junk':
                continue
            out.append(('image %d' % d['id'], d['off'], d['w'], d['h']))
        # A region can start before an indexed block and run straight over it -
        # region 18 of V1.1.1 covers twenty-three of them - so the overlap has
        # to be cut out rather than tested for at the start. What is left of the
        # region is emitted in whole rows, which keeps the pixel phase.
        for r in (self.regions if regions else []):
            stride = r['width'] * 3
            pos = r['off']
            for a, b in blocks:
                if b <= pos or a >= r['end']:
                    continue
                if a > pos:
                    rows = (a - pos) // stride
                    if rows >= 4:
                        out.append(('region %d' % r['id'], pos, r['width'], rows))
                pos = max(pos, b)
            if pos < r['end']:
                rows = (r['end'] - pos) // stride
                if rows >= 4:
                    out.append(('region %d' % r['id'], pos, r['width'], rows))
        if scope:
            out = [t for i, t in enumerate(out) if i in scope]
        return out

    def apply_texture(self, im, scope=None, mode='replace', keep_alpha=True,
                      fit='stretch', opacity=1.0, ids=None):
        """Lay one image over the colour of every asset in the firmware.

        Per asset, not per region. The old version walked a region in payload
        order and tiled the texture along it, so each icon in the region got
        whatever slice of the texture happened to line up with its bytes -
        different for every icon, and nothing at all for the images the region
        scan does not cover, which since the index arrived is most of them.
        Here every image gets the whole texture fitted to its own frame, so a
        sheet of icons comes out looking like a set.

        `fit`: stretch to the image, tile across it, or cover it without
        distorting the aspect. `mode`: replace the colour outright, or multiply
        into it, which keeps the artwork's shading and reads as a tint.
        `opacity`: how far to go towards the texture, 0 to 1 - the result is
        mixed with the colour that was there, so 0.3 tints the artwork and 1
        overwrites it. Alpha is left alone by default; that is what keeps the
        silhouettes.
        """
        if _np is None:
            raise ValueError("this needs numpy")
        im = im.convert('RGB')
        if im.size[0] < 1 or im.size[1] < 1:
            raise ValueError("empty texture")
        targets = self.targets(scope, ids)
        if not targets:
            raise ValueError("nothing to apply it to")
        done = 0
        pixels = 0
        skipped = 0
        for _label, off, w, h in targets:
            n = w * h * 3
            if off < 0 or off + n > len(self.body):
                continue
            sec = self.section_of(off)
            if sec is None or off + n > sec.off + sec.len:
                continue
            try:
                self._check_span(off, n)
            except ValueError:
                skipped += 1
                continue
            tex = self._fit_texture(im, w, h, fit)
            a = _np.frombuffer(bytes(self.body[off:off + n]),
                               dtype=_np.uint8).reshape(h * w, 3).copy()
            r = tex[:, 0].astype(_np.uint16)
            g = tex[:, 1].astype(_np.uint16)
            b = tex[:, 2].astype(_np.uint16)
            if mode == 'multiply':
                c = a[:, 0].astype(_np.uint16) | (a[:, 1].astype(_np.uint16) << 8)
                r = r * (((c >> 11) & 0x1F) * 255 // 31) // 255
                g = g * (((c >> 5) & 0x3F) * 255 // 63) // 255
                b = b * ((c & 0x1F) * 255 // 31) // 255
            if opacity < 1.0:
                c = a[:, 0].astype(_np.uint16) | (a[:, 1].astype(_np.uint16) << 8)
                orr = ((c >> 11) & 0x1F) * 255 // 31
                og = ((c >> 5) & 0x3F) * 255 // 63
                ob = (c & 0x1F) * 255 // 31
                k = float(opacity)
                r = (r * k + orr * (1.0 - k)).astype(_np.uint16)
                g = (g * k + og * (1.0 - k)).astype(_np.uint16)
                b = (b * k + ob * (1.0 - k)).astype(_np.uint16)
            v = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
            a[:, 0] = v & 0xFF
            a[:, 1] = v >> 8
            if not keep_alpha:
                a[:, 2] = 255
            self.body[off:off + n] = a.tobytes()
            done += 1
            pixels += w * h
        self.edits += done
        return {'regions': done, 'targets': len(targets), 'pixels': pixels,
                'skipped': skipped}

    def recolour(self, scope=None, hue=0.0, sat=1.0, light=1.0, tint=None,
                 strength=1.0, keep_alpha=True, ids=None):
        """Shift the colours of whole assets at once - the theming tool.

        A texture paints a picture over the artwork; this keeps the artwork and
        moves it round the colour wheel, which is what "make the interface
        green" actually means. `hue` in degrees, `sat` and `light` as
        multipliers, `tint` pulls everything towards one colour by `strength`.

        Works on the same targets a texture does, and refuses the same spans:
        the twelve bytes in front of each image are the heap's own header and
        the firmware reads them.
        """
        if _np is None:
            raise ValueError("this needs numpy")
        import colorsys
        targets = self.targets(scope, ids)
        if not targets:
            raise ValueError("nothing selected")
        tint_rgb = None
        if tint:
            tint_rgb = _np.array(_rgb(tint), dtype=_np.float32) / 255.0
        done = pixels = skipped = 0
        # one lookup table for all 65536 colours beats touching pixels one by one
        lut = _np.arange(65536, dtype=_np.uint32)
        r = (((lut >> 11) & 0x1F) / 31.0).astype(_np.float32)
        g = (((lut >> 5) & 0x3F) / 63.0).astype(_np.float32)
        b = ((lut & 0x1F) / 31.0).astype(_np.float32)
        mx = _np.maximum(_np.maximum(r, g), b)
        mn = _np.minimum(_np.minimum(r, g), b)
        v = mx
        sdiff = mx - mn
        sv = _np.where(mx > 0, sdiff / _np.where(mx > 0, mx, 1), 0)
        h = _np.zeros_like(r)
        nz = sdiff > 0
        rm = nz & (mx == r)
        gm = nz & (mx == g) & ~rm
        bm = nz & ~rm & ~gm
        h[rm] = ((g - b)[rm] / sdiff[rm]) % 6
        h[gm] = ((b - r)[gm] / sdiff[gm]) + 2
        h[bm] = ((r - g)[bm] / sdiff[bm]) + 4
        h = (h / 6.0 + hue / 360.0) % 1.0
        sv = _np.clip(sv * sat, 0, 1)
        v = _np.clip(v * light, 0, 1)
        i = _np.floor(h * 6).astype(_np.int32) % 6
        f = h * 6 - _np.floor(h * 6)
        p_ = v * (1 - sv)
        q = v * (1 - f * sv)
        t = v * (1 - (1 - f) * sv)
        rr = _np.select([i == 0, i == 1, i == 2, i == 3, i == 4], [v, q, p_, p_, t], t)
        gg = _np.select([i == 0, i == 1, i == 2, i == 3, i == 4], [t, v, v, q, p_], p_)
        bb = _np.select([i == 0, i == 1, i == 2, i == 3, i == 4], [p_, p_, t, v, v], q)
        if tint_rgb is not None:
            k = float(_np.clip(strength, 0, 1))
            rr = rr * (1 - k) + tint_rgb[0] * v * k
            gg = gg * (1 - k) + tint_rgb[1] * v * k
            bb = bb * (1 - k) + tint_rgb[2] * v * k
        out = ((_np.clip(rr, 0, 1) * 31).astype(_np.uint32) << 11)             | ((_np.clip(gg, 0, 1) * 63).astype(_np.uint32) << 5)             | (_np.clip(bb, 0, 1) * 31).astype(_np.uint32)
        lut = out.astype(_np.uint16)
        for _label, off, w, hgt in targets:
            n = w * hgt * 3
            sec = self.section_of(off)
            if sec is None or off + n > sec.off + sec.len:
                continue
            try:
                self._check_span(off, n)
            except ValueError:
                skipped += 1
                continue
            a = _np.frombuffer(bytes(self.body[off:off + n]),
                               dtype=_np.uint8).reshape(-1, 3).copy()
            c = a[:, 0].astype(_np.uint16) | (a[:, 1].astype(_np.uint16) << 8)
            nc = lut[c]
            a[:, 0] = (nc & 0xFF).astype(_np.uint8)
            a[:, 1] = (nc >> 8).astype(_np.uint8)
            if not keep_alpha:
                a[:, 2] = 255
            self.body[off:off + n] = a.tobytes()
            done += 1
            pixels += w * hgt
        self.edits += done
        return {'regions': done, 'targets': len(targets), 'pixels': pixels,
                'skipped': skipped}

    @staticmethod
    def _fit_texture(im, w, h, fit):
        """The texture as (w*h, 3) uint8, framed to one image."""
        if fit == 'tile':
            tw, th = im.size
            canvas = Image.new('RGB', (w, h))
            for y in range(0, h, th):
                for x in range(0, w, tw):
                    canvas.paste(im, (x, y))
            out = canvas
        elif fit == 'cover':
            tw, th = im.size
            s = max(w / float(tw), h / float(th))
            r = im.resize((max(1, int(tw * s)), max(1, int(th * s))),
                          Image.LANCZOS)
            x = (r.size[0] - w) // 2
            y = (r.size[1] - h) // 2
            out = r.crop((x, y, x + w, y + h))
        else:
            out = im.resize((w, h), Image.LANCZOS)
        return _np.frombuffer(out.tobytes(), dtype=_np.uint8).reshape(w * h, 3)

    def build(self, out_path):
        fw = self.fw
        hdr = bytearray(fw.blob[:fw.pack_off if fw.packed else fw.payload])
        body = bytes(self.body)
        for s in fw.sections:
            crc = htfw_tool.crc16_modbus(body[s.off:s.off + s.len])
            struct.pack_into('>H', hdr, s.rec, crc)
            struct.pack_into('<III', hdr, s.rec + 4, s.flash, s.off, s.len)
        struct.pack_into('<I', hdr, 0x24, len(body))
        if fw.packed:
            if htfw_tool.lzodll is None:
                raise RuntimeError("this image is LZO-packed and Valeton Suite's "
                                   "minilzo_plugin.dll was not found - install "
                                   "Valeton Suite to rebuild packed firmware")
            comp = htfw_tool.lzodll.compress(body)
            tail = struct.pack('<I', len(body)) + comp
        else:
            tail = body
        struct.pack_into('<I', hdr, 8, len(hdr) + len(tail))
        # The header carries a CRC of the whole file from offset 6. It has to be
        # stamped last, and leaving it stale is what made every earlier build fail
        # Valeton Suite's own checkCrc().
        data = htfw_tool.seal(bytes(hdr) + tail)
        open(out_path, 'wb').write(data)
        return {'path': out_path, 'size': len(data),
                'original_size': len(fw.blob), 'edits': self.edits}


PROJECT = Project()


# --------------------------------------------------------------------------
# NAM captures
#
# An A2 capture ships two trained submodels, three channels and eight. Suite
# takes the three-channel one because the eight-channel one costs 94% of the
# M7 and cannot run. Nothing forces that choice: the `.namb` describes its own
# width, so a model can be trained at four or five channels - wide enough to
# hear, cheap enough to run. `tools/nam_distill.py` does the training; this is
# the part of it Studio drives, as a background job with a log the page tails.
# --------------------------------------------------------------------------

NAM = {'running': False, 'lines': [], 'stop': False, 'result': None,
       'error': None, 'source': None}
NAM_LOCK = threading.Lock()


def nam_tools():
    """Imported late - numpy is optional for the rest of Studio."""
    import nam2namb
    import nam_distill
    return nam2namb, nam_distill


def nam_say(line):
    with NAM_LOCK:
        NAM['lines'].append(str(line))


def nam_survey(path):
    """What is in a capture, and what each width would cost to run."""
    import copy
    n2, nd = nam_tools()
    nam = n2.load(path)
    subs = n2.submodels(nam)
    la = nd.layer_of(subs[0][1])
    rows = []
    for c in range(int(la['channels']), 9):
        lb = copy.deepcopy(la)
        lb['channels'] = c
        mm = nd.macs(lb)
        w = nd.nweights(lb)
        rows.append({'channels': c, 'weights': w, 'macs': mm,
                     'namb': w * 4 + 496,
                     'load': round(100.0 * mm * 48000.0 / nd.CORE_HZ, 1)})
    meta = nam.get('metadata') or {}
    return {'ok': True, 'name': meta.get('name') or os.path.basename(path),
            'gear': ' '.join(x for x in (meta.get('gear_make'),
                                         meta.get('gear_model')) if x),
            'nam_version': nam.get('version'),
            'container': nam.get('architecture'),
            'rate': nam.get('sample_rate'),
            'layers': len(la['kernel_sizes']),
            'receptive': nd.receptive(la),
            'stock': int(la['channels']),
            'teacher': int(nd.layer_of(subs[-1][1])['channels']),
            'widths': rows}


def nam_esr(path, student=None, seconds=10.0):
    """How far each model is from the eight-channel one it is standing in for."""
    n2, nd = nam_tools()
    di = n2.default_di()
    if di is None:
        raise ValueError("no DI wav found - Valeton Suite ships the one the "
                         "vendor's own converter uses")
    x = n2.read_di(di, 48000, seconds)
    nam = n2.load(path)
    subs = n2.submodels(nam)
    rf = nd.receptive(nd.layer_of(subs[0][1]))
    ref = n2.WaveNet(subs[-1][1]).process(x)
    out = []

    def row(label, y, ch):
        e = n2.esr(y[rf:], ref[rf:])
        out.append({'label': label, 'channels': ch, 'esr': e,
                    'db': round(10.0 * _np.log10(max(e, 1e-12)), 1)})

    row('what Suite ships', n2.WaveNet(subs[0][1]).process(x),
        int(nd.layer_of(subs[0][1])['channels']))
    if student and os.path.isfile(student):
        st = n2.load(student)
        row(os.path.basename(student), n2.WaveNet(st).process(x),
            int(nd.layer_of(st)['channels']))
    return {'ok': True, 'di': os.path.basename(di), 'seconds': seconds,
            'rows': out}


def nam_start(path, channels, minutes, seconds, out=None):
    if NAM['running']:
        return {'ok': False, 'error': 'a run is already going'}
    with NAM_LOCK:
        NAM.update({'running': True, 'lines': [], 'stop': False,
                    'result': None, 'error': None, 'source': path})

    def work():
        try:
            _n2, nd = nam_tools()
            NAM['result'] = nd.run_train(
                path, channels, out, minutes=minutes, seconds=seconds,
                report=nam_say, should_stop=lambda: NAM['stop'])
        except BaseException as e:                            # noqa: BLE001
            NAM['error'] = str(e)
            nam_say('failed: %s' % e)
        finally:
            NAM['running'] = False

    threading.Thread(target=work, daemon=True).start()
    return {'ok': True}


# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype='application/json'):
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj), 'application/json')

    def _err(self, e):
        self._json({'error': str(e)}, 400)

    # ---- GET -----------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            if u.path in ('/', '/index.html'):
                p = os.path.join(HERE, 'index.html')
                return self._send(200, open(p, 'rb').read(), 'text/html; charset=utf-8')
            if u.path in ('/gp', '/gp/'):
                self.send_response(302)
                self.send_header('Location', '/')
                self.end_headers()
                return
            if u.path == '/api/state':
                if PROJECT.fw is None:
                    return self._json({'loaded': False})
                d = PROJECT.summary()
                d['loaded'] = True
                return self._json(d)
            if u.path == '/api/open':
                return self._json(PROJECT.load(q['path'][0]))
            if u.path == '/api/image':
                off = int(q['off'][0], 0)
                w = int(q['w'][0]); h = int(q['h'][0])
                src = PROJECT.body if q.get('src', ['cur'])[0] == 'cur' else PROJECT.orig
                im = decode_image(src, off, w, h)
                scale = int(q.get('scale', ['1'])[0])
                if scale > 1:
                    im = im.resize((w * scale, h * scale), Image.NEAREST)
                buf = io.BytesIO()
                im.save(buf, 'PNG')
                return self._send(200, buf.getvalue(), 'image/png')
            if u.path == '/api/strip':
                off = int(q['off'][0], 0)
                w = int(q['w'][0])
                rows = int(q['rows'][0])
                scale = int(q.get('scale', ['2'])[0])
                src = PROJECT.body
                avail = (len(src) - off) // (w * 3)
                rows = max(1, min(rows, avail))
                im = decode_image(src, off, w, rows)
                if scale > 1:
                    im = im.resize((w * scale, rows * scale), Image.NEAREST)
                buf = io.BytesIO()
                im.save(buf, 'PNG')
                return self._send(200, buf.getvalue(), 'image/png')
            if u.path == '/api/index':
                return self._json({'items': PROJECT.images,
                                   'runs': gfx_index.runs(
                                       [gfx_index.Blob(d['hdr'], d['w'], d['h'],
                                                       d['size'], d['addr'],
                                                       d['fmt'])
                                        for d in PROJECT.images])})
            if u.path == '/api/gif':
                i = int(q.get('i', ['0'])[0])
                if i >= len(PROJECT.gifs):
                    return self._send(404, b'', 'image/gif')
                g = PROJECT.gifs[i]
                blob = bytes(PROJECT.body[g['off']:g['off'] + g['len']])
                end = blob.rfind(b';') + 1
                return self._send(200, blob[:end] or blob, 'image/gif')
            if u.path == '/api/curated':
                items = PROJECT.curated()
                return self._json({'items': items, 'ok': bool(items)})
            if u.path == '/api/gallery':
                # The indexed images first - those come with their real width
                # and height - then whatever the region scan turns up in the
                # artwork the index does not describe.
                out = [dict(d) for d in PROJECT.curated()]
                for d in out:
                    d['region'] = -1
                covered = [(d['hdr'], d['off'] + d['size']) for d in out]
                for r in PROJECT.regions:
                    for ic in PROJECT.detect_icons(r['off'], r['end'],
                                                   r['width'], min_h=5):
                        if any(a <= ic['off'] < b for a, b in covered):
                            continue
                        ic['region'] = r['id']
                        ic['id'] = len(out)
                        blob = gfx_index.Blob(ic['off'] - gfx_index.HDR,
                                              ic['w'], ic['h'],
                                              ic['w'] * ic['h'] * 3, 0x80000000,
                                              gfx_index.FMT_RGB565A)
                        ic['grade'] = gfx_index.grade(PROJECT.body, blob)
                        ic['filled'] = ic['grade'] != 'junk'
                        out.append(ic)
                return self._json({'items': out, 'regions': len(PROJECT.regions),
                                   'indexed': len(PROJECT.images)})
            if u.path == '/api/icons':
                o = int(q['off'][0], 0); e = int(q['end'][0], 0)
                w = int(q['w'][0])
                mh = int(q.get('minh', ['6'])[0])
                return self._json({'icons': PROJECT.detect_icons(o, e, w, mh)})
            if u.path == '/api/stride':
                off = int(q['off'][0], 0)
                span = int(q.get('span', ['60000'])[0])
                span = min(span, len(PROJECT.body) - off - 1024)
                w = PROJECT.alpha_width(off, max(span, 24576))
                return self._json({'off': off, 'width': w})
            if u.path == '/api/sysfonts':
                _img, items = sysfonts()
                return self._json({'ok': True, 'items': items})
            if u.path == '/api/sysfont_sheet':
                import lv_font
                img, items = sysfonts()
                which = int(q.get('font', ['0'])[0])
                f = lv_font.Font(img, items[which]['dsc'])
                tiles = [f.render(i) for i in range(1, min(f.count, 96))]
                tiles = [t for t in tiles if t]
                if not tiles:
                    raise ValueError("that font rendered nothing")
                scale = int(q.get('scale', ['2'])[0])
                w = max(t.width for t in tiles) + 2
                h = max(t.height for t in tiles) + 2
                cols = 24
                rows = (len(tiles) + cols - 1) // cols
                sheet = Image.new('L', (cols * w, rows * h), 0)
                for n, t in enumerate(tiles):
                    sheet.paste(t, ((n % cols) * w + 1, (n // cols) * h + 1))
                if scale > 1:
                    sheet = sheet.resize((sheet.width * scale,
                                          sheet.height * scale), Image.NEAREST)
                buf = io.BytesIO()
                sheet.convert('RGB').save(buf, 'PNG')
                return self._send(200, buf.getvalue(), 'image/png')
            if u.path == '/api/labels':
                # Every indexed tile that has a word printed on it, with the
                # word's box and whatever caption has been typed for it before.
                caps = read_captions()
                out = []
                for d in PROJECT.curated():
                    if d.get('grade') not in (None, 'art'):
                        continue
                    box = PROJECT.word_box(d['off'], d['w'], d['h'])
                    if not box:
                        continue
                    out.append({'off': d['off'], 'w': d['w'], 'h': d['h'],
                                'box': box,
                                'text': caps.get('0x%X' % d['off'], '')})
                return self._json({'ok': True, 'items': out})
            if u.path == '/api/captions':
                return self._json({'ok': True, 'captions': read_captions()})
            if u.path == '/api/labelpreview':
                off = int(q['off'][0], 0)
                w, h = int(q['w'][0]), int(q['h'][0])
                text = q.get('text', [''])[0]
                scale = int(q.get('scale', ['2'])[0])
                if text:
                    im = PROJECT.retypeset(
                        off, w, h, text,
                        font_path=q.get('font', [None])[0] or None,
                        pad=int(q.get('pad', ['2'])[0]),
                        dy=int(q.get('dy', ['0'])[0]), preview=True)
                else:
                    im = decode_image(PROJECT.body, off, w, h).convert('RGBA')
                bg = Image.new('RGB', (w, h), (17, 19, 24))
                bg.paste(im, (0, 0), im)
                if scale > 1:
                    bg = bg.resize((w * scale, h * scale), Image.NEAREST)
                buf = io.BytesIO()
                bg.save(buf, 'PNG')
                return self._send(200, buf.getvalue(), 'image/png')
            if u.path == '/api/fonts':
                return self._json({'items': fonts_available(),
                                   'dir': FONT_DIR})
            if u.path == '/api/fontsample':
                # Deliberately independent of the loaded firmware and of any
                # chosen slot: picking a font has to show something at once,
                # or the tab looks dead - which is exactly how it looked.
                from PIL import ImageDraw
                text = q.get('text', ['GP-150'])[0] or ' '
                size = int(q.get('size', ['0'])[0]) or 34
                w, h = 460, int(size * 1.9) + 16
                im = Image.new('RGB', (w, h), (17, 19, 24))
                dr = ImageDraw.Draw(im)
                fp = q.get('font', [None])[0] or None
                try:
                    f = Project._font(fp, size, text, w, h)
                except Exception as e:                        # noqa: BLE001
                    dr.text((8, 8), 'this file did not open as a font: %s' % e,
                            fill=(220, 90, 90))
                    f = None
                if f is not None:
                    ol = int(q.get('outline', ['0'])[0])
                    dr.text((w // 2, h // 2), text, font=f, anchor='mm',
                            fill=_rgb(q.get('color', ['#ffffff'])[0]),
                            stroke_width=ol,
                            stroke_fill=_rgb(q.get('ocolor', ['#000000'])[0]))
                buf = io.BytesIO()
                im.save(buf, 'PNG')
                return self._send(200, buf.getvalue(), 'image/png')
            if u.path == '/api/textpreview':
                off = int(q['off'][0], 0)
                w = int(q['w'][0]); h = int(q['h'][0])
                im = PROJECT.draw_text(
                    off, w, h, q.get('text', [''])[0],
                    font_path=q.get('font', [None])[0] or None,
                    size=int(q.get('size', ['0'])[0]),
                    color=_rgb(q.get('color', ['#ffffff'])[0]),
                    align=q.get('align', ['center'])[0],
                    over=q.get('over', ['1'])[0] == '1',
                    outline=int(q.get('outline', ['0'])[0]),
                    outline_color=_rgb(q.get('ocolor', ['#000000'])[0]),
                    dy=int(q.get('dy', ['0'])[0]),
                    preview=True)
                scale = int(q.get('scale', ['1'])[0])
                if scale > 1:
                    im = im.resize((w * scale, h * scale), Image.NEAREST)
                buf = io.BytesIO()
                im.save(buf, 'PNG')
                return self._send(200, buf.getvalue(), 'image/png')
            if u.path == '/api/suitefont':
                # Suite's own typeface, read from its install. Nothing is copied
                # anywhere: it is served straight from Program Files so Studio
                # looks like the application it sits beside.
                f = os.path.join(gp150.SUITE, 'data', 'flutter_assets',
                                 'assets', 'font', 'Source-regular.OTF')
                if not os.path.isfile(f):
                    return self._send(404, b'', 'font/otf')
                return self._send(200, open(f, 'rb').read(), 'font/otf')
            if u.path == '/api/device':
                try:
                    ins = gp150._names(gp150.scan('scanInDevice'))
                    outs = gp150._names(gp150.scan('scanOutDevice'))
                    return self._json({'ok': True, 'in': ins, 'out': outs})
                except Exception as e:            # noqa: BLE001
                    return self._json({'ok': False, 'error': str(e),
                                       'in': [], 'out': []})
            if u.path == '/api/validate':
                path = q.get('path', [''])[0]
                if not path or not os.path.isfile(path):
                    return self._json({'ok': False, 'error': 'no such file'})
                blob = open(path, 'rb').read()
                stored, calc = gp150.whole_file_crc(blob)
                out = {'ok': True, 'stored': stored, 'calc': calc,
                       'sealed': stored == calc, 'size': len(blob)}
                try:
                    rc, ver = gp150.vendor_check(path)
                    out['rc'] = rc
                    out['version'] = ver
                except Exception as e:            # noqa: BLE001
                    out['rc'] = None
                    out['vendor_error'] = str(e)
                return self._json(out)
            if u.path == '/api/log':
                # The vendor library truncates this on startup and floods it
                # with scanInDevice polling, so tail from a caller-held offset
                # and drop the noise unless asked for it.
                pos = int(q.get('pos', ['-1'])[0])
                keep_all = q.get('all', ['0'])[0] == '1'
                fn = gp150.LOGFILE
                if not os.path.isfile(fn):
                    return self._json({'ok': False, 'error': 'no log yet',
                                       'pos': 0, 'lines': []})
                size = os.path.getsize(fn)
                if pos < 0 or pos > size:
                    pos = max(0, size - 65536)
                with open(fn, 'r', encoding='latin1') as fh:
                    fh.seek(pos)
                    text = fh.read()
                    npos = fh.tell()
                blocks = [b for b in gp150._blocks(text)
                          if gp150._interesting(b, keep_all)]
                return self._json({'ok': True, 'pos': npos, 'size': size,
                                   'lines': blocks[-200:]})
            if u.path == '/api/strings':
                needle = q.get('q', [''])[0].lower()
                items = PROJECT.strings
                if needle:
                    items = [s for s in items if needle in s['text'].lower()]
                return self._json({'total': len(items), 'items': items[:1200]})
            if u.path == '/api/assets':
                root = assets_root()
                if not root:
                    return self._json({'root': None, 'dirs': [], 'files': []})
                sub = q.get('dir', [''])[0].replace('..', '')
                d = os.path.join(root, sub) if sub else root
                if not os.path.isdir(d):
                    d = root
                    sub = ''
                names = sorted(os.listdir(d))
                dirs = [x for x in names if os.path.isdir(os.path.join(d, x))]
                files = [x for x in names if x.lower().endswith('.png')]
                return self._json({'root': root, 'rel': sub, 'dirs': dirs,
                                   'files': files,
                                   'parent': os.path.dirname(sub) if sub else None})
            if u.path == '/api/asset':
                root = assets_root()
                rel = q['path'][0].replace('..', '')
                full = os.path.join(root, rel)
                if not os.path.isfile(full):
                    return self._send(404, 'no asset', 'text/plain')
                im = Image.open(full).convert('RGBA')
                mx = int(q.get('max', ['0'])[0])
                if mx and max(im.size) > mx:
                    im.thumbnail((mx, mx), Image.LANCZOS)
                buf = io.BytesIO()
                im.save(buf, 'PNG')
                return self._send(200, buf.getvalue(), 'image/png')
            if u.path == '/api/nam':
                return self._json(nam_survey(q['path'][0]))
            if u.path == '/api/nam_esr':
                return self._json(nam_esr(q['path'][0],
                                          q.get('student', [None])[0],
                                          float(q.get('seconds', ['10'])[0])))
            if u.path == '/api/nam_log':
                pos = int(q.get('pos', ['0'])[0])
                with NAM_LOCK:
                    lines = NAM['lines'][pos:]
                    n = len(NAM['lines'])
                return self._json({'ok': True, 'pos': n, 'lines': lines,
                                   'running': NAM['running'],
                                   'result': NAM['result'],
                                   'error': NAM['error']})
            if u.path == '/api/browse':
                d = q.get('dir', [os.path.expanduser('~')])[0]
                ext = q.get('ext', ['.bin'])[0].lower()
                try:
                    entries = sorted(os.listdir(d))
                except OSError as e:
                    return self._err(e)
                dirs = [x for x in entries if os.path.isdir(os.path.join(d, x))]
                bins = [x for x in entries if x.lower().endswith(ext)]
                return self._json({'dir': os.path.abspath(d),
                                   'parent': os.path.dirname(os.path.abspath(d)),
                                   'dirs': dirs[:400], 'files': bins[:400]})
            return self._send(404, 'not found', 'text/plain')
        except Exception as e:                    # noqa: BLE001
            return self._err(e)

    @staticmethod
    def _image_from(data):
        """Accept either an uploaded PNG or a path into the Suite asset tree."""
        if data.get('asset'):
            root = assets_root()
            full = os.path.join(root, data['asset'].replace('..', ''))
            return Image.open(full)
        raw = base64.b64decode(data['png'].split(',')[-1])
        return Image.open(io.BytesIO(raw))

    # ---- POST ----------------------------------------------------------
    def do_POST(self):
        u = urlparse(self.path)
        n = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(n) if n else b'{}'
        try:
            data = json.loads(raw.decode('utf-8'))
        except Exception:
            data = {}
        try:
            if u.path == '/api/replace':
                im = self._image_from(data)
                PROJECT.put_image(int(data['off']), int(data['w']), int(data['h']),
                                  im, bool(data.get('preserve_alpha', True)))
                return self._json({'ok': True, 'edits': PROJECT.edits})
            if u.path == '/api/text':
                PROJECT.draw_text(
                    int(data['off']), int(data['w']), int(data['h']),
                    data.get('text', ''),
                    font_path=data.get('font') or None,
                    size=int(data.get('size', 0)),
                    color=_rgb(data.get('color', '#ffffff')),
                    align=data.get('align', 'center'),
                    over=bool(data.get('over', True)),
                    keep_alpha=bool(data.get('keep_alpha', False)),
                    outline=int(data.get('outline', 0)),
                    outline_color=_rgb(data.get('ocolor', '#000000')),
                    dy=int(data.get('dy', 0)))
                return self._json({'ok': True, 'edits': PROJECT.edits})
            if u.path == '/api/sysfont_replace':
                import lv_font
                img, items = sysfonts()
                which = int(data.get('font', 0))
                ttf = data.get('ttf') or ''
                if not os.path.isfile(ttf):
                    return self._json({'ok': False, 'error': 'no such font file'})
                f = lv_font.Font(img, items[which]['dsc'])
                b0, blob = f.span()
                before = len(PROJECT.images)
                # the blob sits inside section b, so the same guard that keeps
                # a texture off an image descriptor applies here too
                PROJECT._check_span(img.off(b0, blob), blob,
                                    'replacing that font')
                lv_font.write_face(img, f, ttf, size=data.get('size') or None)
                PROJECT.edits += 1
                after = len(gfx_index.scan(PROJECT.body))
                return self._json({'ok': True, 'edits': PROJECT.edits,
                                   'descriptors_before': before,
                                   'descriptors_after': after})
            if u.path == '/api/retypeset':
                # The whole point of the Font tab: change the face of every
                # word already printed into the artwork, keeping each tile's
                # own colours and the room the old word took.
                font = data.get('font') or None
                pad = int(data.get('pad', 2))
                dy = int(data.get('dy', 0))
                done, failed = 0, []
                caps = read_captions()
                for s0 in data.get('slots', []):
                    txt = (s0.get('text') or '').strip()
                    if not txt:
                        continue
                    caps['0x%X' % int(s0['off'])] = txt
                    try:
                        PROJECT.retypeset(int(s0['off']), int(s0['w']),
                                          int(s0['h']), txt,
                                          box=s0.get('box'), font_path=font,
                                          pad=pad, dy=dy)
                        done += 1
                    except Exception as e:                    # noqa: BLE001
                        failed.append({'off': int(s0['off']), 'why': str(e)})
                write_captions(caps)
                return self._json({'ok': True, 'written': done, 'failed': failed,
                                   'edits': PROJECT.edits})
            if u.path == '/api/captions':
                write_captions(data.get('captions', {}))
                return self._json({'ok': True})
            if u.path == '/api/text_batch':
                # One font, many slots. Each slot keeps its own words, because
                # a caption that fits an 80x24 button does not fit a 320x240
                # splash - so this is a list, not one string sprayed everywhere
                # unless the page chose to fill it that way.
                shared = dict(
                    font_path=data.get('font') or None,
                    size=int(data.get('size', 0)),
                    color=_rgb(data.get('color', '#ffffff')),
                    align=data.get('align', 'center'),
                    over=bool(data.get('over', True)),
                    keep_alpha=bool(data.get('keep_alpha', False)),
                    outline=int(data.get('outline', 0)),
                    outline_color=_rgb(data.get('ocolor', '#000000')),
                    dy=int(data.get('dy', 0)))
                done, failed = 0, []
                for s in data.get('slots', []):
                    txt = (s.get('text') or '').strip()
                    if not txt:
                        continue
                    try:
                        PROJECT.draw_text(int(s['off']), int(s['w']), int(s['h']),
                                          txt, **shared)
                        done += 1
                    except Exception as e:                    # noqa: BLE001
                        failed.append({'off': int(s['off']), 'why': str(e)})
                return self._json({'ok': True, 'written': done,
                                   'failed': failed, 'edits': PROJECT.edits})
            if u.path == '/api/font_upload':
                name = os.path.basename(data['name']).replace('..', '')
                if not name.lower().endswith(('.ttf', '.otf')):
                    raise ValueError("a font has to be .ttf or .otf")
                if not os.path.isdir(FONT_DIR):
                    os.makedirs(FONT_DIR)
                raw = base64.b64decode(data['data'].split(',')[-1])
                path = os.path.join(FONT_DIR, name)
                open(path, 'wb').write(raw)
                # opening it is the check that it is really a font
                from PIL import ImageFont
                ImageFont.truetype(path, 16)
                return self._json({'ok': True, 'path': path, 'name': name,
                                   'fonts': fonts_available()})
            if u.path == '/api/recolor':
                scope = data.get('regions')
                res = PROJECT.recolour(
                    scope=set(scope) if scope else None,
                    ids=data.get('ids'),
                    hue=float(data.get('hue', 0)),
                    sat=float(data.get('sat', 1)),
                    light=float(data.get('light', 1)),
                    tint=data.get('tint') or None,
                    strength=float(data.get('strength', 1)),
                    keep_alpha=bool(data.get('keep_alpha', True)))
                res['ok'] = True
                res['edits'] = PROJECT.edits
                return self._json(res)
            if u.path == '/api/replace_gif':
                raw = base64.b64decode(data['gif'].split(',')[-1])
                r = PROJECT.put_gif(int(data.get('i', 0)), raw)
                r['ok'] = True
                r['edits'] = PROJECT.edits
                return self._json(r)
            if u.path == '/api/replace_many':
                im = self._image_from(data)
                off = int(data['off']); w = int(data['w']); h = int(data['h'])
                count = int(data['count'])
                for k in range(count):
                    PROJECT.put_image(off + k * w * h * 3, w, h, im,
                                      bool(data.get('preserve_alpha', True)))
                return self._json({'ok': True, 'edits': PROJECT.edits})
            if u.path == '/api/string':
                PROJECT.put_string(int(data['off']), data['text'])
                return self._json({'ok': True, 'edits': PROJECT.edits})
            if u.path == '/api/string_replace':
                return self._json(PROJECT.replace_in_strings(
                    data.get('find', ''), data.get('repl', ''),
                    bool(data.get("case")),
                    set(data['offs']) if data.get('offs') else None))
            if u.path == '/api/texture':
                raw = base64.b64decode(data['image'].split(',')[-1])
                im = Image.open(io.BytesIO(raw))
                scope = data.get('regions')
                res = PROJECT.apply_texture(
                    im,
                    scope=set(scope) if scope else None,
                    ids=data.get('ids'),
                    mode=data.get('mode', 'replace'),
                    keep_alpha=bool(data.get('keep_alpha', True)),
                    fit=data.get('fit', 'stretch'),
                    opacity=max(0.0, min(1.0, float(data.get('opacity', 1.0)))))
                res['edits'] = PROJECT.edits
                res['ok'] = True
                return self._json(res)
            if u.path == '/api/deploy':
                """Build, stamp, let the vendor library check it, then flash."""
                out = data.get('out')
                if not out:
                    return self._json({'ok': False, 'error': 'no output path'})
                steps = []
                info = PROJECT.build(out)
                steps.append('built %s (%d bytes, %d edits)'
                             % (out, info['size'], info['edits']))
                blob = open(out, 'rb').read()
                stored, calc = gp150.whole_file_crc(blob)
                steps.append('whole-file CRC 0x%04X %s'
                             % (stored, 'OK' if stored == calc else 'STALE'))
                if stored != calc:
                    return self._json({'ok': False, 'steps': steps,
                                       'error': 'the build did not stamp its CRC'})
                rc, ver = gp150.vendor_check(out)
                steps.append('vendor checkCrc %d, version %s' % (rc, ver))
                if rc != 0:
                    return self._json({'ok': False, 'steps': steps,
                                       'error': 'the vendor library rejects it'})
                ins = gp150._names(gp150.scan('scanInDevice'))
                outs = gp150._names(gp150.scan('scanOutDevice'))
                steps.append('MIDI in %s, out %s' % (ins or '(none)', outs or '(none)'))
                if not ins or not outs:
                    return self._json({'ok': False, 'steps': steps,
                                       'built': out,
                                       'error': 'built and verified, but no device '
                                                'is connected - nothing was written'})
                if not data.get('confirm'):
                    return self._json({'ok': False, 'steps': steps,
                                       'error': 'not confirmed'})
                d = gp150.dll()
                conn = d.connectDevice
                conn.restype = ctypes.c_void_p
                conn.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p,
                                 ctypes.c_void_p]
                h = conn(0, 0, out.encode('mbcs'), None)
                steps.append('connectDevice -> %s' % ('0x%X' % h if h else 'NULL'))
                if not h:
                    return self._json({'ok': False, 'steps': steps,
                                       'error': 'connectDevice failed'})
                upd = d.deviceStartUpdate
                upd.restype, upd.argtypes = ctypes.c_int, [ctypes.c_void_p]
                r = upd(h)
                steps.append('deviceStartUpdate -> %d' % r)
                return self._json({'ok': r == 0, 'steps': steps, 'result': r})
            if u.path == '/api/flash':
                path = data.get('path', '')
                if not os.path.isfile(path):
                    return self._json({'ok': False, 'error': 'no such file'})
                blob = open(path, 'rb').read()
                stored, calc = gp150.whole_file_crc(blob)
                if stored != calc:
                    return self._json({'ok': False, 'error':
                                       'whole-file CRC is stale - seal it first'})
                rc, _ = gp150.vendor_check(path)
                if rc != 0:
                    return self._json({'ok': False, 'error':
                                       'the vendor library rejects this file '
                                       '(checkCrc %d)' % rc})
                ins = gp150._names(gp150.scan('scanInDevice'))
                outs = gp150._names(gp150.scan('scanOutDevice'))
                if not ins or not outs:
                    return self._json({'ok': False, 'error':
                                       'no device reported - plug the GP-150 in '
                                       'and close Valeton Suite'})
                if not data.get('confirm'):
                    return self._json({'ok': False, 'error': 'not confirmed'})
                d = gp150.dll()
                conn = d.connectDevice
                conn.restype = ctypes.c_void_p
                conn.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p,
                                 ctypes.c_void_p]
                h = conn(int(data.get('inport', 0)), int(data.get('outport', 0)),
                         path.encode('mbcs'), None)
                if not h:
                    return self._json({'ok': False, 'error': 'connectDevice failed'})
                upd = d.deviceStartUpdate
                upd.restype, upd.argtypes = ctypes.c_int, [ctypes.c_void_p]
                r = upd(h)
                return self._json({'ok': r == 0, 'result': r,
                                   'handle': '0x%X' % h})
            if u.path == '/api/nam_train':
                p = data.get('path', '')
                if not os.path.isfile(p):
                    return self._json({'ok': False, 'error': 'no such capture'})
                return self._json(nam_start(
                    p, int(data.get('channels', 4)),
                    float(data.get('minutes', 10)),
                    float(data.get('seconds', 20)),
                    data.get('out') or None))
            if u.path == '/api/nam_stop':
                NAM['stop'] = True
                return self._json({'ok': True})
            if u.path == '/api/nam_convert':
                n2, _nd = nam_tools()
                p = data.get('path', '')
                if not os.path.isfile(p):
                    return self._json({'ok': False, 'error': 'no such file'})
                out = data.get('out') or (os.path.splitext(p)[0] + '.namb')
                n2.convert(p, out, float(data.get('slim', 0.0)))
                h = n2.namb_header(out)
                return self._json({'ok': True, 'out': out,
                                   'size': os.path.getsize(out), 'header': h})
            if u.path == '/api/revert':
                PROJECT.revert()
                return self._json({'ok': True, 'edits': 0})
            if u.path == '/api/build':
                return self._json(PROJECT.build(data['out']))
            return self._send(404, 'not found', 'text/plain')
        except Exception as e:                    # noqa: BLE001
            return self._err(e)


def main():
    if len(sys.argv) > 1:
        try:
            PROJECT.load(sys.argv[1])
            print("loaded %s" % sys.argv[1])
        except Exception as e:                    # noqa: BLE001
            print("could not load %s: %s" % (sys.argv[1], e))
    srv = ThreadingHTTPServer(('127.0.0.1', PORT), Handler)
    url = 'http://127.0.0.1:%d' % PORT
    print("GP-150 Studio on %s   (Ctrl+C to stop)" % url)
    threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == '__main__':
    main()
