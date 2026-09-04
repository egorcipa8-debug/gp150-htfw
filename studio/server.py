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
                    b0 += ph + 1
                    b0 = self._align(b0, b1, w)
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
        al = bytes(self.body[off:off + win_px * 3:3])
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
        vis = a[:, 0] > 32
        if int(vis.sum()) < 24:
            return None
        v = (a[vis, 1].astype(_np.uint16) | (a[vis, 2].astype(_np.uint16) << 8))
        r = ((v >> 11) & 0x1F) * 255 // 31
        g = ((v >> 5) & 0x3F) * 255 // 63
        b = (v & 0x1F) * 255 // 31
        rgb = _np.stack([r, g, b]).astype(_np.float64)
        return float((rgb.max(0) - rgb.min(0)).mean())

    def best_phase(self, off, npx, margin=0.6):
        """Which byte offset starts a whole pixel here. Only moves off zero when
        the winner is clearly cleaner - photographic artwork is colourful at
        every phase and must not be nudged around on a tie."""
        vals = []
        for d in (0, 1, 2):
            v = self.fringe(off + d, npx)
            vals.append(1e9 if v is None else v)
        b = min(range(3), key=lambda i: vals[i])
        others = min(vals[i] for i in range(3) if i != b)
        if b != 0 and vals[b] < others * margin:
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
        al = x[0::3].astype(_np.float64)
        col = (x[1::3].astype(_np.uint16)
               | (x[2::3].astype(_np.uint16) << 8)).astype(_np.float64)
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
        original = self.orig[off:off + n]
        self.body[off:off + n] = encode_image(im, w, h, original, preserve_alpha)
        self.edits += 1

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
            d['filled'] = gfx_index.looks_like_picture(self.orig, b)
            d['name'] = '%dx%d @0x%06X' % (b.w, b.h, b.off)
            out.append(d)
        self.images = out

    def curated(self):
        """The indexed images - the ones that decode as artwork first."""
        good = [d for d in self.images if d['filled']]
        rest = [d for d in self.images if not d['filled']]
        return good + rest

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
    def apply_texture(self, im, scope=None, mode='replace', keep_alpha=True,
                      fit='tile'):
        """Lay one image over the colour of every pixel in every graphics region.

        This is deliberately not the tile replacer. That one walks a region in
        fixed w*h steps, so it only ever reaches things that happen to sit on
        that grid; regions hold images of several sizes packed with no
        separator, and everything off the grid is left behind. Here the unit is
        the pixel, so an overlay reaches every asset in the image whatever shape
        it is.

        Alpha is left alone by default, which is what keeps the artwork's
        silhouettes: only the colour underneath them changes.
        """
        im = im.convert('RGB')
        tw, th = im.size
        if tw < 1 or th < 1:
            raise ValueError("empty texture")
        regions = self.regions if scope is None else [
            r for r in self.regions if r['id'] in scope]
        if not regions:
            raise ValueError("no regions selected")
        tex = im.load()
        touched = 0
        for r in regions:
            off, end, w = r['off'], r['end'], r['width']
            npx = (end - off) // 3
            if fit == 'stretch':
                rows = max(1, npx // w)
            for i in range(npx):
                x, y = i % w, i // w
                if fit == 'stretch':
                    sx = x * tw // w
                    sy = y * th // max(rows, 1)
                else:
                    sx, sy = x % tw, y % th
                cr, cg, cb = tex[min(sx, tw - 1), min(sy, th - 1)]
                o = off + i * 3
                if mode == 'multiply':
                    c = self.body[o] | (self.body[o + 1] << 8)
                    orr = ((c >> 11) & 0x1F) * 255 // 31
                    og = ((c >> 5) & 0x3F) * 255 // 63
                    ob = (c & 0x1F) * 255 // 31
                    cr, cg, cb = cr * orr // 255, cg * og // 255, cb * ob // 255
                v = ((cr >> 3) << 11) | ((cg >> 2) << 5) | (cb >> 3)
                self.body[o] = v & 0xFF
                self.body[o + 1] = v >> 8
                if not keep_alpha:
                    self.body[o + 2] = 255
            touched += npx
            self.edits += 1
        return {'regions': len(regions), 'pixels': touched}

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
                        ic['filled'] = True
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
            if u.path == '/api/browse':
                d = q.get('dir', [os.path.expanduser('~')])[0]
                try:
                    entries = sorted(os.listdir(d))
                except OSError as e:
                    return self._err(e)
                dirs = [x for x in entries if os.path.isdir(os.path.join(d, x))]
                bins = [x for x in entries if x.lower().endswith('.bin')]
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
                    mode=data.get('mode', 'replace'),
                    keep_alpha=bool(data.get('keep_alpha', True)),
                    fit=data.get('fit', 'tile'))
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
