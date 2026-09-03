#!/usr/bin/env python3
"""
GP-150 Studio - a local browser UI for building custom Valeton HTFW firmware.

    python server.py [firmware.bin]

Then open http://127.0.0.1:8765 . Everything runs locally; nothing is uploaded.

Depends only on Pillow plus the sibling tools (htfw_tool, lzo1x, lzodll).
Repacking an LZO-packed image (V1.1.1 and later) needs Valeton Suite installed,
because it borrows that install's minilzo_plugin.dll to compress.
"""

import base64
import io
import json
import os
import re
import struct
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'tools'))
sys.path.insert(0, HERE)

from PIL import Image                      # noqa: E402
import htfw_tool                            # noqa: E402

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
# pixel format: 3 bytes per pixel, little-endian RGB565 then one byte that
# behaves as alpha (0 = transparent). Rows top to bottom, no padding.
# --------------------------------------------------------------------------

def decode_image(buf, off, w, h):
    im = Image.new('RGBA', (w, h))
    px = im.load()
    for y in range(h):
        base = off + y * w * 3
        if base + w * 3 > len(buf):
            break
        for x in range(w):
            o = base + x * 3
            c = buf[o] | (buf[o + 1] << 8)
            px[x, y] = (((c >> 11) & 0x1F) * 255 // 31,
                        ((c >> 5) & 0x3F) * 255 // 63,
                        (c & 0x1F) * 255 // 31,
                        buf[o + 2])
    return im


def encode_image(im, w, h, original=None, preserve_alpha=True):
    """Return w*h*3 bytes. With preserve_alpha the third byte of every pixel is
    copied from `original`, so icon shapes and anything encoded there survive."""
    im = im.convert('RGBA')
    if im.size != (w, h):
        im = im.resize((w, h), Image.LANCZOS)
    px = im.load()
    out = bytearray(w * h * 3)
    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            c = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
            i = (y * w + x) * 3
            out[i] = c & 0xFF
            out[i + 1] = c >> 8
            if preserve_alpha and original is not None and i + 2 < len(original):
                out[i + 2] = original[i + 2]
            else:
                out[i + 2] = a
    return bytes(out)


# --------------------------------------------------------------------------

class Project(object):
    def __init__(self):
        self.path = None
        self.fw = None
        self.body = None          # mutable copy of the unpacked payload
        self.orig = None          # pristine copy, for preserve-alpha and revert
        self.regions = []
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
            hit = None
            for ph in (0, 1, 2):
                n = k = 0
                for o in range(a + ph + 2, a + BLK, 3):
                    v = body[o]
                    n += 1
                    if v == 0 or v == 255:
                        k += 1
                if n and k / n > 0.80:
                    hit = ph
                    break
            if hit is not None:
                if cur and a - cur[1] <= BLK * 2 and hit == cur[2]:
                    cur[1] = a + BLK
                else:
                    if cur:
                        runs.append(cur)
                    cur = [a, a + BLK, hit]
        if cur:
            runs.append(cur)
        runs = [r for r in runs if r[1] - r[0] >= 24576]

        out = []
        for i, (a, bb, _ph) in enumerate(runs):
            w = self.best_stride(a, min(90000, bb - a)) // 3
            rows = (bb - a) // (w * 3) if w else 0
            out.append({'id': i, 'off': a, 'end': bb, 'bytes': bb - a,
                        'width': w, 'rows': rows,
                        'name': 'region %d @0x%06X' % (i, a)})
        self.regions = out

    def best_stride(self, off, n, lo=24, hi=1000):
        body = self.body
        best = None
        for s in range(lo, hi, 3):
            m = min(n - s, 50000)
            tot = 0
            c = 0
            for i in range(0, m, 5):
                tot += abs(body[off + i] - body[off + i + s])
                c += 1
            v = tot / max(c, 1)
            if best is None or v < best[0]:
                best = (v, s)
        return best[1]

    # ---- strings -------------------------------------------------------
    @staticmethod
    def _trim_head(t):
        """Number tails glue onto the front of strings. A float like 1000.0 is
        `00 00 7A 44`, whose last two bytes print as 'zD', so the scanner reads
        'zD%.0fHz' where the real entry is '%.0fHz'. Drop a short wordless prefix
        when a clear token start follows it."""
        for cut in (1, 2, 3, 4):
            if cut >= len(t):
                break
            head, rest = t[:cut], t[cut:]
            if ' ' in head or not rest:
                break
            starts_token = (rest[0] == '%'
                            or (rest[0].isupper() and len(rest) > 1 and rest[1].islower()))
            if starts_token and not head.isalpha() or (starts_token and len(head) <= 2):
                return cut
        return 0

    @staticmethod
    def _texty(t):
        """Reject printable runs that are really binary. Firmware is full of byte
        sequences that happen to be ASCII; UI text has a word-like shape."""
        t = t.strip()
        if len(t) < 4:
            return False
        if len(set(t)) < 3:
            return False
        # judge the word-likeness of the letters only: digits, dots and printf
        # specifiers are legitimate parts of a label like "%.0fHz" or "30 min"
        letters = sum(c.isalpha() for c in t)
        core = sum(1 for c in t if not (c.isdigit() or c in '.%'))
        if letters / max(core, 1) < 0.6:
            return False
        allowed = " .,:;/()-+%'\"!?&#*[]{}<>=_@|"
        if any(not (c.isalnum() or c in allowed) for c in t):
            return False
        # punctuation in a very short token is a hallmark of stray code bytes
        punct = sum(1 for c in t if not (c.isalnum() or c == ' '))
        if punct and len(t) < 6:
            return False
        if not any(c in 'aeiouAEIOUy0123456789' for c in t):
            return False
        return True

    def scan_strings(self):
        """NUL-terminated printable runs in section b, with the space available
        before the next string starts (that bounds a safe in-place edit).

        Two filters keep binary noise out: each run must look like text, and it
        must sit in a neighbourhood where other strings live - real UI text is
        stored in dense tables, stray matches in code are isolated."""
        body = self.body
        secs = {s.tag: s for s in self.fw.sections}
        b = secs.get('b')
        if b is None:
            self.strings = []
            return
        lo, hi = b.off, b.off + b.len
        found = []
        i = lo
        while i < hi:
            c = body[i]
            if 32 <= c < 127:
                j = i
                while j < hi and 32 <= body[j] < 127:
                    j += 1
                # a real table entry is NUL-terminated *and* NUL-preceded; without
                # the leading test, printable code bytes glue onto the front and
                # you get "zD%.0fHz" instead of "%.0fHz"
                if (j < hi and body[j] == 0 and (j - i) >= 3
                        and (i == lo or body[i - 1] == 0)):
                    found.append([i, j - i])
                i = j + 1
            else:
                i += 1
        # quality filter, with a leading-junk trim first
        keep = []
        for off, ln in found:
            t = bytes(body[off:off + ln]).decode('latin1')
            d = self._trim_head(t)
            if d:
                off += d
                ln -= d
                t = t[d:]
            if self._texty(t):
                keep.append((off, ln, t))
        # neighbourhood filter. Real UI text sits in tables of *varied* strings;
        # binary noise shows up as one token repeated at a regular stride, so the
        # test is how many DISTINCT texts share the neighbourhood.
        import bisect
        offs = [k[0] for k in keep]
        dense = []
        for off, ln, t in keep:
            lo_i = bisect.bisect_left(offs, off - 1500)
            hi_i = bisect.bisect_right(offs, off + 1500)
            distinct = len({keep[i][2] for i in range(lo_i, hi_i)})
            if len(t) >= 8 and distinct >= 2:
                dense.append((off, ln, t))
            elif distinct >= 6:
                dense.append((off, ln, t))
        out = []
        for k, (off, ln, t) in enumerate(dense):
            nxt = dense[k + 1][0] if k + 1 < len(dense) else off + ln + 1
            room = max(ln, min(nxt - off - 1, ln + 64))
            out.append({'id': k, 'off': off, 'len': ln, 'room': room, 'text': t})
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
        data = bytes(hdr) + tail
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
            if u.path == '/api/stride':
                off = int(q['off'][0], 0)
                span = int(q.get('span', ['60000'])[0])
                span = min(span, len(PROJECT.body) - off - 1024)
                w = PROJECT.best_stride(off, max(span, 8192)) // 3
                return self._json({'off': off, 'width': w})
            if u.path == '/api/strings':
                needle = q.get('q', [''])[0].lower()
                items = PROJECT.strings
                if needle:
                    items = [s for s in items if needle in s['text'].lower()]
                return self._json({'total': len(items), 'items': items[:400]})
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
