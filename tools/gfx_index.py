#!/usr/bin/env python3
"""gfx_index.py - the firmware's own image index.

Every stored image is preceded by a 12-byte descriptor, so the geometry does not
have to be guessed at all:

    struct {
        u32 desc;   /* [7:0]   format tag, 0x05 = RGB565 + alpha, 3 bytes/pixel
                       [19:8]  width  * 4
                       [31:20] height * 2                                   */
        u32 size;   /* width * height * 3, always                           */
        u32 addr;   /* where this descriptor sits in SDRAM                   */
    } __attribute__((packed));                 /* pixels follow immediately */

Found by measuring the drift of a sheet of pedal icons: reading them at the
recovered width of 80 left every image rolled four pixels further right than the
one above, so the true stride was 4 pixels *more* than 80x102 - twelve bytes of
something between images. Those twelve bytes turned out to carry the width and
the height.

The predicate is self-checking: `size` has to equal `width * height * 3` with the
width and the height taken from two other fields of a different word, which is
around thirty bits of agreement, so a false positive in an 8 MB payload is not a
practical concern. On GP-150 V1.1.1 it finds 132 images.

Descriptors are the allocator's, not a resource table's: `addr` is an SDRAM
address, consecutive blocks are chained (`hdr + 12 + size` is the next `hdr`),
and the file-to-SDRAM delta is constant along a run - this area of section `b` is
a heap image copied to SDRAM verbatim. Blocks that were allocated but never
filled are in it too, which is why a handful of entries decode as noise;
`looks_like_picture()` marks them rather than hiding them.

Pixel format, settled against a descriptor's own geometry (see FINDINGS §17):

    [0:2] uint16 RGB565, little endian
    [2]   uint8  alpha

Rows top to bottom, no padding. Earlier notes here had the alpha byte first;
that reads the same bytes one position over and tints everything olive.
"""

import struct
import sys

try:
    import numpy as _np
except ImportError:                              # pragma: no cover - optional
    _np = None

FMT_RGB565A = 0x05
HDR = 12


class Blob(object):
    __slots__ = ('hdr', 'off', 'w', 'h', 'size', 'addr', 'fmt')

    def __init__(self, hdr, w, h, size, addr, fmt):
        self.hdr = hdr                            # descriptor offset
        self.off = hdr + HDR                      # first pixel
        self.w = w
        self.h = h
        self.size = size
        self.addr = addr                          # SDRAM address of the descriptor
        self.fmt = fmt

    @property
    def end(self):
        return self.off + self.size

    def as_dict(self):
        return {'hdr': self.hdr, 'off': self.off, 'w': self.w, 'h': self.h,
                'size': self.size, 'addr': self.addr, 'fmt': self.fmt}

    def __repr__(self):
        return ('<Blob 0x%06X %dx%d %d bytes addr=%08X>'
                % (self.off, self.w, self.h, self.size, self.addr))


def _valid(desc, size, addr, limit):
    if desc & 0xFF != FMT_RGB565A:
        return None
    wf = (desc >> 8) & 0xFFF
    hf = (desc >> 20) & 0xFFF
    if wf & 3 or hf & 1:
        return None
    w, h = wf >> 2, hf >> 1
    if w < 4 or h < 4 or w > 1024 or h > 1024:
        return None
    if size != w * h * 3 or size > limit:
        return None
    if not (0x80000000 <= addr < 0x82000000):
        return None
    return w, h


def scan(payload):
    """Every image the firmware describes, in file order."""
    buf = bytes(payload)
    n = len(buf)
    out = []
    if _np is not None:
        b = _np.frombuffer(buf, dtype=_np.uint8).astype(_np.uint32)
        if n < 16:
            return out
        u32 = b[0:n - 3] | (b[1:n - 2] << 8) | (b[2:n - 1] << 16) | (b[3:n] << 24)
        m = len(u32) - 8
        desc, size, addr = u32[0:m], u32[4:4 + m], u32[8:8 + m]
        wf = (desc >> 8) & 0xFFF
        hf = (desc >> 20) & 0xFFF
        w, h = wf >> 2, hf >> 1
        ok = ((desc & 0xFF) == FMT_RGB565A) & ((wf & 3) == 0) & ((hf & 1) == 0)
        ok &= (w >= 4) & (h >= 4) & (size == w * h * 3)
        ok &= (addr >= 0x80000000) & (addr < 0x82000000)
        for p in _np.nonzero(ok)[0]:
            p = int(p)
            if p + HDR + int(size[p]) <= n:
                out.append(Blob(p, int(w[p]), int(h[p]), int(size[p]),
                                int(addr[p]), FMT_RGB565A))
        return out
    p = buf.find(b'\x05')
    while p >= 0:
        if p + HDR <= n:
            desc, size, addr = struct.unpack_from('<III', buf, p)
            wh = _valid(desc, size, addr, n - p - HDR)
            if wh:
                out.append(Blob(p, wh[0], wh[1], size, addr, FMT_RGB565A))
        p = buf.find(b'\x05', p + 1)
    return out


def runs(blobs):
    """Group the index by file-to-SDRAM delta: one run is one contiguous heap
    area, and inside it `addr - hdr` is constant."""
    out = []
    for b in sorted(blobs, key=lambda x: x.hdr):
        d = (b.addr - b.hdr) & 0xFFFFFFFF
        if out and out[-1]['delta'] == d and b.hdr <= out[-1]['end'] + 4096:
            out[-1]['count'] += 1
            out[-1]['end'] = b.end
        else:
            out.append({'delta': d, 'start': b.hdr, 'end': b.end, 'count': 1})
    return out


# --- pixels ---------------------------------------------------------------

def decode(buf, off, w, h):
    """Return a PIL image. RGB565 little endian, then the alpha byte."""
    from PIL import Image
    n = w * h * 3
    if off < 0 or off + n > len(buf):
        raise ValueError("image runs past the end of the payload")
    if _np is not None:
        a = _np.frombuffer(bytes(buf[off:off + n]), dtype=_np.uint8)
        a = a.reshape(h, w, 3).astype(_np.uint16)
        c = a[:, :, 0] | (a[:, :, 1] << 8)
        r = ((c >> 11) & 0x1F) * 255 // 31
        g = ((c >> 5) & 0x3F) * 255 // 63
        b = (c & 0x1F) * 255 // 31
        rgba = _np.dstack([r, g, b, a[:, :, 2]]).astype(_np.uint8)
        return Image.frombytes('RGBA', (w, h), rgba.tobytes())
    im = Image.new('RGBA', (w, h))
    px = im.load()
    for y in range(h):
        base = off + y * w * 3
        for x in range(w):
            o = base + x * 3
            c = buf[o] | (buf[o + 1] << 8)
            px[x, y] = (((c >> 11) & 0x1F) * 255 // 31,
                        ((c >> 5) & 0x3F) * 255 // 63,
                        (c & 0x1F) * 255 // 31, buf[o + 2])
    return im


def encode(im, w, h, original=None, preserve_alpha=False):
    """w*h*3 bytes in the firmware's order. With preserve_alpha the alpha byte
    of every pixel is taken from `original`, so an icon's silhouette survives a
    recolour."""
    from PIL import Image
    im = im.convert('RGBA')
    if im.size != (w, h):
        im = im.resize((w, h), Image.LANCZOS)
    if _np is not None:
        a = _np.frombuffer(im.tobytes(), dtype=_np.uint8).reshape(h * w, 4)
        c = (((a[:, 0] >> 3).astype(_np.uint16) << 11)
             | ((a[:, 1] >> 2).astype(_np.uint16) << 5)
             | (a[:, 2] >> 3).astype(_np.uint16))
        out = _np.empty((h * w, 3), dtype=_np.uint8)
        out[:, 0] = c & 0xFF
        out[:, 1] = c >> 8
        out[:, 2] = a[:, 3]
        raw = out.tobytes()
        if preserve_alpha and original is not None and len(original) >= w * h * 3:
            o = _np.frombuffer(bytes(original[:w * h * 3]), dtype=_np.uint8)
            out[:, 2] = o.reshape(h * w, 3)[:, 2]
            raw = out.tobytes()
        return raw
    px = im.load()
    out = bytearray(w * h * 3)
    for y in range(h):
        for x in range(w):
            r, g, b, al = px[x, y]
            c = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
            i = (y * w + x) * 3
            out[i] = c & 0xFF
            out[i + 1] = c >> 8
            if preserve_alpha and original is not None and i + 2 < len(original):
                out[i + 2] = original[i + 2]
            else:
                out[i + 2] = al
    return bytes(out)


def smoothness(buf, blob):
    """Mean difference between neighbouring pixels, in RGB565 steps. Artwork
    lands between roughly 0.1 and 5; a block the loader allocated but never
    filled is either flat 0 or well above that."""
    if _np is None:
        return None
    n = blob.w * blob.h * 3
    a = _np.frombuffer(bytes(buf[blob.off:blob.off + n]), dtype=_np.uint8)
    a = a.reshape(blob.h, blob.w, 3).astype(_np.uint16)
    c = (a[:, :, 0] | (a[:, :, 1] << 8)).astype(_np.int32)
    rgb = _np.dstack([(c >> 11) & 0x1F, ((c >> 5) & 0x3F) >> 1, c & 0x1F])
    rgb = rgb.astype(_np.float32)
    dx = _np.abs(_np.diff(rgb, axis=1)).mean() if blob.w > 1 else 0.0
    dy = _np.abs(_np.diff(rgb, axis=0)).mean() if blob.h > 1 else 0.0
    return float((dx + dy) / 2)


def looks_like_picture(buf, blob):
    s = smoothness(buf, blob)
    if s is None:
        return True
    return 0.02 <= s <= 5.0


# --- CLI ------------------------------------------------------------------

def _payload(path):
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import htfw_tool
    fw = htfw_tool.Firmware(open(path, 'rb').read())
    if fw.body is None:
        raise SystemExit("payload is packed and could not be unpacked")
    return fw, bytes(fw.body)


def cmd_list(path, show_all=False):
    fw, body = _payload(path)
    blobs = scan(body)
    print("%-9s %-9s %-9s %-9s %s" % ("desc", "pixels", "size", "sdram", "geometry"))
    shown = 0
    for b in blobs:
        ok = looks_like_picture(body, b)
        if not ok and not show_all:
            continue
        shown += 1
        print("0x%06X  0x%06X  %7d  %08X  %4dx%-4d%s"
              % (b.hdr, b.off, b.size, b.addr, b.w, b.h,
                 "" if ok else "   (unfilled)"))
    print("\n%d images, %d shown, %.2f MB of pixels"
          % (len(blobs), shown, sum(b.size for b in blobs) / 1e6))
    rs = [r for r in runs(blobs) if r['count'] >= 3]
    if rs:
        print("\nheap runs (file offset -> SDRAM is constant inside each):")
        for r in rs:
            print("  +0x%08X  %2d blocks  0x%06X..0x%06X"
                  % (r['delta'], r['count'], r['start'], r['end']))


def cmd_dump(path, outdir):
    import os
    fw, body = _payload(path)
    if not os.path.isdir(outdir):
        os.makedirs(outdir)
    n = 0
    for b in scan(body):
        tag = '' if looks_like_picture(body, b) else '_unfilled'
        name = '%06X_%dx%d%s.png' % (b.off, b.w, b.h, tag)
        decode(body, b.off, b.w, b.h).save(os.path.join(outdir, name))
        n += 1
    print("wrote %d images to %s" % (n, outdir))


def main(argv):
    if len(argv) >= 2 and argv[0] == 'list':
        return cmd_list(argv[1], '--all' in argv)
    if len(argv) == 3 and argv[0] == 'dump':
        return cmd_dump(argv[1], argv[2])
    print(__doc__.strip().splitlines()[0])
    print("\n  gfx_index.py list <fw.bin> [--all]     the index, one line per image"
          "\n  gfx_index.py dump <fw.bin> <dir>       write every image as a PNG")
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
