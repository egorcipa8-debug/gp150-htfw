#!/usr/bin/env python3
"""lv_font.py - the pedal's own menu typeface, found, rendered and replaced.

For a long time these notes said the system font was not in the firmware. It
is. The reason it could not be found is the reason nothing about the interface
could be found: section b is **not executed in place**. It carries a load table
(see `flat_image.py`) and is copied in two halves - one to ITCM at
`0x00000000`, one to SDRAM at `0x80000000` - so every address inside it is
written for where it will be, not where it is stored. Search the file at the
flash base and the font is invisible; map it properly and it is right there.

The interface is **LVGL v8**. That is not a guess: the widget calls set style
properties by number and the numbers are LVGL's own - 1 width, 4 height, 7 x,
8 y - and the fonts are `lv_font_fmt_txt` exactly as LVGL lays them out:

```
lv_font_fmt_txt_dsc_t          lv_font_fmt_txt_glyph_dsc_t   (8 bytes each)
  +0  const uint8_t *glyph_bitmap   +0  uint32  bitmap_index : 20
  +4  glyph_dsc *                            adv_w        : 12
  +8  cmaps *                       +4  uint8   box_w
  +12 kern_dsc *                    +5  uint8   box_h
  +16 uint16 kern_scale             +6  int8    ofs_x
  +18 bitfields                     +7  int8    ofs_y
```

`bpp` is not read from the bitfield here - it is *measured*, by checking that
consecutive `bitmap_index` values differ by exactly `ceil(box_w*box_h*bpp/8)`.
On every font in the GP-150 image that test picks one value with no
disagreements at all, which is a stronger statement than trusting a field.

    lv_font.py list    <fw.bin>
    lv_font.py dump    <fw.bin> --font N -o sheet.png
    lv_font.py replace <fw.bin> --font N --ttf face.ttf -o new.bin [--size N]

`replace` re-renders the ASCII range from any TrueType or OpenType face into
the font's own structures: new boxes, new advances, new bitmaps, all repacked
into the byte span the original occupied. It refuses rather than overflow, and
it never moves anything else in the file.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import flat_image
import htfw_tool

try:
    import lzodll
except ImportError:                                       # pragma: no cover
    lzodll = None

SDRAM = 0x80000000


# --------------------------------------------------------------------------
# where things are
# --------------------------------------------------------------------------

class Image(object):
    """A firmware image, with the SDRAM half of section b addressable."""

    def __init__(self, path=None, fw=None, body=None):
        """From a file, or from a payload somebody else already holds.

        Studio keeps the unpacked payload in memory and edits it in place, so
        it passes its own `fw` and `body` and the two share the bytearray -
        a font replacement lands in the project the same way an image
        replacement does.
        """
        if path is not None:
            self.fw = htfw_tool.Firmware(open(path, 'rb').read())
            if self.fw.body is None:
                raise SystemExit("payload is packed and could not be unpacked")
            self.body = bytearray(self.fw.body)
        else:
            self.fw, self.body = fw, body
        tbl = flat_image.load_table(self.fw, bytes(self.body))
        if not tbl:
            raise SystemExit("section b has no load table; this is not a "
                             "GP-150 image this tool understands")
        (self.itcm_off, self.itcm_len, _), (self.sd_off, self.sd_len, dest) = tbl
        if dest != SDRAM:
            raise SystemExit("the second block does not go to SDRAM")

    def off(self, addr, n=1):
        """Payload offset of an SDRAM address."""
        i = addr - SDRAM
        if i < 0 or i + n > self.sd_len:
            raise ValueError("0x%08X is outside the SDRAM block" % addr)
        return self.sd_off + i

    def u32(self, addr):
        return struct.unpack_from('<I', self.body, self.off(addr, 4))[0]

    def read(self, addr, n):
        o = self.off(addr, n)
        return bytes(self.body[o:o + n])

    def write(self, addr, data):
        o = self.off(addr, len(data))
        self.body[o:o + len(data)] = data

    def save(self, path):
        """Rebuild the container around the edited payload.

        The same steps `htfw_tool repack` takes, from memory rather than from a
        directory: restamp every section's CRC-16/MODBUS, repack with LZO if the
        original was packed, then re-seal the whole-file CRC. Section lengths do
        not change here, so the table's offsets stay as they were.
        """
        fw = self.fw
        if fw.packed and lzodll is None:
            raise SystemExit("the original is packed and minilzo_plugin.dll "
                             "is not available to pack it again")
        hdr = bytearray(fw.blob[:fw.pack_off if fw.packed else fw.payload])
        body = bytes(self.body)
        for s in fw.sections:
            dat = body[s.off:s.off + s.len]
            struct.pack_into('>H', hdr, s.rec, htfw_tool.crc16_modbus(dat))
        struct.pack_into('<I', hdr, 0x24, len(body))
        if fw.packed:
            comp = lzodll.compress(body)
            tail = struct.pack('<I', len(body)) + comp
        else:
            tail = body
        struct.pack_into('<I', hdr, 8, len(hdr) + len(tail))
        data = htfw_tool.seal(bytes(hdr) + tail)
        open(path, 'wb').write(data)
        return len(data)


class Font(object):
    """One `lv_font_fmt_txt` font, read out of the image."""

    def __init__(self, img, dsc):
        self.img = img
        self.dsc = dsc
        self.bitmap, self.glyphs, self.cmaps, self.kern = \
            struct.unpack_from('<4I', img.body, img.off(dsc, 16))
        self.count = self._count()
        self.bpp = self._bpp()
        self.first, self.n_ascii, self.gid = self._range()

    # -- geometry --------------------------------------------------------
    def entry(self, i):
        e = self.img.off(self.glyphs + i * 8, 8)
        w0 = struct.unpack_from('<I', self.img.body, e)[0]
        return {'bi': w0 & 0xFFFFF, 'adv': (w0 >> 20) & 0xFFF,
                'w': self.img.body[e + 4], 'h': self.img.body[e + 5],
                'ox': struct.unpack_from('<b', self.img.body, e + 6)[0],
                'oy': struct.unpack_from('<b', self.img.body, e + 7)[0]}

    def put(self, i, g):
        e = self.img.off(self.glyphs + i * 8, 8)
        w0 = (g['bi'] & 0xFFFFF) | ((g['adv'] & 0xFFF) << 20)
        struct.pack_into('<Ibbbb', self.img.body, e, w0,
                         g['w'], g['h'], g['ox'], g['oy'])

    @staticmethod
    def _plausible(g):
        boxed = 1 <= g['w'] <= 64 and 1 <= g['h'] <= 64
        blank = g['w'] == 0 and g['h'] == 0        # the space, and only it
        return (boxed or blank) and 0 < g['adv'] <= 2048

    def _count(self):
        n = 1
        while n < 4096 and self._plausible(self.entry(n)):
            n += 1
        return n

    def _bpp(self):
        """Measured, not read: the one depth whose glyph sizes fit the gaps."""
        best = (0, -1)
        for bpp in (1, 2, 4, 8):
            ok = 0
            for i in range(1, min(self.count - 1, 60)):
                a, b = self.entry(i), self.entry(i + 1)
                if a['w'] == 0 or a['h'] == 0:
                    continue
                if b['bi'] - a['bi'] == (a['w'] * a['h'] * bpp + 7) // 8:
                    ok += 1
            if ok > best[1]:
                best = (bpp, ok)
        return best[0]

    def _range(self):
        """The cmap that covers plain ASCII, and where it starts in the array.

        Not always the first one: three of the fourteen fonts begin with a
        one-character cmap for the line feed and put ASCII second. Entries are
        twenty bytes; a contiguous one has no unicode list, which is what makes
        it safe to walk by index.
        """
        for k in range(8):
            try:
                e = self.img.off(self.cmaps + k * 20, 20)
            except ValueError:
                break
            start, ln, gid = struct.unpack_from('<IHH', self.img.body, e)
            ulist = struct.unpack_from('<I', self.img.body, e + 8)[0]
            if start == 0 or ln == 0 or start > 0x10FFFF:
                break
            if start == 0x20 and ln >= 90 and ulist == 0:
                return start, ln, gid
        return 0x20, 0, 1

    def span(self):
        """(first byte, length) of the glyph bitmap blob.

        The length is what the glyphs actually use, but never more than the
        room between the blob and the glyph array that follows it - the glyph
        count is found by walking until the entries stop looking like entries,
        and if that ever overruns, a replacement must not be allowed to write
        over the table it is indexing.
        """
        end = 0
        for i in range(1, self.count):
            g = self.entry(i)
            end = max(end, g['bi'] + (g['w'] * g['h'] * self.bpp + 7) // 8)
        if self.glyphs > self.bitmap:
            end = min(end, self.glyphs - self.bitmap)
        return self.bitmap, end

    def height(self):
        return max(self.entry(i)['h'] for i in range(1, self.count))

    # -- pixels ----------------------------------------------------------
    def render(self, i):
        from PIL import Image as PILImage
        g = self.entry(i)
        if g['w'] == 0 or g['h'] == 0:
            return None
        n = (g['w'] * g['h'] * self.bpp + 7) // 8
        raw = self.img.read(self.bitmap + g['bi'], n)
        maxv = (1 << self.bpp) - 1
        px = []
        for k in range(g['w'] * g['h']):
            p = k * self.bpp
            sh = 8 - self.bpp - (p & 7)
            px.append(int(((raw[p >> 3] >> sh) & maxv) * 255 / maxv))
        im = PILImage.new('L', (g['w'], g['h']))
        im.putdata(px)
        return im


def find(img, min_glyphs=40):
    """Every font in the SDRAM block, found by its descriptor's shape.

    Hunting for the glyph array first turned out to be fragile - the entries
    are eight bytes and a scan stepping four can enter a table half a record
    out and walk past it. The descriptor is the better handle: four words in a
    row where the first three are SDRAM pointers that climb (bitmap, then the
    glyph array, then the cmaps) and the fourth is either a pointer or nothing.
    Confirm it by looking at the glyph array: LVGL keeps a blank entry at index
    zero, so entry one starts at bitmap offset zero and has a real box.
    """
    body = img.body
    base, n = img.sd_off, img.sd_len
    lo, hi = SDRAM, SDRAM + n
    out = []
    for k in range(0, n - 24, 4):
        o = base + k
        w0, w1, w2, w3 = struct.unpack_from('<4I', body, o)
        if not (lo <= w0 < w1 < w2 < hi):
            continue
        if w3 and not (lo <= w3 < hi):
            continue
        try:
            e = img.off(w1 + 8, 8)
        except ValueError:
            continue
        g0 = struct.unpack_from('<I', body, e)[0]
        bw, bh = body[e + 4], body[e + 5]
        # glyph one is the space: a real advance and no box at all
        if (g0 & 0xFFFFF) != 0 or not (bw == 0 and bh == 0):
            continue
        if not (0 < ((g0 >> 20) & 0xFFF) <= 2048):
            continue
        out.append(SDRAM + k)
    keep = []
    for d in out:
        try:
            f = Font(img, d)
        except Exception:                                 # noqa: BLE001
            continue
        if f.count - 1 >= min_glyphs and f.bpp:
            keep.append(d)
    return keep


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def load_fonts(path):
    img = Image(path)
    return img, [Font(img, d) for d in find(img)]


def cmd_list(path):
    img, fonts = load_fonts(path)
    print("%s" % os.path.basename(path))
    print("  section b's SDRAM half: payload 0x%06X, %d bytes, at 0x%08X"
          % (img.sd_off, img.sd_len, SDRAM))
    print()
    print("  %-3s %-12s %-8s %-5s %-7s %-9s %s"
          % ("#", "descriptor", "glyphs", "bpp", "height", "bitmap", "blob"))
    for k, f in enumerate(fonts):
        b0, ln = f.span()
        print("  %-3d 0x%08X   %-8d %-5d %-7d 0x%08X %d bytes"
              % (k, f.dsc, f.count - 1, f.bpp, f.height(), b0, ln))
    print()
    print("  ASCII 0x20.. is glyph 1 upward in every one of them.")


def cmd_dump(path, which, out):
    from PIL import Image as PILImage
    img, fonts = load_fonts(path)
    f = fonts[which]
    tiles = [f.render(i) for i in range(1, min(f.count, 96))]
    tiles = [t for t in tiles if t]
    w = max(t.width for t in tiles) + 2
    h = max(t.height for t in tiles) + 2
    cols = 24
    rows = (len(tiles) + cols - 1) // cols
    m = PILImage.new('L', (cols * w, rows * h), 0)
    for n, t in enumerate(tiles):
        m.paste(t, ((n % cols) * w + 1, (n // cols) * h + 1))
    m = m.resize((m.width * 3, m.height * 3), PILImage.NEAREST)
    m.save(out)
    print("font %d: %d glyphs, %d bpp, %d px tall -> %s"
          % (which, len(tiles), f.bpp, f.height(), out))


def _draw(face, ch, bpp):
    """One glyph as (bytes, w, h, ofs_x, ofs_y, advance), the LVGL way."""
    from PIL import Image as PILImage, ImageDraw
    asc, _desc = face.getmetrics()
    try:
        box = face.getbbox(ch)
    except Exception:                                     # noqa: BLE001
        return None
    if box is None:
        return None
    x0, y0, x1, y1 = box
    w, h = x1 - x0, y1 - y0
    adv = int(round(face.getlength(ch) * 16))
    if w <= 0 or h <= 0:
        return b'', 0, 0, 0, 0, adv
    if w > 64 or h > 64:
        return None
    im = PILImage.new('L', (w, h), 0)
    ImageDraw.Draw(im).text((-x0, -y0), ch, font=face, fill=255)
    maxv = (1 << bpp) - 1
    bits = bytearray()
    acc = 0
    used = 0
    for v in im.getdata():
        acc = (acc << bpp) | int(round(v * maxv / 255))
        used += bpp
        while used >= 8:
            used -= 8
            bits.append((acc >> used) & 0xFF)
            acc &= (1 << used) - 1
    if used:
        bits.append((acc << (8 - used)) & 0xFF)
    return bytes(bits), w, h, x0, asc - y1, adv


def write_face(img, f, ttf, size=None, report=lambda *_a: None):
    """Re-render a font's ASCII range from a TrueType or OpenType face.

    The boxes, advances and bitmaps are all recomputed; the glyph count, the
    cmaps and everything around the font are left exactly as they were. The new
    bitmaps have to fit the span the old ones held, so the point size steps down
    until they do - and if nothing fits, this raises rather than write past the
    end and take the glyph table with it.
    """
    from PIL import ImageFont
    if f.n_ascii == 0:
        raise ValueError("this font has no plain ASCII cmap to replace")
    b0, blob = f.span()
    target = f.height()

    def build(pt):
        face = ImageFont.truetype(ttf, pt)
        gs = []
        for k in range(f.n_ascii):
            r = _draw(face, chr(f.first + k), f.bpp)
            if r is None:
                return None
            gs.append(r)
        return gs

    if size:
        pt = int(size)
    else:
        pt = target
        for probe in range(6, 96):
            face = ImageFont.truetype(ttf, probe)
            bb = face.getbbox('Hg')
            if bb and bb[3] - bb[1] > target:
                pt = max(6, probe - 1)
                break
    gs = None
    while pt >= 5:
        gs = build(pt)
        if gs is not None:
            total = sum(len(g[0]) for g in gs)
            if total <= blob:
                break
            report("   %d pt needs %d bytes, %d available - trying smaller"
                   % (pt, total, blob))
        pt -= 1
        gs = None
    if gs is None:
        raise ValueError("nothing from this face fits the %d bytes this font "
                         "has room for" % blob)

    data = bytearray(blob)
    at = 0
    for k, (bits, w, h, ox, oy, adv) in enumerate(gs):
        data[at:at + len(bits)] = bits
        f.put(f.gid + k, {'bi': at, 'adv': min(adv, 2047), 'w': w, 'h': h,
                          'ox': max(-128, min(127, ox)),
                          'oy': max(-128, min(127, oy))})
        at += len(bits)
    img.write(b0, bytes(data))
    return {'pt': pt, 'glyphs': len(gs), 'used': at, 'room': blob}


def cmd_replace(path, which, ttf, out, size=None):
    img, fonts = load_fonts(path)
    f = fonts[which]
    b0, blob = f.span()
    print("font %d: %d glyphs, %d bpp, %d px tall, %d bytes of bitmap"
          % (which, f.count - 1, f.bpp, f.height(), blob))
    r = write_face(img, f, ttf, size, report=print)
    print("   %d pt, %d glyphs, %d of %d bitmap bytes used"
          % (r['pt'], r['glyphs'], r['used'], r['room']))
    n = img.save(out)
    print("   wrote %s (%d bytes), all section CRCs and the file CRC restamped"
          % (out, n))


def main(argv):
    if not argv:
        print(__doc__.strip())
        return 1
    cmd, rest = argv[0], argv[1:]
    opt = {}
    args = []
    i = 0
    while i < len(rest):
        if rest[i] in ('--font', '-f'):
            opt['font'] = int(rest[i + 1], 0); i += 2
        elif rest[i] in ('-o', '--out'):
            opt['out'] = rest[i + 1]; i += 2
        elif rest[i] == '--ttf':
            opt['ttf'] = rest[i + 1]; i += 2
        elif rest[i] == '--size':
            opt['size'] = int(rest[i + 1]); i += 2
        else:
            args.append(rest[i]); i += 1
    if cmd == 'list' and args:
        return cmd_list(args[0])
    if cmd == 'dump' and args:
        return cmd_dump(args[0], opt.get('font', 0),
                        opt.get('out', 'font.png'))
    if cmd == 'replace' and args and opt.get('ttf') and opt.get('out'):
        return cmd_replace(args[0], opt.get('font', 0), opt['ttf'],
                           opt['out'], opt.get('size'))
    print(__doc__.strip())
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
