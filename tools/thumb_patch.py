#!/usr/bin/env python3
"""thumb_patch.py - change the constants the interface is drawn with.

The pedal's panels, bars and highlights are not pictures. They are rectangles
the application fills, so their colours and their coordinates are immediate
operands in Thumb instructions, sitting in region `d` at 0x60800000 (see
FINDINGS: the application is executed in place from flash, not copied to SDRAM).
This finds those immediates and rewrites them.

Two encodings carry them:

```
MOVW Rd, #imm16    11110 i 10 0100 imm4 : 0 imm3 Rd imm8      f2 4x .. ..
MOV  Rd, #imm8     00100 Rd imm8                              2x ..
```

A 16-bit colour is always a MOVW - RGB565 does not fit anywhere else - and small
coordinates are usually the 8-bit form.

    thumb_patch.py find    <fw.bin> <value> [--in d] [--kind movw|mov8]
    thumb_patch.py colours <fw.bin> [--top N]      what looks like a palette
    thumb_patch.py set     <fw.bin> <addr> <value> <out.bin>
    thumb_patch.py swap    <fw.bin> <from> <to> <out.bin> [--in d] [--limit N]

`swap` rewrites every instruction in the region that loads `from`, which is how
a colour used in fifty places changes at once. It refuses to touch anything
outside the region you name, prints every address it changed, and re-stamps the
region CRCs and the whole-file checksum, so the result is a valid image.

Nothing here can tell a colour from a length that happens to have the same
value. Change one, flash it, look at the screen - that is the loop.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

XIP = 0x60000000


def load(path):
    import htfw_tool
    fw = htfw_tool.Firmware(open(path, 'rb').read())
    if fw.body is None:
        raise SystemExit("payload is packed and could not be unpacked")
    return fw, bytearray(fw.body)


def region(fw, tag):
    for s in fw.sections:
        if s.tag == tag:
            return s
    raise SystemExit("no region %r in this image" % tag)


def addr_of(fw, tag, off):
    """Payload offset -> the address the chip sees."""
    s = region(fw, tag)
    return XIP + s.flash + (off - s.off)


def off_of(fw, tag, addr):
    s = region(fw, tag)
    return s.off + (addr - XIP - s.flash)


def find_movw(body, lo, hi, value=None):
    """(offset, register, immediate) for every MOVW in the range."""
    out = []
    for p in range(lo, hi - 3, 2):
        w1 = body[p] | (body[p + 1] << 8)
        w2 = body[p + 2] | (body[p + 3] << 8)
        if (w1 & 0xFBF0) != 0xF240 or (w2 & 0x8000):
            continue
        i = (w1 >> 10) & 1
        imm4 = w1 & 0xF
        imm3 = (w2 >> 12) & 7
        rd = (w2 >> 8) & 0xF
        imm8 = w2 & 0xFF
        imm = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8
        if value is None or imm == value:
            out.append((p, rd, imm))
    return out


def find_mov8(body, lo, hi, value=None):
    out = []
    for p in range(lo, hi - 1, 2):
        w = body[p] | (body[p + 1] << 8)
        if (w & 0xF800) != 0x2000:
            continue
        rd = (w >> 8) & 7
        imm = w & 0xFF
        if value is None or imm == value:
            out.append((p, rd, imm))
    return out


def set_movw(body, off, value):
    if not 0 <= value <= 0xFFFF:
        raise ValueError("a MOVW immediate is 16 bits")
    w1 = body[off] | (body[off + 1] << 8)
    w2 = body[off + 2] | (body[off + 3] << 8)
    if (w1 & 0xFBF0) != 0xF240:
        raise ValueError("no MOVW at that offset")
    rd = (w2 >> 8) & 0xF
    imm4 = (value >> 12) & 0xF
    i = (value >> 11) & 1
    imm3 = (value >> 8) & 7
    imm8 = value & 0xFF
    w1 = 0xF240 | (i << 10) | imm4
    w2 = (imm3 << 12) | (rd << 8) | imm8
    body[off] = w1 & 0xFF
    body[off + 1] = w1 >> 8
    body[off + 2] = w2 & 0xFF
    body[off + 3] = w2 >> 8


def rgb(v):
    return (((v >> 11) & 0x1F) * 255 // 31, ((v >> 5) & 0x3F) * 255 // 63,
            (v & 0x1F) * 255 // 31)


def build(fw, body, out):
    import htfw_tool
    body = bytes(body)
    if fw.packed:
        if htfw_tool.lzodll is None:
            raise SystemExit("this image is LZO-packed and Valeton Suite's "
                             "minilzo_plugin.dll was not found")
        comp = htfw_tool.lzodll.compress(body)
        tail = struct.pack('<I', len(body)) + comp
        head = bytearray(fw.blob[:fw.pack_off])
    else:
        tail = body
        head = bytearray(fw.blob[:fw.payload])
    for s in fw.sections:
        crc = htfw_tool.crc16_modbus(body[s.off:s.off + s.len])
        struct.pack_into('>H', head, s.rec, crc)
    struct.pack_into('<I', head, 0x24, len(body))
    struct.pack_into('<I', head, 8, len(head) + len(tail))
    data = htfw_tool.seal(bytes(head) + tail)
    open(out, 'wb').write(data)
    return len(data)


# --------------------------------------------------------------------------

def cmd_find(path, value, tag='d', kind='movw'):
    fw, body = load(path)
    s = region(fw, tag)
    lo, hi = s.off, s.off + s.len
    hits = (find_movw if kind == 'movw' else find_mov8)(body, lo, hi, value)
    print("%d instruction(s) in region %s load 0x%X" % (len(hits), tag, value))
    for off, rd, imm in hits[:200]:
        print("  0x%08X  r%-2d  #0x%04X" % (addr_of(fw, tag, off), rd, imm))
    if len(hits) > 200:
        print("  ... and %d more" % (len(hits) - 200))


def cmd_colours(path, tag='d', top=40):
    """MOVW immediates that could be RGB565: what a palette looks like from the
    outside. Values under 0x100 are dropped - those are counts and flags."""
    import collections
    fw, body = load(path)
    s = region(fw, tag)
    hits = find_movw(body, s.off, s.off + s.len)
    c = collections.Counter(imm for _o, _r, imm in hits if imm >= 0x100)
    print("%-8s %-6s %-16s %s" % ("value", "uses", "rgb", "swatch"))
    for v, n in c.most_common(top):
        r, g, b = rgb(v)
        # peripheral addresses are the noise here; they cluster in 0x4000-0x6900
        note = "  (looks like a peripheral address)" if 0x4000 <= v <= 0x6900 else ""
        print("0x%04X   %5d  #%02X%02X%02X          %s%s"
              % (v, n, r, g, b, "%3d,%3d,%3d" % (r, g, b), note))


def cmd_set(path, addr, value, out, tag='d'):
    fw, body = load(path)
    off = off_of(fw, tag, addr)
    before = find_movw(body, off, off + 4)
    if not before:
        raise SystemExit("no MOVW at 0x%08X" % addr)
    set_movw(body, off, value)
    n = build(fw, body, out)
    print("0x%08X: #0x%04X -> #0x%04X" % (addr, before[0][2], value))
    print("wrote %s (%d bytes), CRCs restamped" % (out, n))


def cmd_swap(path, old, new, out, tag='d', limit=0):
    fw, body = load(path)
    s = region(fw, tag)
    hits = find_movw(body, s.off, s.off + s.len, old)
    if not hits:
        raise SystemExit("nothing in region %s loads 0x%X" % (tag, old))
    if limit and len(hits) > limit:
        raise SystemExit("%d instructions load it, more than the %d you allowed"
                         % (len(hits), limit))
    for off, _rd, _imm in hits:
        set_movw(body, off, new)
        print("  0x%08X  #0x%04X -> #0x%04X" % (addr_of(fw, tag, off), old, new))
    n = build(fw, body, out)
    print("%d instruction(s) changed; wrote %s (%d bytes)" % (len(hits), out, n))


def main(argv):
    if not argv:
        print(__doc__.strip())
        return 1
    tag = 'd'
    kind = 'movw'
    top = 40
    limit = 0
    rest = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '--in' and i + 1 < len(argv):
            tag = argv[i + 1]; i += 2
        elif a == '--kind' and i + 1 < len(argv):
            kind = argv[i + 1]; i += 2
        elif a == '--top' and i + 1 < len(argv):
            top = int(argv[i + 1]); i += 2
        elif a == '--limit' and i + 1 < len(argv):
            limit = int(argv[i + 1]); i += 2
        else:
            rest.append(a); i += 1
    if len(rest) == 3 and rest[0] == 'find':
        return cmd_find(rest[1], int(rest[2], 0), tag, kind)
    if len(rest) >= 2 and rest[0] == 'colours':
        return cmd_colours(rest[1], tag, top)
    if len(rest) == 5 and rest[0] == 'set':
        return cmd_set(rest[1], int(rest[2], 0), int(rest[3], 0), rest[4], tag)
    if len(rest) == 5 and rest[0] == 'swap':
        return cmd_swap(rest[1], int(rest[2], 0), int(rest[3], 0), rest[4], tag,
                        limit)
    print(__doc__.strip())
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
