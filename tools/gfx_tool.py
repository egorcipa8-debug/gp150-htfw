#!/usr/bin/env python3
# gfx_tool.py - extract / inject GP-150 firmware graphics.
#
# Pixel format, reverse engineered from GP-150 V1.0.5:
#   3 bytes per pixel, little endian:
#     [0:2]  uint16 RGB565 colour
#     [2]    uint8  alpha (0 = transparent, 255 = opaque)
#   Rows stored top to bottom, no padding, no per-image header, no compression.
#
# Images live in a flat blob with an index kept somewhere else, so slot
# geometry below was recovered by row-stride analysis, not read from the file.
#
# Usage:
#   gfx_tool.py slots
#   gfx_tool.py extract <fw.bin> <addr> <w> <h> <out.png>
#   gfx_tool.py inject  <fw.bin> <addr> <w> <h> <in.png> <out.bin>
#
# inject writes the same number of bytes it replaces, so nothing shifts and the
# section table stays valid. It recomputes the CRC-16/MODBUS of the affected
# section afterwards (the bootloader does not appear to check it, but a correct
# image costs nothing).

import sys
import struct

try:
    from PIL import Image
except ImportError:
    print("needs pillow:  python -m pip install pillow")
    raise

# name, file offset, width, height  (height is a best estimate where noted)
SLOTS = [
    ("menu_icons",    0x0B30A8,  32,  32, "first icon of a run of 32x32 icons"),
    ("drums",         0x0A2000, 152, 148, "drum kit illustration"),
    ("amp_cab_1",     0x0C0000, 172, 140, "amp / cabinet illustration"),
    ("amp_cab_2",     0x0CD800, 172, 140, "amp / cabinet illustration"),
    ("pedal_cal_1",   0x0DE000, 112, 112, "expression pedal calibration frame"),
    ("pedal_cal_2",   0x0EE0A8, 112, 112, "expression pedal calibration frame"),
    ("fx_icons",      0x10ED40,  80,  80, "effect block icons: AMP/CAB/EQ/NR/..."),
    ("small_gfx",     0x1EA800,  28,  28, "small UI elements"),
    ("font_a",        0x714000,   8,  16, "font glyphs"),
    ("font_b",        0x730000,   8,  16, "font glyphs"),
]

_REF8 = [int('{:08b}'.format(i)[::-1], 2) for i in range(256)]
_TAB = []
for _i in range(256):
    _c = _i << 8
    for _ in range(8):
        _c = ((_c << 1) ^ 0x8005) & 0xFFFF if _c & 0x8000 else (_c << 1) & 0xFFFF
    _TAB.append(_c)


def _refl16(v):
    r = 0
    for i in range(16):
        if v >> i & 1:
            r |= 1 << (15 - i)
    return r


def crc16_modbus(data):
    c = 0xFFFF
    for x in data:
        c = ((c << 8) & 0xFFFF) ^ _TAB[((c >> 8) ^ _REF8[x]) & 0xFF]
    return _refl16(c)


def sections(blob):
    image_size = struct.unpack_from('<I', blob, 0x24)[0]
    payload = len(blob) - image_size
    out = []
    off = 0x38
    while True:
        rec = blob[off:off + 16]
        if len(rec) < 16 or rec[0:4] == b'\xff\xff\xff\xff' or not (0x61 <= rec[3] <= 0x7a):
            break
        flash, soff, slen = struct.unpack_from('<III', rec, 4)
        out.append({'tag': chr(rec[3]), 'rec': off, 'flash': flash,
                    'off': soff, 'len': slen, 'file': payload + soff})
        off += 16
    return out


def decode(blob, addr, w, h):
    img = Image.new('RGBA', (w, h))
    px = img.load()
    for y in range(h):
        base = addr + y * w * 3
        for x in range(w):
            o = base + x * 3
            if o + 2 >= len(blob):
                return img
            c = struct.unpack_from('<H', blob, o)[0]
            a = blob[o + 2]
            px[x, y] = (((c >> 11) & 0x1F) * 255 // 31,
                        ((c >> 5) & 0x3F) * 255 // 63,
                        (c & 0x1F) * 255 // 31, a)
    return img


def encode(img, w, h):
    img = img.convert('RGBA')
    if img.size != (w, h):
        img = img.resize((w, h), Image.LANCZOS)
    px = img.load()
    out = bytearray()
    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            c = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
            out += struct.pack('<HB', c, a)
    return bytes(out)


def cmd_slots():
    print("%-13s %-10s %-9s %-9s  %s" % ("name", "offset", "size", "bytes", "note"))
    for n, a, w, h, note in SLOTS:
        print("%-13s 0x%06X   %4dx%-4d %8d  %s" % (n, a, w, h, w * h * 3, note))
    print("\nGeometry was derived by row-stride analysis. Height is the least certain")
    print("value - if an extracted image looks cut off or runs into the next one,")
    print("adjust h and extract again before injecting anything.")


def cmd_extract(fw, addr, w, h, out):
    blob = open(fw, 'rb').read()
    decode(blob, addr, w, h).save(out)
    print("extracted 0x%06X %dx%d (%d bytes) -> %s" % (addr, w, h, w * h * 3, out))


def cmd_inject(fw, addr, w, h, png, out):
    blob = bytearray(open(fw, 'rb').read())
    data = encode(Image.open(png), w, h)
    n = w * h * 3
    if len(data) != n:
        print("internal size mismatch"); return 1
    if addr + n > len(blob):
        print("image would run past end of file"); return 1
    secs = sections(blob)
    hit = [s for s in secs if s['file'] <= addr < s['file'] + s['len']]
    if not hit:
        print("offset 0x%06X is not inside any section" % addr); return 1
    s = hit[0]
    if addr + n > s['file'] + s['len']:
        print("image would cross the end of section %s" % s['tag']); return 1
    blob[addr:addr + n] = data
    body = bytes(blob[s['file']:s['file'] + s['len']])
    crc = crc16_modbus(body)
    old = (blob[s['rec']] << 8) | blob[s['rec'] + 1]
    struct.pack_into('>H', blob, s['rec'], crc)
    open(out, 'wb').write(bytes(blob))
    print("injected %s -> 0x%06X (%d bytes) in section %s" % (png, addr, n, s['tag']))
    print("section %s CRC 0x%04X -> 0x%04X" % (s['tag'], old, crc))
    print("written %s (%d bytes, unchanged size)" % (out, len(blob)))
    return 0


if __name__ == '__main__':
    a = sys.argv[1:]
    if not a:
        print("commands: slots | extract | inject   (see header comment)")
        sys.exit(1)
    if a[0] == 'slots':
        cmd_slots()
    elif a[0] == 'extract' and len(a) == 6:
        cmd_extract(a[1], int(a[2], 0), int(a[3]), int(a[4]), a[5])
    elif a[0] == 'inject' and len(a) == 7:
        sys.exit(cmd_inject(a[1], int(a[2], 0), int(a[3]), int(a[4]), a[5], a[6]))
    else:
        print("commands: slots | extract | inject   (see header comment)")
        sys.exit(1)
