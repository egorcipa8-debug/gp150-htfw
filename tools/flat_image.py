#!/usr/bin/env python3
"""flat_image.py - lay the firmware out the way the chip sees it.

The container stores each region with the flash address it belongs at, and the
RT1064 maps that flash into the address space at **0x60000000** (FlexSPI XIP).
So a disassembler wants one flat file with every region at
`0x60000000 + flash address`, which is what this writes - and with that, section
`d` stops being a blob:

    aligned words pointing inside section d, by candidate base
      0x60800000   798      <- FlexSPI XIP, its own flash address
      0x00800000   364
      0x80000000   239
      0x00838000   250
      0x70800000    41

Nothing else comes close, so the application is executed in place from flash
rather than copied to SDRAM. (Regions `g` and `h` carry flash address 0 because
they are other chips' firmware - see FINDINGS - and are left out.)

    flat_image.py <fw.bin> <out.bin>          write the flat image
    flat_image.py map <fw.bin>                just print the layout
    flat_image.py base <fw.bin> [tag]         re-run the base measurement

`map` prints the ranges to give a disassembler, including where the code is:
a region's code is the part with Thumb in it, which `base` finds by counting
self-references rather than by guessing.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

XIP = 0x60000000

try:
    import numpy as _np
except ImportError:                                   # pragma: no cover
    _np = None


def load(path):
    import htfw_tool
    fw = htfw_tool.Firmware(open(path, 'rb').read())
    if fw.body is None:
        raise SystemExit("payload is packed and could not be unpacked")
    return fw, bytes(fw.body)


def layout(fw):
    """[(tag, address, length, payload offset)] for the regions that live in the
    RT1064's own flash."""
    out = []
    for s in fw.sections:
        if s.flash == 0:
            continue
        out.append((s.tag, XIP + s.flash, s.len, s.off))
    return sorted(out, key=lambda r: r[1])


def build(fw, body):
    rows = layout(fw)
    lo = min(r[1] for r in rows)
    hi = max(r[1] + r[2] for r in rows)
    img = bytearray(b'\xFF' * (hi - lo))
    for _tag, addr, ln, off in rows:
        img[addr - lo:addr - lo + ln] = body[off:off + ln]
    return lo, bytes(img)


def self_refs(body, off, ln, base):
    """How many 4-aligned words in a region point inside that region if it is
    loaded at `base`. The right base wins by a wide margin."""
    if _np is None:
        return None
    d = body[off:off + ln]
    n = (len(d) // 4) * 4
    w = _np.frombuffer(d[:n], dtype='<u4')
    return int(((w >= base) & (w < base + ln)).sum())


def cmd_map(path):
    fw, body = load(path)
    lo, _img = build(fw, body)
    print("flat image starts at 0x%08X" % lo)
    print("%-4s %-12s %-10s %-10s %s" % ("id", "address", "length", "in file", "self-refs at that base"))
    for tag, addr, ln, off in layout(fw):
        n = self_refs(body, off, ln, addr)
        print("%-4s 0x%08X   %-10d 0x%06X   %s"
              % (tag, addr, ln, off, n if n is not None else '-'))
    print("\nuninitialised blocks the chip also has:")
    for nm, a, sz in (("ITCM", 0x00000000, 0x80000), ("DTCM", 0x20000000, 0x80000),
                      ("OCRAM", 0x20200000, 0x200000), ("SDRAM", 0x80000000, 0x2000000),
                      ("AIPS", 0x40000000, 0x2000000)):
        print("  %-6s 0x%08X + 0x%X" % (nm, a, sz))


def cmd_base(path, tag=None):
    fw, body = load(path)
    for s in fw.sections:
        if s.flash == 0 or (tag and s.tag != tag):
            continue
        best = []
        for base in list(range(0x60000000, 0x61000000, 0x40000)) + \
                    list(range(0x80000000, 0x80400000, 0x40000)) + \
                    [0x00000000 + s.flash, XIP + s.flash, 0x70000000 + s.flash,
                     0x20200000]:
            n = self_refs(body, s.off, s.len, base)
            if n:
                best.append((n, base))
        best.sort(reverse=True)
        print("section %s (flash 0x%08X, %d bytes)" % (s.tag, s.flash, s.len))
        for n, base in best[:4]:
            mark = "  <- its own flash address, XIP" if base == XIP + s.flash else ""
            print("   0x%08X  %6d words point inside%s" % (base, n, mark))


def cmd_build(path, out):
    fw, body = load(path)
    lo, img = build(fw, body)
    open(out, 'wb').write(img)
    print("%s: %d bytes at 0x%08X..0x%08X" % (out, len(img), lo, lo + len(img)))
    print("import it as ARM:LE:32:Cortex, base 0x%08X, and disassemble as Thumb"
          % lo)
    for tag, addr, ln, _off in layout(fw):
        print("   %s  0x%08X..0x%08X" % (tag, addr, addr + ln))


def main(argv):
    if len(argv) >= 2 and argv[0] == 'map':
        return cmd_map(argv[1])
    if len(argv) >= 2 and argv[0] == 'base':
        return cmd_base(argv[1], argv[2] if len(argv) > 2 else None)
    if len(argv) == 2:
        return cmd_build(argv[0], argv[1])
    print(__doc__.strip())
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
