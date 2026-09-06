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


def load_table(fw, body):
    """Section b's own header: where its two halves are copied to at boot.

    Section b is **not** executed in place. Its first 0x28 bytes are a header
    whose two (flash address, size) pairs each carry a destination:

        0x10  u32 flash address   0x14  u32 size   0x18  u32 destination
        0x1C  u32 flash address   0x20  u32 size   0x24  u32 destination

    and on every GP-150 image seen so far that reads

        b + 0x28      218089 bytes  -> 0x00000000  (ITCM)   the application
        b + 0x35411  5011313 bytes  -> 0x80000000  (SDRAM)  the interface

    with the two runs consecutive and ending at the section's own end. This is
    what makes the interface reachable: it is in the file, it is simply written
    for the address it will be copied to rather than the one it is stored at.
    Returns [(payload offset, size, destination)] or [] if the header does not
    look like one.
    """
    sec = next((x for x in fw.sections if x.tag == 'b'), None)
    if sec is None or sec.len < 0x28:
        return []
    hdr = body[sec.off:sec.off + 0x28]
    a1, s1, d1, a2, s2, d2 = struct.unpack_from('<6I', hdr, 0x10)
    if a1 != sec.flash + 0x28 or a1 + s1 != a2 or a2 + s2 > sec.flash + sec.len:
        return []
    if d1 != 0 or not (0x80000000 <= d2 < 0x82000000):
        return []
    return [(sec.off + (a1 - sec.flash), s1, d1),
            (sec.off + (a2 - sec.flash), s2, d2)]


def layout(fw, body=None):
    """[(tag, address, length, payload offset)] as the chip actually sees it.

    Sections c, d, e and f are executed or read in place, so they sit at
    `0x60000000 + flash address`. Section b is split by its own load table
    (see `load_table`) into an ITCM half and an SDRAM half; g and h go to other
    chips entirely and are left out.
    """
    out = []
    split = load_table(fw, body) if body is not None else []
    for s in fw.sections:
        if s.flash == 0:
            continue
        if s.tag == 'b' and split:
            for n, (off, ln, dest) in enumerate(split):
                out.append(('b%d' % (n + 1), dest, ln, off))
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
    tbl = load_table(fw, body)
    if tbl:
        print("section b carries a load table: it is copied, not run in place")
        for off, ln, dest in tbl:
            print("   payload 0x%06X  %-9d -> 0x%08X  %s"
                  % (off, ln, dest, 'ITCM' if dest < 0x1000000 else 'SDRAM'))
        print()
    print("%-4s %-12s %-10s %-10s %s" % ("id", "address", "length", "in file", "self-refs at that base"))
    for tag, addr, ln, off in layout(fw, body):
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
    """One file per run, named <out>.<address>.bin, because the runs are far
    apart in the address space and one flat file would be gigabytes of padding."""
    fw, body = load(path)
    root, ext = os.path.splitext(out)
    rows = layout(fw, body)
    for tag, addr, ln, off in rows:
        name = "%s.%08X%s" % (root, addr, ext or '.bin')
        open(name, 'wb').write(body[off:off + ln])
        print("%-4s 0x%08X  %-9d -> %s" % (tag, addr, ln, name))
    print()
    print("import each as ARM:LE:32:Cortex at its own base and disassemble Thumb")


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
