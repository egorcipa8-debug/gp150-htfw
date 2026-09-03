#!/usr/bin/env python3
# htfw_tool.py - unpack / repack Valeton HTFW firmware images (GP-150 family).
#
# Container format, reverse engineered from GP-150 V1.0.5 and V1.1.1:
#
#   0x00  char[4]   "HTFW"
#   0x04  uint32    build id (high 16 bits = 0x0001); not derived from content
#   0x08  uint32    total file size
#   0x0C  char[16]  model name, NUL padded ("GP-150")
#   0x1C  'V', major, minor, patch
#   0x20  uint32    unknown
#   0x24  uint32    size of the image = sum of all section lengths
#   0x38  section table, 16-byte records, terminated by FF FF FF FF:
#           [0:2]   CRC-16/MODBUS of the section data, stored BIG-ENDIAN
#           [2]     0x00
#           [3]     section tag, ASCII 'b'..'h'
#           [4:8]   destination address in flash
#           [8:12]  offset of the section inside the image
#           [12:16] section length
#   payload starts at  filesize - header[0x24]
#
# CRC verified on all 7 sections of both V1.0.5 and V1.1.1.
#
# V1.0.5 stores the payload raw. V1.1.1 stores it PACKED: immediately after the
# TOC comes a u32 little-endian uncompressed length, then an LZO1X stream. This
# is the same miniLZO that Valeton Suite ships as minilzo_plugin.dll.
# Decompression here is pure Python (lzo1x.py); repacking a packed image borrows
# the DLL's startCompress through lzodll.py.
#
# Usage:
#   htfw_tool.py info    <fw.bin>
#   htfw_tool.py verify  <fw.bin>
#   htfw_tool.py unpack  <fw.bin> <outdir>
#   htfw_tool.py repack  <orig.bin> <indir> <new.bin>

import sys
import os
import struct

# LZO1X support: packed images (V1.1.1 and later) store the payload as
#   [u32 uncompressed_length][LZO1X stream]
# right after the TOC. Decompression is pure Python; compression borrows
# Valeton Suite's own minilzo_plugin.dll when it is installed.
try:
    from lzo1x import lzo1x_decompress
except ImportError:
    lzo1x_decompress = None
try:
    import lzodll
except Exception:
    lzodll = None

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
    # poly 0x8005, init 0xFFFF, refin/refout true, xorout 0x0000
    c = 0xFFFF
    for x in data:
        c = ((c << 8) & 0xFFFF) ^ _TAB[((c >> 8) ^ _REF8[x]) & 0xFF]
    return _refl16(c)


class Section(object):
    __slots__ = ('tag', 'crc', 'flash', 'off', 'len', 'rec')

    def __repr__(self):
        return "<%s crc=0x%04X flash=0x%08X off=0x%08X len=0x%08X>" % (
            self.tag, self.crc, self.flash, self.off, self.len)


class Firmware(object):
    def __init__(self, blob):
        if blob[0:4] != b'HTFW':
            raise ValueError("not an HTFW image (magic = %r)" % blob[0:4])
        self.blob = blob
        self.build = struct.unpack_from('<I', blob, 4)[0]
        self.size = struct.unpack_from('<I', blob, 8)[0]
        self.model = blob[12:28].split(b'\0')[0].decode('ascii', 'replace')
        self.ver = (blob[0x1d], blob[0x1e], blob[0x1f])
        self.unk20 = struct.unpack_from('<I', blob, 0x20)[0]
        self.image_size = struct.unpack_from('<I', blob, 0x24)[0]
        self.sections = []
        off = 0x38
        while True:
            rec = blob[off:off + 16]
            if len(rec) < 16 or rec[0:4] == b'\xff\xff\xff\xff':
                break
            if not (0x61 <= rec[3] <= 0x7a):
                break
            s = Section()
            s.tag = chr(rec[3])
            s.crc = (rec[0] << 8) | rec[1]
            s.flash, s.off, s.len = struct.unpack_from('<III', rec, 4)
            s.rec = off
            self.sections.append(s)
            off += 16
        self.table_end = off
        self.payload = len(blob) - self.image_size
        self.packed = self.payload < self.table_end
        self.body = None
        if self.packed:
            self.pack_off = self.table_end
            self.raw_len = struct.unpack_from('<I', blob, self.pack_off)[0]
            if lzo1x_decompress is not None:
                try:
                    self.body = lzo1x_decompress(blob[self.pack_off + 4:])
                except Exception:
                    self.body = None
        else:
            self.body = blob[self.payload:]

    def data(self, s):
        if self.body is None:
            return b''
        return self.body[s.off:s.off + s.len]

    def describe(self):
        L = []
        L.append("model        : %s" % self.model)
        L.append("version      : V%d.%d.%d" % self.ver)
        L.append("build id     : 0x%08X" % self.build)
        L.append("file size    : %d (header says %d)" % (len(self.blob), self.size))
        L.append("image size   : %d (0x%X)" % (self.image_size, self.image_size))
        L.append("payload at   : 0x%X" % self.payload)
        if self.packed:
            L.append("packed       : YES - LZO1X, %d -> %d bytes%s"
                     % (len(self.blob) - self.pack_off - 4, self.raw_len,
                        "" if self.body is not None else "  (decompressor unavailable)"))
        else:
            L.append("packed       : no, raw")
        L.append("sections     : %d" % len(self.sections))
        run = 0
        for s in self.sections:
            gap = "" if s.off == run else "   <-- NOT CONTIGUOUS"
            L.append("   %s  crc=0x%04X  flash=0x%08X  off=0x%08X  len=0x%08X (%d KB)%s"
                     % (s.tag, s.crc, s.flash, s.off, s.len, s.len // 1024, gap))
            run = s.off + s.len
        L.append("sum of lens  : 0x%X  header 0x24 = 0x%X  %s"
                 % (run, self.image_size, "OK" if run == self.image_size else "MISMATCH"))
        return "\n".join(L)

    def verify(self):
        if self.body is None:
            return None
        out = []
        for s in self.sections:
            calc = crc16_modbus(self.data(s))
            out.append((s.tag, calc, s.crc, calc == s.crc))
        return out


def cmd_info(p):
    print(Firmware(open(p, 'rb').read()).describe())
    return 0


def cmd_verify(p):
    fw = Firmware(open(p, 'rb').read())
    res = fw.verify()
    if res is None:
        print("payload is packed and could not be unpacked (lzo1x.py missing?)")
        return 2
    bad = 0
    for tag, calc, stored, ok in res:
        print("  section %s: calc=0x%04X stored=0x%04X  %s" % (tag, calc, stored, "OK" if ok else "FAIL"))
        bad += 0 if ok else 1
    print("result: %s" % ("all sections OK" if not bad else "%d section(s) FAILED" % bad))
    return 0 if not bad else 1


def cmd_unpack(p, outdir):
    fw = Firmware(open(p, 'rb').read())
    if fw.body is None:
        print("refusing: payload is packed and could not be unpacked")
        return 2
    if not os.path.isdir(outdir):
        os.makedirs(outdir)
    hdr_len = fw.pack_off if fw.packed else fw.payload
    open(os.path.join(outdir, 'header.bin'), 'wb').write(fw.blob[:hdr_len])
    for s in fw.sections:
        fn = os.path.join(outdir, "section_%s.bin" % s.tag)
        open(fn, 'wb').write(fw.data(s))
        print("  %s -> %s  (%d bytes, flash 0x%08X)" % (s.tag, fn, s.len, s.flash))
    print("header -> %s (%d bytes)%s" % (os.path.join(outdir, 'header.bin'), hdr_len,
                                         "  [packed image]" if fw.packed else ""))
    return 0


def cmd_repack(orig, indir, outp):
    fw = Firmware(open(orig, 'rb').read())
    if fw.packed and lzodll is None:
        print("refusing: original is packed and minilzo_plugin.dll is unavailable")
        return 2
    hdr = bytearray(fw.blob[:fw.pack_off if fw.packed else fw.payload])
    body = bytearray()
    off = 0
    for s in fw.sections:
        dat = open(os.path.join(indir, "section_%s.bin" % s.tag), 'rb').read()
        if len(dat) != s.len:
            print("  WARNING section %s length changed: %d -> %d" % (s.tag, s.len, len(dat)))
        crc = crc16_modbus(dat)
        struct.pack_into('>H', hdr, s.rec, crc)
        struct.pack_into('<III', hdr, s.rec + 4, s.flash, off, len(dat))
        print("  section %s: len=%d  crc 0x%04X -> 0x%04X %s"
              % (s.tag, len(dat), s.crc, crc, "(CHANGED)" if crc != s.crc else ""))
        body += dat
        off += len(dat)
    struct.pack_into('<I', hdr, 0x24, len(body))
    if fw.packed:
        comp = lzodll.compress(bytes(body))
        tail = struct.pack('<I', len(body)) + comp
        print("  LZO1X repack: %d -> %d bytes" % (len(body), len(comp)))
    else:
        tail = bytes(body)
    struct.pack_into('<I', hdr, 8, len(hdr) + len(tail))
    open(outp, 'wb').write(bytes(hdr) + tail)
    print("written %s (%d bytes)" % (outp, len(hdr) + len(tail)))
    print("NOTE: header field 0x04 (build id) left unchanged - purpose unknown.")
    return 0


if __name__ == '__main__':
    a = sys.argv[1:]
    if not a:
        print(__doc__ or "see comments at top of file")
        sys.exit(1)
    c = a[0]
    if c == 'info' and len(a) == 2:
        sys.exit(cmd_info(a[1]))
    elif c == 'verify' and len(a) == 2:
        sys.exit(cmd_verify(a[1]))
    elif c == 'unpack' and len(a) == 3:
        sys.exit(cmd_unpack(a[1], a[2]))
    elif c == 'repack' and len(a) == 4:
        sys.exit(cmd_repack(a[1], a[2], a[3]))
    else:
        print("see usage in the header comment of this file")
        sys.exit(1)
