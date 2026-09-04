#!/usr/bin/env python3
# gp150.py - inspect, validate and flash Valeton HTFW firmware, with logs.
#
# The device side of Valeton Suite lives in assets/5868USB.dll, and its exports
# are plain C: scanInDevice, scanOutDevice, connectDevice, deviceStartUpdate,
# sendMidiMessage, checkCrc, isRealFirmware. Updates go over MIDI. Rather than
# guess the SysEx protocol, this drives the vendor's own library, so a firmware
# is validated by exactly the code that validates it in Suite.
#
# The library also writes a log of its own to %TEMP%\HTCache\logfile.txt, which
# is where the update's progress messages appear; `log` reads it, and drops the
# scanInDevice polling that otherwise accounts for over 99% of the lines.
#
#   gp150.py info    <fw.bin>          header, regions, both checksum levels
#   gp150.py check   <fw.bin>          our verification plus the vendor's
#   gp150.py seal    <fw.bin> [-o out] recompute the whole-file CRC
#   gp150.py devices                   MIDI ports the library can see
#   gp150.py probe                     dump what the library reports, verbatim
#   gp150.py log [--follow] [--all]    the library's own log
#   gp150.py flash   <fw.bin> --yes    update the device

import argparse
import ctypes
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import htfw_tool as H

SUITE = os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'),
                     'Valeton Suite', 'Valeton Suite')
USBDLL = os.path.join(SUITE, 'assets', '5868USB.dll')
LOGFILE = os.path.join(os.environ.get('TEMP', r'C:\Windows\Temp'),
                       'HTCache', 'logfile.txt')

_dll = None


def dll():
    """Load the vendor library. Its dependencies sit beside it, so both the
    install root and assets/ have to be on the DLL search path."""
    global _dll
    if _dll is None:
        if not os.path.isfile(USBDLL):
            raise SystemExit("not found: %s\nInstall Valeton Suite." % USBDLL)
        os.add_dll_directory(SUITE)
        os.add_dll_directory(os.path.join(SUITE, 'assets'))
        _dll = ctypes.CDLL(USBDLL)
    return _dll


# --------------------------------------------------------------------------
# file side
# --------------------------------------------------------------------------

def whole_file_crc(blob):
    """The header holds a CRC of everything from offset 6, big-endian at 0x04.
    Returns (stored, computed)."""
    return (blob[4] << 8) | blob[5], H.crc16_modbus(blob[6:])


def vendor_check(path):
    """checkCrc() and getVersionStringForFilePath() from the vendor library.
    0 means the file passes; -1 a checksum mismatch; -2 a truncated file."""
    d = dll()
    f = d.checkCrc
    f.restype, f.argtypes = ctypes.c_int, [ctypes.c_char_p]
    g = d.getVersionStringForFilePath
    g.restype, g.argtypes = ctypes.c_char_p, [ctypes.c_char_p]
    p = path.encode('mbcs')
    v = g(p)
    return f(p), (v.decode('latin1') if v else None)


def cmd_info(a):
    blob = open(a.firmware, 'rb').read()
    fw = H.Firmware(blob)
    stored, calc = whole_file_crc(blob)
    print("file        : %s" % a.firmware)
    print("model       : %s" % fw.model)
    print("version     : V%d.%d.%d" % fw.ver)
    print("size        : %d (header says %d) %s"
          % (len(blob), fw.size, "OK" if len(blob) == fw.size else "MISMATCH"))
    print("file CRC    : stored 0x%04X  computed 0x%04X  %s"
          % (stored, calc, "OK" if stored == calc else "STALE - run `seal`"))
    print("format      : %d" % struct.unpack_from('<H', blob, 6)[0])
    print("packed      : %s" % ("LZO1X, %d -> %d" % (len(blob) - fw.pack_off - 4,
                                                     fw.raw_len)
                                if fw.packed else "no"))
    print("regions     :")
    for s in fw.sections:
        print("   %s  crc=0x%04X  flash=0x%08X  off=0x%08X  len=%d"
              % (s.tag, s.crc, s.flash, s.off, s.len))


def cmd_check(a):
    blob = open(a.firmware, 'rb').read()
    fw = H.Firmware(blob)
    bad = 0
    print("region checksums:")
    for tag, calc, stored, ok in fw.verify() or []:
        print("   %s  calc=0x%04X stored=0x%04X  %s"
              % (tag, calc, stored, "OK" if ok else "FAIL"))
        bad += 0 if ok else 1
    stored, calc = whole_file_crc(blob)
    fok = stored == calc
    print("whole-file checksum: stored 0x%04X computed 0x%04X  %s"
          % (stored, calc, "OK" if fok else "FAIL"))
    try:
        rc, ver = vendor_check(a.firmware)
        meaning = {0: "accepted", -1: "checksum mismatch",
                   -2: "file truncated or size field wrong"}.get(rc, "code %d" % rc)
        print("vendor checkCrc()  : %d  (%s)" % (rc, meaning))
        print("vendor version     : %s" % ver)
    except Exception as e:                        # noqa: BLE001
        rc = None
        print("vendor check unavailable: %s" % e)
    good = not bad and fok and (rc in (0, None))
    print("\nresult: %s" % ("PASSES" if good else "REJECTED"))
    return 0 if good else 1


def cmd_seal(a):
    blob = bytearray(open(a.firmware, 'rb').read())
    struct.pack_into('<I', blob, 8, len(blob))
    out = bytearray(H.seal(bytes(blob)))
    dst = a.out or a.firmware
    open(dst, 'wb').write(bytes(out))
    stored, calc = whole_file_crc(bytes(out))
    print("written %s  file CRC 0x%04X %s" % (dst, stored,
                                              "OK" if stored == calc else "??"))
    try:
        rc, _ = vendor_check(dst)
        print("vendor checkCrc(): %d" % rc)
    except Exception:                             # noqa: BLE001
        pass


# --------------------------------------------------------------------------
# device side
# --------------------------------------------------------------------------

SCAN_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int)


def scan(which, filt=b""):
    """scanInDevice / scanOutDevice both take (const char *filter, callback),
    and hand the callback a buffer and a length."""
    d = dll()
    f = getattr(d, which)
    f.restype, f.argtypes = None, [ctypes.c_char_p, SCAN_CB]
    seen = []

    def cb(ptr, n):
        seen.append(ctypes.string_at(ptr, n) if (ptr and n > 0) else b"")
    held = SCAN_CB(cb)                 # keep a reference for the call's lifetime
    f(filt, held)
    return seen


def _names(chunks):
    out = []
    for c in chunks:
        for part in c.split(b'\0'):
            t = part.decode('latin1', 'replace').strip()
            if t:
                out.append(t)
    return out


def cmd_devices(a):
    for which, label in (("scanInDevice", "MIDI in "),
                         ("scanOutDevice", "MIDI out")):
        try:
            names = _names(scan(which, a.filter.encode('latin1')))
        except Exception as e:                    # noqa: BLE001
            print("%s: error %s" % (label, e))
            continue
        if names:
            for i, n in enumerate(names):
                print("%s [%d] %s" % (label, i, n))
        else:
            print("%s (none reported)" % label)
    print("\nNothing listed usually means the GP-150 is not plugged in, or is "
          "held open by Valeton Suite - close Suite and try again.")


def cmd_probe(a):
    """Raw dump of what the library reports, for filling in the last unknowns
    of connectDevice() once a device is actually attached."""
    for which in ("scanInDevice", "scanOutDevice"):
        chunks = scan(which, a.filter.encode('latin1'))
        print("%s -> %d callback(s)" % (which, len(chunks)))
        for c in chunks:
            print("   %d bytes: %r" % (len(c), c[:512]))
    # checkDeviceConnecting() takes a device object, not a name - handing it a
    # string faults inside the library, so it is not probed here. The handle it
    # wants comes from connectDevice(), which needs hardware present.


# --------------------------------------------------------------------------
# the library's own log
# --------------------------------------------------------------------------

NOISE = ("scanInDevice-----", "scanOutDevice-----", "reciveMidiData-----")


def _interesting(block, keep_all):
    if keep_all:
        return True
    return not any(n in block for n in NOISE)


def _blocks(text):
    """The log is stanzas separated by blank lines, each a timestamp line then
    the message."""
    cur = []
    for line in text.splitlines():
        if line.strip():
            cur.append(line)
        elif cur:
            yield "\n".join(cur)
            cur = []
    if cur:
        yield "\n".join(cur)


def cmd_log(a):
    if not os.path.isfile(LOGFILE):
        raise SystemExit("no log at %s - run Valeton Suite or `flash` once"
                         % LOGFILE)
    size = os.path.getsize(LOGFILE)
    print("# %s  (%.1f MB)" % (LOGFILE, size / 1048576.0))
    with open(LOGFILE, 'r', encoding='latin1') as fh:
        if a.follow:
            fh.seek(0, os.SEEK_END)
        else:
            back = min(size, a.tail * 400)
            fh.seek(size - back)
            fh.readline()
        text = fh.read()
        shown = [b for b in _blocks(text) if _interesting(b, a.all)]
        for b in shown[-a.tail:]:
            print(b + "\n")
        if not shown:
            print("# nothing to show. The library truncates this file when it "
                  "starts, and\n# over 99% of what it writes is scanInDevice "
                  "polling, which is hidden\n# unless you pass --all.")
        if not a.follow:
            return
        print("# following, ctrl-c to stop")
        buf = ""
        while True:
            chunk = fh.read()
            if not chunk:
                time.sleep(0.3)
                continue
            buf += chunk
            while "\n\n" in buf:
                blk, buf = buf.split("\n\n", 1)
                blk = blk.strip("\n")
                if blk and _interesting(blk, a.all):
                    print(blk + "\n")


# --------------------------------------------------------------------------
# flashing
# --------------------------------------------------------------------------

def cmd_flash(a):
    blob = open(a.firmware, 'rb').read()
    H.Firmware(blob)                              # parses or raises
    stored, calc = whole_file_crc(blob)
    if stored != calc:
        raise SystemExit("refusing: whole-file CRC is stale (stored 0x%04X, "
                         "computed 0x%04X). Run `seal` first." % (stored, calc))
    rc, ver = vendor_check(a.firmware)
    print("vendor checkCrc(): %d   version: %s" % (rc, ver))
    if rc != 0:
        raise SystemExit("refusing: the vendor library rejects this file.")

    ins = _names(scan("scanInDevice"))
    outs = _names(scan("scanOutDevice"))
    print("MIDI in : %s" % (ins or "(none)"))
    print("MIDI out: %s" % (outs or "(none)"))
    if not ins or not outs:
        raise SystemExit("no device reported - plug the GP-150 in and close "
                         "Valeton Suite, then run `gp150.py devices` to check.")
    if not a.yes:
        raise SystemExit("would flash %s; pass --yes to actually write."
                         % a.firmware)

    d = dll()
    connect = d.connectDevice
    connect.restype = ctypes.c_void_p
    connect.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p,
                        ctypes.c_void_p]
    handle = connect(a.inport, a.outport, a.firmware.encode('mbcs'), None)
    print("connectDevice -> handle %s" % (hex(handle) if handle else "NULL"))
    if not handle:
        raise SystemExit("connectDevice failed")

    upd = d.deviceStartUpdate
    upd.restype, upd.argtypes = ctypes.c_int, [ctypes.c_void_p]
    print("deviceStartUpdate ...")
    r = upd(handle)
    print("deviceStartUpdate -> %d" % r)
    print("watch progress with:  gp150.py log --follow")
    dis = d.disConnectDevice
    dis.restype, dis.argtypes = None, [ctypes.c_void_p]
    dis(handle)
    return 0 if r == 0 else 1


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('info'); p.add_argument('firmware'); p.set_defaults(fn=cmd_info)
    p = sub.add_parser('check'); p.add_argument('firmware'); p.set_defaults(fn=cmd_check)
    p = sub.add_parser('seal'); p.add_argument('firmware')
    p.add_argument('-o', '--out'); p.set_defaults(fn=cmd_seal)
    p = sub.add_parser('devices'); p.add_argument('--filter', default='')
    p.set_defaults(fn=cmd_devices)
    p = sub.add_parser('probe'); p.add_argument('--filter', default='')
    p.set_defaults(fn=cmd_probe)
    p = sub.add_parser('log')
    p.add_argument('--follow', action='store_true')
    p.add_argument('--all', action='store_true',
                   help="keep the scanInDevice polling too")
    p.add_argument('--tail', type=int, default=40)
    p.set_defaults(fn=cmd_log)
    p = sub.add_parser('flash'); p.add_argument('firmware')
    p.add_argument('--inport', type=int, default=0)
    p.add_argument('--outport', type=int, default=0)
    p.add_argument('--yes', action='store_true')
    p.set_defaults(fn=cmd_flash)

    a = ap.parse_args()
    sys.exit(a.fn(a) or 0)


if __name__ == '__main__':
    main()
