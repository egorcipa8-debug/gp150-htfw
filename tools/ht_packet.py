#!/usr/bin/env python3
"""ht_packet.py - the wire format Valeton Suite speaks to the pedal.

Every host-to-device message is one SysEx frame around a small buffer:

    BUF = [ crc8 ][ command ][ index ][ length ][ length payload bytes ]
    wire = F0, then for each byte of BUF: (b >> 4), (b & 0x0F), then F7

`crc8` is **CRC-8, polynomial 0x07, init 0x00, no reflection, no final xor**,
computed over the whole of BUF with its own slot held at zero. The nibble split
is what keeps every byte under 0x80, which is what SysEx requires.

Read out of `5868USB.dll` rather than guessed. The builder is one function:

```c
buf[0] = 0; buf[1] = command; buf[2] = index; buf[3] = length;
append(buf, payload, length);
crc = 0; for (b : buf) crc = TBL[crc ^ b];      /* TBL at 0x180195910 */
buf[0] = crc;
if (nibble) for (b : buf) { emit(b >> 4); emit(b & 0xF); }
frame = 0xF0 ++ body ++ 0xF7;
```

and `verify` checks that the table this file generates is byte-for-byte the one
in the DLL, so the checksum is not taken on faith.

### The firmware update

`deviceStartUpdate` parses the container, decompresses an LZO payload if the
header says it is packed, then walks the section table. For each section it
checks the stored CRC-16/MODBUS itself - the same big-endian comparison the
bootloader makes - and builds one message whose payload is

    0x11, section id, then the whole section

split into blocks of **42 bytes** (`0x2A`), or 19 (`0x13`) when the device is put
in the compressed mode `setDeviceCompress` selects. So a section of length L
becomes `ceil(L / 42)` frames, and the block count the library reports is exactly
that.

`plan` prints that whole schedule for a firmware file, and the first frame of
each section, without opening a MIDI port. It also shows the one thing the code
does not settle: the index is a single byte and a section runs to six figures of
blocks, so the counter must wrap somewhere - here it simply wraps at 256, which
is a guess until someone captures a real update. Nothing here talks to a device: this
module builds bytes and stops. The GP-50 project's warning is worth repeating -
sending guessed traffic wedged a pedal once - and while every field below is read
out of the vendor's code rather than invented, none of it has been checked
against a capture here.

    ht_packet.py verify                     table against the DLL's own
    ht_packet.py frame <cmd> <index> <hex>  build one frame
    ht_packet.py parse <hex>                take one apart
    ht_packet.py plan <fw.bin>              what an update would send
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SUITE = os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'),
                     'Valeton Suite', 'Valeton Suite')
USBDLL = os.path.join(SUITE, 'assets', '5868USB.dll')

BLOCK = 42                 # 0x2A payload bytes per frame
BLOCK_COMPRESSED = 19      # 0x13, when setDeviceCompress is on
CMD_FIRMWARE_BLOCK = 0x11  # first payload byte of an update message

_TBL = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = ((_c << 1) ^ 0x07) & 0xFF if _c & 0x80 else (_c << 1) & 0xFF
    _TBL.append(_c)


def crc8(data):
    c = 0
    for b in data:
        c = _TBL[c ^ b]
    return c


def encode(cmd, index, payload=b'', nibble=True):
    """One frame, ready to put on the wire."""
    if not 0 <= cmd <= 0xFF or not 0 <= index <= 0xFF:
        raise ValueError("command and index are one byte each")
    if len(payload) > 0xFF:
        raise ValueError("payload is longer than the length byte can say")
    buf = bytearray([0, cmd & 0xFF, index & 0xFF, len(payload)])
    buf += bytes(payload)
    buf[0] = crc8(buf)
    if not nibble:
        return b'\xF0' + bytes(buf) + b'\xF7'
    body = bytearray()
    for b in buf:
        body.append(b >> 4)
        body.append(b & 0x0F)
    return b'\xF0' + bytes(body) + b'\xF7'


def decode(frame):
    """(command, index, payload, checksum_ok). Accepts either encoding."""
    if len(frame) < 3 or frame[0] != 0xF0 or frame[-1] != 0xF7:
        raise ValueError("not a SysEx frame")
    body = frame[1:-1]
    if body and max(body) < 0x10:
        if len(body) % 2:
            raise ValueError("odd number of nibbles")
        buf = bytearray((body[i] << 4) | body[i + 1]
                        for i in range(0, len(body), 2))
    else:
        buf = bytearray(body)
    if len(buf) < 4:
        raise ValueError("frame is shorter than a header")
    stored = buf[0]
    buf[0] = 0
    ok = crc8(buf) == stored
    return buf[1], buf[2], bytes(buf[4:4 + buf[3]]), ok


def blocks(data, size=BLOCK):
    for i in range(0, len(data), size):
        yield data[i:i + size]


def dll_table():
    """The CRC-8 table out of Valeton Suite's own library, if it is installed."""
    if not os.path.isfile(USBDLL):
        return None
    blob = open(USBDLL, 'rb').read()
    want = bytes(_TBL)
    at = blob.find(want)
    return None if at < 0 else (at, blob[at:at + 256])


# --------------------------------------------------------------------------

def cmd_verify():
    hit = dll_table()
    if hit is None:
        print("Valeton Suite is not installed here, or its table has moved -")
        print("nothing to compare against. The table this file builds is the")
        print("standard CRC-8/0x07 one; %d entries." % len(_TBL))
        return 1
    at, tbl = hit
    same = tbl == bytes(_TBL)
    print("%s: CRC-8/0x07 table at file offset 0x%X" % (os.path.basename(USBDLL), at))
    print("256 of 256 entries match" if same else "TABLE DIFFERS")
    print("\nframe of an empty command 1, index 0:")
    print("  " + encode(1, 0).hex(' '))
    return 0 if same else 1


def cmd_frame(cmd, index, payload_hex):
    payload = bytes.fromhex(payload_hex) if payload_hex else b''
    f = encode(cmd, index, payload)
    print("command 0x%02X  index %d  %d payload bytes" % (cmd, index, len(payload)))
    print("  frame  %d bytes" % len(f))
    print("  " + f.hex(' '))
    c, i, p, ok = decode(f)
    print("  round trip: command 0x%02X index %d payload %d bytes, checksum %s"
          % (c, i, len(p), "ok" if ok else "WRONG"))


def cmd_parse(frame_hex):
    frame = bytes.fromhex(frame_hex.replace(',', ' '))
    cmd, index, payload, ok = decode(frame)
    print("command   0x%02X" % cmd)
    print("index     %d" % index)
    print("payload   %d bytes" % len(payload))
    if payload:
        print("          " + payload.hex(' '))
    print("checksum  %s" % ("ok" if ok else "does not match"))


def cmd_plan(path, compressed=False):
    import htfw_tool
    fw = htfw_tool.Firmware(open(path, 'rb').read())
    if fw.body is None:
        raise SystemExit("payload is packed and could not be unpacked")
    body = bytes(fw.body)
    size = BLOCK_COMPRESSED if compressed else BLOCK
    print("%s - %s %s%s" % (os.path.basename(path), fw.model,
                            'V%d.%d.%d' % fw.ver,
                            ', LZO packed' if fw.packed else ''))
    print("blocks of %d bytes\n" % size)
    print("%-3s %-10s %-10s %-9s %s" % ("id", "flash", "length", "frames", "section CRC"))
    total = 0
    index = 0
    firsts = []
    for s in fw.sections:
        data = body[s.off:s.off + s.len]
        calc = htfw_tool.crc16_modbus(data)
        payload = bytes([CMD_FIRMWARE_BLOCK, ord(s.tag)]) + data
        n = (len(payload) + size - 1) // size
        print("%-3s 0x%08X %-10d %-9d 0x%04X %s"
              % (s.tag, s.flash, s.len, n, s.crc,
                 "ok" if calc == s.crc else "MISMATCH 0x%04X" % calc))
        firsts.append((s.tag, encode(1, index & 0xFF,
                                     payload[:size])))
        total += n
        index += n
    print("\n%d frames in all, %.1f MB on the wire (each byte goes as two nibbles)"
          % (total, total * (size + 4) * 2 / 1e6))
    print("\nfirst frame of each section, %d bytes each:" % ((size + 4) * 2 + 2))
    for tag, f in firsts:
        print("  %s  %s..." % (tag, f[:24].hex(' ')))
    print("\nNothing was sent. This is what the library would build, read out of\n"
          "its own code; it has not been checked against a capture here.")


def main(argv):
    if not argv:
        print(__doc__.strip())
        return 1
    cmd = argv[0]
    if cmd == 'verify':
        return cmd_verify()
    if cmd == 'frame' and len(argv) >= 3:
        return cmd_frame(int(argv[1], 0), int(argv[2], 0),
                         argv[3] if len(argv) > 3 else '')
    if cmd == 'parse' and len(argv) == 2:
        return cmd_parse(argv[1])
    if cmd == 'plan' and len(argv) >= 2:
        return cmd_plan(argv[1], '--compressed' in argv)
    print(__doc__.strip())
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
