#!/usr/bin/env python3
"""ht_sysex.py - the GP-150's editor protocol, read off the wire.

Not the updater's format (that one is `ht_packet.py`, taken from the vendor
library). This is what Suite and the pedal actually say to each other while you
browse and edit, captured with `tools/spy/` and decoded here.

A frame:

```
F0 7F <crc> [len16] [off16] [id_a] [id_b] <payload> F7
```

* `crc` is **CRC-8, polynomial 0x31, init 0x00, masked to seven bits** - it has
  to fit in a SysEx data byte. Confirmed on 876 of 876 captured frames, and the
  same table sits in the firmware at payload `0x0331A8`, which is what makes it
  the device's own and not a guess.
* `len16` and `off16` are 14-bit, sent as two seven-bit halves, low first. On a
  reply `len16` is the **total size of the object** and `off16` is where this
  chunk starts; on a request both are zero and the arguments live in the
  payload.
* `id_a`/`id_b` pair a reply to its request.
* the payload is **nibble-encoded** - two wire bytes per real byte, high nibble
  first - because SysEx cannot carry a byte above 0x7F. A full chunk is 119
  bytes, which is why offsets step by 119.

Inside the payload there is a second layer, the "data package" the Dart side
calls it: `01 <check> <len16 LE> 03 <type> <a a> <b b> <len16 LE> ...`, where
the two repeated 16-bit values look like the addresses of the thing being read
and the thing asking. That layer is not fully decoded here.

    ht_sysex.py frames  <capture.log>     every frame, decoded
    ht_sysex.py objects <capture.log>     reassemble what the device sent
    ht_sysex.py dump    <capture.log> <dir>   write those objects out
    ht_sysex.py build   <hex-payload> [--len N] [--off N] [--id A,B]

`build` makes a frame with a correct checksum, for a reply you want to replay or
a request you have worked out. It does not send anything: nothing in this file
opens a MIDI port.
"""

import collections
import os
import re
import sys

LINE = re.compile(r'^(\d\d:\d\d:\d\d\.\d+)\s+(out|in )\s+sysex\s+len=(\d+)\s+(.*)$')

_TBL = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = ((_c << 1) ^ 0x31) & 0xFF if _c & 0x80 else (_c << 1) & 0xFF
    _TBL.append(_c)


def crc(data):
    """CRC-8/0x31 over the body, in seven bits."""
    c = 0
    for b in data:
        c = _TBL[c ^ b]
    return c & 0x7F


def u14(lo, hi):
    return lo | (hi << 7)


def p14(v):
    return bytes([v & 0x7F, (v >> 7) & 0x7F])


def unnibble(p):
    return bytes(((p[i] << 4) | p[i + 1]) for i in range(0, len(p) - 1, 2))


def nibble(b):
    out = bytearray()
    for x in b:
        out.append((x >> 4) & 0x0F)
        out.append(x & 0x0F)
    return bytes(out)


class Frame(object):
    __slots__ = ('total', 'off', 'id_a', 'id_b', 'data', 'ok', 'raw')

    def __init__(self, total, off, id_a, id_b, data, ok=True, raw=b''):
        self.total, self.off = total, off
        self.id_a, self.id_b = id_a, id_b
        self.data = data
        self.ok = ok
        self.raw = raw

    def __repr__(self):
        return ('<Frame total=%d off=%d id=%02X.%02X %d bytes%s>'
                % (self.total, self.off, self.id_a, self.id_b, len(self.data),
                   '' if self.ok else ' BAD CRC'))


def decode(frame):
    if len(frame) < 5 or frame[0] != 0xF0 or frame[1] != 0x7F or frame[-1] != 0xF7:
        raise ValueError("not a GP-150 frame")
    body = frame[3:-1]
    ok = crc(body) == frame[2]
    if len(body) < 6:
        return Frame(0, 0, 0, 0, b'', ok, frame)
    return Frame(u14(body[0], body[1]), u14(body[2], body[3]),
                 body[4], body[5], unnibble(body[6:]), ok, frame)


def encode(payload=b'', total=0, off=0, id_a=0, id_b=0):
    body = p14(total) + p14(off) + bytes([id_a & 0x7F, id_b & 0x7F]) + nibble(payload)
    return b'\xF0\x7F' + bytes([crc(body)]) + body + b'\xF7'


def read_capture(path):
    """(time, direction, frame) for every SysEx in a spy capture."""
    out = []
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for line in fh:
            m = LINE.match(line.strip())
            if not m:
                continue
            t, d, _ln, rest = m.groups()
            if '...' in rest:
                continue                     # a truncated line cannot be decoded
            try:
                raw = bytes.fromhex(rest.strip())
            except ValueError:
                continue
            try:
                out.append((t, d.strip(), decode(raw)))
            except ValueError:
                pass
    return out


def objects(msgs):
    """Reassemble what came back, one transfer at a time.

    A transfer is a run of replies with the same `id_a` whose offsets climb;
    the same id is used again later for something else, so a chunk at offset 0
    starts a new transfer rather than overwriting the old one.
    """
    out = []
    open_ = {}
    for _t, d, f in msgs:
        if d != 'in' or not f.data or f.total == 0:
            continue
        cur = open_.get(f.id_a)
        if cur is None or f.off == 0 or f.total != cur['total'] or f.off < cur['end']:
            cur = {'id': f.id_a, 'total': f.total, 'buf': bytearray(f.total),
                   'seen': 0, 'end': 0}
            open_[f.id_a] = cur
            out.append(cur)
        n = min(len(f.data), f.total - f.off)
        if n > 0:
            cur['buf'][f.off:f.off + n] = f.data[:n]
            cur['seen'] += n
            cur['end'] = f.off + n
    return out


def cmd_frames(path):
    msgs = read_capture(path)
    print("%d frames" % len(msgs))
    bad = sum(1 for _t, _d, f in msgs if not f.ok)
    print("checksum: %d good, %d bad" % (len(msgs) - bad, bad))
    print()
    print("%-13s %-4s %-7s %-7s %-7s %s"
          % ("time", "dir", "total", "offset", "id", "payload"))
    for t, d, f in msgs[:60]:
        print("%-13s %-4s %-7d %-7d %02X.%02X   %s"
              % (t, d, f.total, f.off, f.id_a, f.id_b, f.data[:20].hex(' ')))
    if len(msgs) > 60:
        print("... %d more" % (len(msgs) - 60))


def cmd_objects(path):
    msgs = read_capture(path)
    objs = objects(msgs)
    whole = [o for o in objs if o['seen'] >= o['total']]
    print("%d transfers from %d frames, %d of them complete"
          % (len(objs), len(msgs), len(whole)))
    print()
    print("%-6s %-8s %-10s %s" % ("id", "size", "covered", "first bytes"))
    for o in objs[:40]:
        print("%-6d %-8d %-10s %s"
              % (o['id'], o['total'],
                 "%d%s" % (o['seen'], "" if o['seen'] >= o['total'] else " (gaps)"),
                 bytes(o['buf'])[:16].hex(' ')))
    if len(objs) > 40:
        print("... %d more" % (len(objs) - 40))
    sizes = collections.Counter(o['total'] for o in objs)
    print()
    print("sizes seen: " + ", ".join("%d x%d" % (s, n) for s, n in sizes.most_common()))
    print("1136 is a patch; the small ones are the objects Suite reads to draw a")
    print("list. Nothing here is addressed by memory address - the protocol asks")
    print("for objects by id, not for bytes at a location.")


def cmd_dump(path, outdir):
    msgs = read_capture(path)
    objs = objects(msgs)
    if not os.path.isdir(outdir):
        os.makedirs(outdir)
    for i, o in enumerate(objs):
        name = os.path.join(outdir, '%03d_id%02X_%d.bin' % (i, o['id'], o['total']))
        open(name, 'wb').write(bytes(o['buf']))
    print("wrote %d objects to %s" % (len(objs), outdir))


def cmd_build(hexstr, total=0, off=0, ids=(0, 0)):
    payload = bytes.fromhex(hexstr) if hexstr else b''
    f = encode(payload, total, off, ids[0], ids[1])
    print("%d bytes" % len(f))
    print(f.hex(' '))
    d = decode(f)
    print("round trip: total=%d off=%d id=%02X.%02X payload=%d crc %s"
          % (d.total, d.off, d.id_a, d.id_b, len(d.data),
             "ok" if d.ok else "WRONG"))


def main(argv):
    if len(argv) >= 2 and argv[0] == 'frames':
        return cmd_frames(argv[1])
    if len(argv) >= 2 and argv[0] == 'objects':
        return cmd_objects(argv[1])
    if len(argv) == 3 and argv[0] == 'dump':
        return cmd_dump(argv[1], argv[2])
    if len(argv) >= 2 and argv[0] == 'build':
        total = off = 0
        ids = (0, 0)
        rest = argv[1:]
        i = 0
        payload = ''
        while i < len(rest):
            if rest[i] == '--len':
                total = int(rest[i + 1], 0); i += 2
            elif rest[i] == '--off':
                off = int(rest[i + 1], 0); i += 2
            elif rest[i] == '--id':
                a, _, b = rest[i + 1].partition(',')
                ids = (int(a, 0), int(b or 0, 0)); i += 2
            else:
                payload = rest[i]; i += 1
        return cmd_build(payload, total, off, ids)
    print(__doc__.strip())
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
