#!/usr/bin/env python3
"""ht_sysex.py - the GP-150's editor protocol, read off the wire.

Not the updater's format (that one is `ht_packet.py`, taken from the vendor
library). This is what Suite and the pedal say to each other while you browse
and edit, captured with `tools/spy/` and decoded here.

There are two layers.

## The envelope

```
F0 7F <crc> [len16] [off16] [seq] [chunk] <payload> F7
```

* `crc` is **CRC-8, polynomial 0x31, init 0x00, masked to seven bits** so it
  fits in a SysEx data byte, over everything between it and `F7`. Confirmed on
  876 of 876 captured frames; the same table sits in the firmware at payload
  `0x0331A8`, which is what makes it the device's own and not a guess.
* `len16`/`off16` are 14-bit, two seven-bit halves, low first. On a reply
  `len16` is the total size of the object and `off16` is where this chunk
  starts. On a request both are zero.
* `seq` numbers the transfer, `chunk` numbers the chunk inside it (from 1).
  A resend request quotes the pair of the chunk it wants again.
* the payload is **nibble-encoded** - two wire bytes per real byte, high nibble
  first - for everything except resend requests, whose arguments are plain
  seven-bit values. A full chunk is 119 bytes, which is why offsets step by 119.

## The data package

Every nibble payload, request and reply alike, is one package:

```
01 <crc> <len16 LE> | <cmd> <type> <dst16> <src16> <size16> <data[size]>
```

`crc` here is the same CRC-8/0x31 but over the eight *whole* bits, computed
over the package body (from `cmd` onward). `len16` counts that body. `cmd` is
`0x03` to read (and on every reply) and `0x00` to write. `dst`/`src` are the
object being addressed - equal on a read, different on a write - and the
catalog below is what the capture showed them to be.

    ht_sysex.py frames  <capture.log>          every frame, decoded
    ht_sysex.py objects <capture.log>          the conversation, one line each
    ht_sysex.py dump    <capture.log> <dir>    write the objects out
    ht_sysex.py read    <object>               build a read request
    ht_sysex.py build   <hex-payload> [--len N] [--off N] [--seq A,B]

`read` and `build` make frames with correct checksums, at both layers. They do
not send anything: nothing in this file opens a MIDI port.
"""

import collections
import os
import re
import sys

LINE = re.compile(r'^(\d\d:\d\d:\d\d\.\d+)\s+(out|in )\s+sysex\s+len=(\d+)\s+(.*)$')

# What the capture asked for, and what came back. Names are from the content.
OBJECTS = {
    0x1010: 'patch name list (4012 bytes, the browser list)',
    0x1042: 'User IR name list (412)',
    0x1052: 'cab/IR model names (2032)',
    0x1070: 'session handshake (16)',
    0x1080: 'device state blob (144)',
    0x1092: 'amp model names (2032)',
    0x2000: 'device info, firmware version string (408)',
    0x2050: 'input level meter (36, pushed)',
    0x2060: 'tuner / level (20, pushed)',
    0x3011: 'the current patch (1136)',
    0x3020: 'current patch header and name (92)',
    0x3031: 'live state (16, pushed on edit)',
    0x3032: 'live state (20, pushed on edit)',
    0x3033: 'live state (24, pushed on edit)',
    0x3070: 'live state (16, pushed)',
    0x3080: 'live state (48, pushed)',
}

# The reads Suite issues, exactly as captured, so they can be replayed verbatim.
READS = {
    0x1010: (0x03, 0x01, b''),
    0x1042: (0x03, 0x01, b''),
    0x1052: (0x03, 0x01, b''),
    0x1070: (0x03, 0x01, b''),
    0x1080: (0x03, 0x01, b''),
    0x1092: (0x03, 0x01, b''),
    0x2000: (0x03, 0x02, b''),
    0x3011: (0x03, 0x03, b'\xff\xff\x01'),
}

_TBL = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = ((_c << 1) ^ 0x31) & 0xFF if _c & 0x80 else (_c << 1) & 0xFF
    _TBL.append(_c)


def crc8(data):
    """CRC-8/0x31, init 0, all eight bits - the data package's checksum."""
    c = 0
    for b in data:
        c = _TBL[c ^ b]
    return c


def crc(data):
    """The same, in seven bits - the envelope's checksum."""
    return crc8(data) & 0x7F


def u14(lo, hi):
    return lo | (hi << 7)


def p14(v):
    return bytes([v & 0x7F, (v >> 7) & 0x7F])


def u16(b, i):
    return b[i] | (b[i + 1] << 8)


def p16(v):
    return bytes([v & 0xFF, (v >> 8) & 0xFF])


def unnibble(p):
    return bytes(((p[i] << 4) | p[i + 1]) for i in range(0, len(p) - 1, 2))


def nibble(b):
    out = bytearray()
    for x in b:
        out.append((x >> 4) & 0x0F)
        out.append(x & 0x0F)
    return bytes(out)


class Frame(object):
    """One SysEx message."""

    __slots__ = ('total', 'off', 'seq', 'chunk', 'data', 'nibbled', 'ok', 'raw')

    def __init__(self, total, off, seq, chunk, data, nibbled, ok, raw):
        self.total, self.off = total, off
        self.seq, self.chunk = seq, chunk
        self.data = data
        self.nibbled = nibbled
        self.ok = ok
        self.raw = raw

    def __repr__(self):
        return ('<Frame total=%d off=%d seq=%02X.%02X %d bytes%s%s>'
                % (self.total, self.off, self.seq, self.chunk, len(self.data),
                   '' if self.nibbled else ' raw', '' if self.ok else ' BAD CRC'))


class Package(object):
    """The thing inside the payload: a read, a write, or an object."""

    __slots__ = ('cmd', 'type', 'dst', 'src', 'size', 'data', 'ok')

    def __init__(self, cmd, type_, dst, src, size, data, ok=True):
        self.cmd, self.type = cmd, type_
        self.dst, self.src = dst, src
        self.size, self.data = size, data
        self.ok = ok

    @property
    def name(self):
        return OBJECTS.get(self.dst, 'unknown')

    def __repr__(self):
        return ('<%s cmd=%02X type=%02X dst=%04X src=%04X size=%d data=%d%s>'
                % ('read' if self.cmd == 3 else 'write', self.cmd, self.type,
                   self.dst, self.src, self.size, len(self.data),
                   '' if self.ok else ' BAD CRC'))


def decode(frame):
    """Undo the envelope. Raises only if this is not a frame at all."""
    if len(frame) < 5 or frame[0] != 0xF0 or frame[1] != 0x7F or frame[-1] != 0xF7:
        raise ValueError("not a GP-150 frame")
    body = frame[3:-1]
    ok = crc(body) == frame[2]
    if len(body) < 6:
        return Frame(0, 0, 0, 0, b'', True, ok, frame)
    pay = body[6:]
    # Bulk data is nibble-encoded; a resend request carries plain values.
    nibbled = all(x < 0x10 for x in pay)
    return Frame(u14(body[0], body[1]), u14(body[2], body[3]), body[4], body[5],
                 unnibble(pay) if nibbled else pay, nibbled, ok, frame)


def encode(payload=b'', total=0, off=0, seq=0, chunk=0, raw=False):
    body = (p14(total) + p14(off) + bytes([seq & 0x7F, chunk & 0x7F])
            + (payload if raw else nibble(payload)))
    return b'\xF0\x7F' + bytes([crc(body)]) + body + b'\xF7'


def unpack(buf):
    """Parse a data package. Returns None if `buf` is not one."""
    if len(buf) < 4 or buf[0] != 0x01:
        return None
    ln = u16(buf, 2)
    body = buf[4:4 + ln]
    if len(body) < 8:
        return None
    return Package(body[0], body[1], u16(body, 2), u16(body, 4), u16(body, 6),
                   body[8:], crc8(body) == buf[1])


def pack(cmd, type_, dst, src, size, data=b''):
    body = bytes([cmd, type_]) + p16(dst) + p16(src) + p16(size) + data
    return b'\x01' + bytes([crc8(body)]) + p16(len(body)) + body


def read_request(obj, seq=1):
    """The frame Suite sends to read `obj`, byte for byte as captured."""
    if obj not in READS:
        raise ValueError("no captured read for object %04X; this file only "
                         "replays request shapes that were actually seen"
                         % obj)
    cmd, type_, extra = READS[obj]
    pkg = pack(cmd, type_, obj, obj, 2, extra)
    # On a request `len16` carries the package's length, not an object size.
    return encode(pkg, total=len(pkg), seq=seq)


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

    A transfer is a run of replies with the same `seq` whose offsets climb; the
    same number is used again later for something else, so a chunk at offset 0
    starts a new transfer rather than overwriting the old one.
    """
    out = []
    open_ = {}
    for t, d, f in msgs:
        if d != 'in' or not f.data or f.total == 0 or not f.nibbled:
            continue
        cur = open_.get(f.seq)
        if cur is None or f.off == 0 or f.total != cur['total'] or f.off < cur['end']:
            cur = {'seq': f.seq, 'total': f.total, 'buf': bytearray(f.total),
                   'seen': 0, 'end': 0, 'time': t}
            open_[f.seq] = cur
            out.append(cur)
        n = min(len(f.data), f.total - f.off)
        if n > 0:
            cur['buf'][f.off:f.off + n] = f.data[:n]
            cur['seen'] += n
            cur['end'] = f.off + n
    for o in out:
        o['pkg'] = unpack(bytes(o['buf'])) if o['seen'] >= o['total'] else None
    return out


def requests(msgs):
    """Every package Suite sent, with the resend requests kept apart."""
    out = []
    for t, d, f in msgs:
        if d != 'out' or not f.data:
            continue
        if not f.nibbled:
            p = f.data
            out.append((t, 'resend', {'seq': f.seq, 'chunk': f.chunk,
                                      'off': u14(p[2], p[3]), 'len': p[4]}))
            continue
        p = unpack(f.data)
        if p is not None:
            out.append((t, 'read' if p.cmd == 3 else 'write', p))
    return out


def cmd_frames(path):
    msgs = read_capture(path)
    print("%d frames" % len(msgs))
    bad = sum(1 for _t, _d, f in msgs if not f.ok)
    raw = sum(1 for _t, _d, f in msgs if not f.nibbled)
    print("checksum: %d good, %d bad; %d frames carry plain (un-nibbled) values"
          % (len(msgs) - bad, bad, raw))
    print()
    print("%-13s %-4s %-7s %-7s %-7s %s"
          % ("time", "dir", "total", "offset", "seq", "payload"))
    for t, d, f in msgs[:60]:
        print("%-13s %-4s %-7d %-7d %02X.%02X   %s"
              % (t, d, f.total, f.off, f.seq, f.chunk, f.data[:20].hex(' ')))
    if len(msgs) > 60:
        print("... %d more" % (len(msgs) - 60))


def cmd_objects(path):
    msgs = read_capture(path)
    objs = objects(msgs)
    reqs = requests(msgs)
    whole = [o for o in objs if o['seen'] >= o['total']]
    print("%d frames -> %d transfers (%d complete) and %d requests"
          % (len(msgs), len(objs), len(whole), len(reqs)))
    print()
    print("what Suite asked for:")
    seen = collections.Counter()
    for _t, kind, p in reqs:
        if kind == 'resend':
            seen[('resend', None)] += 1
        else:
            seen[(kind, p.dst)] += 1
    for (kind, dst), n in sorted(seen.items(), key=lambda kv: -kv[1]):
        if dst is None:
            print("  %-6s %-6s %4d  (a chunk that went missing)" % (kind, '', n))
        else:
            print("  %-6s %04X   %4d  %s" % (kind, dst, n, OBJECTS.get(dst, '?')))
    print()
    print("what came back:")
    got = collections.Counter()
    for o in objs:
        p = o['pkg']
        got[(p.dst if p else None, o['total'])] += 1
    for (dst, size), n in sorted(got.items(), key=lambda kv: -kv[1]):
        print("  %s %-6d %4d  %s"
              % ('%04X' % dst if dst is not None else '????', size, n,
                 OBJECTS.get(dst, '?')))
    print()
    print("Objects are addressed by id, not by memory address: there is no")
    print("'read me bytes at this location' anywhere in the capture.")


def cmd_dump(path, outdir):
    msgs = read_capture(path)
    objs = objects(msgs)
    if not os.path.isdir(outdir):
        os.makedirs(outdir)
    n = 0
    for i, o in enumerate(objs):
        p = o['pkg']
        name = '%03d_%s_%d.bin' % (i, '%04X' % p.dst if p else 'part', o['total'])
        open(os.path.join(outdir, name), 'wb').write(bytes(o['buf']))
        n += 1
    print("wrote %d objects to %s" % (n, outdir))


def cmd_read(obj):
    obj = int(obj, 0)
    f = read_request(obj)
    print("%s  -> %s" % (OBJECTS.get(obj, 'unknown object'), f.hex(' ')))
    d = decode(f)
    p = unpack(d.data)
    print("round trip: %r %r" % (d, p))


def cmd_build(hexstr, total=0, off=0, seq=(0, 0)):
    payload = bytes.fromhex(hexstr) if hexstr else b''
    f = encode(payload, total, off, seq[0], seq[1])
    print("%d bytes" % len(f))
    print(f.hex(' '))
    d = decode(f)
    print("round trip: total=%d off=%d seq=%02X.%02X payload=%d crc %s"
          % (d.total, d.off, d.seq, d.chunk, len(d.data),
             "ok" if d.ok else "WRONG"))


def main(argv):
    if len(argv) >= 2 and argv[0] == 'frames':
        return cmd_frames(argv[1])
    if len(argv) >= 2 and argv[0] == 'objects':
        return cmd_objects(argv[1])
    if len(argv) == 3 and argv[0] == 'dump':
        return cmd_dump(argv[1], argv[2])
    if len(argv) == 2 and argv[0] == 'read':
        return cmd_read(argv[1])
    if len(argv) >= 2 and argv[0] == 'build':
        total = off = 0
        seq = (0, 0)
        rest = argv[1:]
        i = 0
        payload = ''
        while i < len(rest):
            if rest[i] == '--len':
                total = int(rest[i + 1], 0); i += 2
            elif rest[i] == '--off':
                off = int(rest[i + 1], 0); i += 2
            elif rest[i] in ('--seq', '--id'):
                a, _, b = rest[i + 1].partition(',')
                seq = (int(a, 0), int(b or 0, 0)); i += 2
            else:
                payload = rest[i]; i += 1
        return cmd_build(payload, total, off, seq)
    print(__doc__.strip())
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
