#!/usr/bin/env python3
"""parse_spy.py - turn a capture into a protocol table.

`build_spy.py` writes one line per call; this reads them back and says what the
vocabulary actually is: which commands Suite sends, how long their payloads are,
what the first bytes look like, and - where the payload is a whole frame - what
is inside it once the nibble encoding and the checksum are undone.

    parse_spy.py <gp150_spy.log>          summary by command
    parse_spy.py <log> --cmd 0x11         every message with that command
    parse_spy.py <log> --frames           decode payloads as protocol frames
"""

import collections
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

try:
    import ht_packet
except ImportError:                                   # pragma: no cover
    ht_packet = None

LINE = re.compile(r'^(\d\d:\d\d:\d\d\.\d+)\s+send cmd=0x([0-9A-Fa-f]{2})\s+'
                  r'len=(-?\d+)\s+flag=(\d+)\s+(.*)$')

# the winmm capture: raw MIDI in both directions
MIDI = re.compile(r'^(\d\d:\d\d:\d\d\.\d+)\s+(out sysex|in  sysex|out short)\s+'
                  r'len=(\d+)\s+(.*)$')
SHORT = re.compile(r'^(\d\d:\d\d:\d\d\.\d+)\s+out short\s+(.*)$')


def read(path):
    out = []
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for line in fh:
            m = LINE.match(line.strip())
            if not m:
                continue
            t, cmd, ln, flag, rest = m.groups()
            hexpart = rest.replace('...', '').strip()
            data = bytes.fromhex(hexpart) if hexpart and hexpart[0] in '0123456789ABCDEFabcdef' else b''
            out.append({'time': t, 'cmd': int(cmd, 16), 'len': int(ln),
                        'flag': int(flag), 'data': data,
                        'truncated': '...' in rest})
    return out


def read_midi(path):
    """The winmm capture: every SysEx, both directions."""
    out = []
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for line in fh:
            m = MIDI.match(line.strip())
            if not m:
                continue
            t, what, ln, rest = m.groups()
            hexpart = rest.replace('...', '').strip()
            try:
                data = bytes.fromhex(hexpart)
            except ValueError:
                data = b''
            out.append({'time': t, 'dir': 'in' if what.startswith('in') else 'out',
                        'len': int(ln), 'data': data, 'truncated': '...' in rest})
    return out


def cmd_midi(path):
    msgs = read_midi(path)
    if not msgs:
        print("no MIDI lines in %s" % path)
        return 1
    print("%d SysEx messages, %s to %s"
          % (len(msgs), msgs[0]['time'], msgs[-1]['time']))
    seen = collections.Counter()
    rows = []
    for m in msgs:
        cmd = index = payload = None
        ok = False
        if ht_packet is not None and m['data'][:1] == b'\xF0' and not m['truncated']:
            try:
                cmd, index, payload, ok = ht_packet.decode(m['data'])
            except ValueError:
                pass
        seen[(m['dir'], cmd)] += 1
        rows.append((m, cmd, index, payload, ok))
    print()
    print("%-4s %-6s %-7s %s" % ("dir", "cmd", "count", "what the payload starts with"))
    for (d, cmd), n in sorted(seen.items(), key=lambda kv: (-kv[1], str(kv[0]))):
        first = next((r for r in rows if r[0]['dir'] == d and r[1] == cmd), None)
        head = (first[3][:10].hex(' ') if first and first[3] else
                (first[0]['data'][:10].hex(' ') if first else ''))
        print("%-4s %-6s %-7d %s"
              % (d, ('0x%02X' % cmd) if cmd is not None else 'raw', n, head))
    print()
    print("first twenty messages:")
    for m, cmd, index, payload, ok in rows[:20]:
        if cmd is None:
            print("  %s %-3s len=%-6d %s" % (m['time'], m['dir'], m['len'],
                                             m['data'][:20].hex(' ')))
        else:
            print("  %s %-3s cmd=0x%02X index=%-3d payload=%-4d crc=%s  %s"
                  % (m['time'], m['dir'], cmd, index, len(payload),
                     'ok' if ok else 'BAD', payload[:16].hex(' ')))
    return 0


def cmd_summary(path):
    if 'midi' in os.path.basename(path):
        return cmd_midi(path)
    msgs = read(path)
    if not msgs:
        print("no send lines in %s - was anything captured?" % path)
        return 1
    print("%d messages, %s to %s" % (len(msgs), msgs[0]['time'], msgs[-1]['time']))
    by = collections.defaultdict(list)
    for m in msgs:
        by[m['cmd']].append(m)
    print()
    print("%-6s %-7s %-12s %-9s %s" % ("cmd", "count", "payload", "flag", "first bytes"))
    for cmd in sorted(by):
        ms = by[cmd]
        lens = sorted({m['len'] for m in ms})
        lens_s = ('%d' % lens[0]) if len(lens) == 1 else \
                 ('%d..%d (%d sizes)' % (lens[0], lens[-1], len(lens)))
        flags = ','.join(str(f) for f in sorted({m['flag'] for m in ms}))
        first = ms[0]['data'][:8].hex(' ')
        print("0x%02X   %-7d %-12s %-9s %s" % (cmd, len(ms), lens_s, flags, first))
    print()
    print("Commands are the byte Suite passes to sendMidiMessage; the payload is")
    print("what goes inside the frame. A command that appears once with a short")
    print("payload and is followed by a burst of one other command is a request")
    print("and its answer being written back.")
    return 0


def cmd_one(path, cmd):
    for m in read(path):
        if m['cmd'] != cmd:
            continue
        print("%s  len=%-5d flag=%d  %s%s"
              % (m['time'], m['len'], m['flag'], m['data'][:64].hex(' '),
                 ' ...' if m['truncated'] else ''))
    return 0


def cmd_frames(path):
    if ht_packet is None:
        raise SystemExit("ht_packet.py is not importable from here")
    for m in read(path):
        d = m['data']
        if len(d) < 2 or d[0] != 0xF0:
            continue
        try:
            c, i, payload, ok = ht_packet.decode(d)
        except ValueError as e:
            print("%s  not a frame: %s" % (m['time'], e))
            continue
        print("%s  frame cmd=0x%02X index=%d payload=%d checksum=%s  %s"
              % (m['time'], c, i, len(payload), "ok" if ok else "BAD",
                 payload[:24].hex(' ')))
    return 0


def main(argv):
    if not argv:
        print(__doc__.strip())
        return 1
    path = argv[0]
    if not os.path.isfile(path):
        raise SystemExit("no such file: %s" % path)
    if '--frames' in argv:
        return cmd_frames(path)
    if '--cmd' in argv:
        return cmd_one(path, int(argv[argv.index('--cmd') + 1], 0))
    if '--midi' in argv:
        return cmd_midi(path)
    return cmd_summary(path)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
