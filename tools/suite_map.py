#!/usr/bin/env python3
"""suite_map.py - read what is legible in Valeton Suite's Dart snapshot.

Suite's UI is AOT-compiled Dart in `data/app.so`: an ELF whose `.dynsym` names
the four snapshot blobs, `_kDartIsolateSnapshotData` (4.4 MB) and
`_kDartIsolateSnapshotInstructions` (6.3 MB) among them. Recovering the objects
in that data means implementing the Dart version's own cluster deserialiser -
that is what a tool like blutter does, by compiling the matching Dart SDK - and
it is not what this is.

What this is: the snapshot was **not built obfuscated**. Every library URI,
class name and member name is in it as an ordinary string, and that alone maps
the application:

    package:qme10_pc                 223 source files - Suite itself
    package:ht_midi_data_protocol     28 source files - the device protocol
    package:flutter                  389 files, and the rest of the packages

so the protocol lives in `src/core/protocol/` with an `ht_protocol_handler`, a
`receive_assembler`, `crc_utils`, `ht_firmware_parser` and `ht_firmware_update`,
and the FFI surface between the Dart side and `assets/5868USB.dll` is 18 of that
library's 61 exports, named in the snapshot exactly as the DLL exports them. Names are canonicalised into one unordered table, so the
strings cannot be grouped back into their classes by position - what comes out
is an inventory, not source. Private members carry Dart's per-library key
(`_bind@637311317`), which does group them by library even though the key itself
says nothing about which library that is.

    suite_map.py map                  the whole picture: packages, files, FFI
    suite_map.py files [pkg]          source files, one per line
    suite_map.py classes [--like RE]  class-shaped names
    suite_map.py ffi                  which 5868USB.dll exports Dart binds
    suite_map.py strings [--like RE] [--min N]
    suite_map.py keys [--key N]       private names grouped by library key
"""

import collections
import os
import re
import struct
import sys

SUITE = os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'),
                     'Valeton Suite', 'Valeton Suite')
APPSO = os.path.join(SUITE, 'data', 'app.so')
USBDLL = os.path.join(SUITE, 'assets', '5868USB.dll')


def sections(blob):
    if blob[:4] != b'\x7fELF' or blob[4] != 2:
        raise SystemExit("not a 64-bit ELF")
    shoff, = struct.unpack_from('<Q', blob, 0x28)
    entsize, num, strndx = struct.unpack_from('<HHH', blob, 0x3A)
    out = []
    for i in range(num):
        o = shoff + i * entsize
        name, typ, _fl, addr, off, size, link, _info, _al, esz = \
            struct.unpack_from('<IIQQQQIIQQ', blob, o)
        out.append({'name': name, 'type': typ, 'addr': addr, 'off': off,
                    'size': size, 'link': link, 'entsize': esz})
    base = out[strndx]['off']
    for s in out:
        e = blob.index(b'\0', base + s['name'])
        s['nm'] = blob[base + s['name']:e].decode()
    return out


def snapshot(path=APPSO):
    """The isolate snapshot data - where the names live."""
    if not os.path.isfile(path):
        raise SystemExit("not found: %s\nInstall Valeton Suite, or pass a path."
                         % path)
    blob = open(path, 'rb').read()
    secs = sections(blob)
    for s in secs:
        if s['type'] == 11 and s['entsize']:
            strtab = secs[s['link']]['off']
            for i in range(s['size'] // s['entsize']):
                o = s['off'] + i * s['entsize']
                nm, _info, _oth, _shndx, val, size = \
                    struct.unpack_from('<IBBHQQ', blob, o)
                e = blob.index(b'\0', strtab + nm)
                if blob[strtab + nm:e] == b'_kDartIsolateSnapshotData':
                    return blob[val:val + size]
    raise SystemExit("no _kDartIsolateSnapshotData in %s" % path)


def strings(snap, minlen=3):
    return [m.group().decode('latin1')
            for m in re.finditer(rb'[ -~]{%d,200}' % minlen, snap)]


def uris(names):
    return sorted(set(s for s in names
                      if s.startswith('package:') or s.startswith('dart:')))


def packages(names):
    c = collections.Counter()
    for u in uris(names):
        c[u.split('/')[0]] += 1
    return c


CLASS_RE = re.compile(r'_?[A-Z][A-Za-z0-9_]{2,48}$')
PRIVATE_RE = re.compile(r'^(.+)@(\d{5,})$')


def classes(names, like=None):
    out = set(s for s in names if CLASS_RE.match(s))
    if like:
        rx = re.compile(like)
        out = set(s for s in out if rx.search(s))
    return sorted(out)


def keys(names):
    """Private members grouped by Dart's per-library key."""
    g = collections.defaultdict(set)
    for s in names:
        m = PRIVATE_RE.match(s)
        if m:
            g[m.group(2)].add(m.group(1))
    return g


def exports(path=USBDLL):
    """The DLL's export table, without needing pefile."""
    blob = open(path, 'rb').read()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    magic = struct.unpack_from('<H', blob, pe + 24)[0]
    dd = pe + 24 + (112 if magic == 0x20B else 96)
    rva, _sz = struct.unpack_from('<II', blob, dd)
    nsec = struct.unpack_from('<H', blob, pe + 6)[0]
    opt = struct.unpack_from('<H', blob, pe + 20)[0]
    secs = []
    for i in range(nsec):
        o = pe + 24 + opt + i * 40
        _vs, va, rawsz, raw = struct.unpack_from('<IIII', blob, o + 8)
        secs.append((va, max(_vs, rawsz), raw))

    def off(v):
        for va, sz, raw in secs:
            if va <= v < va + max(sz, 1):
                return raw + (v - va)
        return None
    e = off(rva)
    if e is None:
        return []
    nnames = struct.unpack_from('<I', blob, e + 24)[0]
    anames = struct.unpack_from('<I', blob, e + 32)[0]
    base = off(anames)
    out = []
    for i in range(nnames):
        p = off(struct.unpack_from('<I', blob, base + 4 * i)[0])
        end = blob.index(b'\0', p)
        out.append(blob[p:end].decode('latin1'))
    return out


# --------------------------------------------------------------------------

def cmd_map(path):
    snap = snapshot(path)
    names = strings(snap)
    pk = packages(names)
    print("Valeton Suite - Dart snapshot, %.1f MB, not obfuscated" % (len(snap) / 1e6))
    print()
    print("packages (source files seen in the snapshot):")
    for k, v in pk.most_common(14):
        print("  %-46s %4d" % (k, v))
    other = sum(v for k, v in pk.items()) - sum(v for _, v in pk.most_common(14))
    if other:
        print("  %-46s %4d  (%d more packages)"
              % ('...', other, len(pk) - 14))
    app = sorted(s for s in set(names) if s.startswith('package:qme10_pc'))
    if app:
        print("\nSuite itself is package:qme10_pc - %d files:" % len(app))
        tree = collections.Counter('/'.join(s.split('/')[1:-1]) or '(root)'
                                   for s in app)
        for d, n in sorted(tree.items()):
            print("  %-46s %4d" % (d, n))
    proto = sorted(s for s in set(names)
                   if s.startswith('package:ht_midi_data_protocol'))
    if proto:
        print("\nthe device protocol is package:ht_midi_data_protocol - %d files:"
              % len(proto))
        for s in proto:
            print("  %s" % s.split('/', 1)[1])
    try:
        ex = exports()
    except Exception:                                 # noqa: BLE001
        ex = []
    if ex:
        seen = set(names)
        used = sorted(e for e in ex if e in seen)
        print("\nFFI: Dart binds %d of 5868USB.dll's %d exports:"
              % (len(used), len(ex)))
        for i in range(0, len(used), 3):
            print("  " + "  ".join("%-30s" % u for u in used[i:i + 3]).rstrip())
    g = keys(names)
    print("\nprivate members: %d names in %d library groups (suite_map.py keys)"
          % (sum(len(v) for v in g.values()), len(g)))


def cmd_files(path, pkg=None):
    names = strings(snapshot(path))
    for u in uris(names):
        if pkg is None or u.startswith(pkg) or u.startswith('package:' + pkg):
            print(u)


def cmd_classes(path, like=None):
    names = strings(snapshot(path))
    out = classes(names, like)
    for s in out:
        print(s)
    print("\n%d names" % len(out), file=sys.stderr)


def cmd_ffi(path):
    names = set(strings(snapshot(path)))
    ex = exports()
    used = [e for e in ex if e in names]
    print("%-34s %s" % ("export", "bound by the Dart side"))
    for e in sorted(ex):
        print("  %-32s %s" % (e, "yes" if e in names else ""))
    print("\n%d of %d" % (len(used), len(ex)))


def cmd_strings(path, like=None, minlen=4):
    rx = re.compile(like) if like else None
    for s in sorted(set(strings(snapshot(path), minlen))):
        if rx is None or rx.search(s):
            print(s)


def cmd_keys(path, key=None):
    g = keys(strings(snapshot(path)))
    if key:
        for s in sorted(g.get(str(key), ())):
            print(s)
        return
    for k, v in sorted(g.items(), key=lambda kv: -len(kv[1]))[:40]:
        sample = ', '.join(sorted(v)[:6])
        print("  @%-12s %4d  %s" % (k, len(v), sample[:90]))


def main(argv):
    path = APPSO
    like = None
    key = None
    minlen = 4
    rest = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '--app' and i + 1 < len(argv):
            path = argv[i + 1]; i += 2
        elif a == '--like' and i + 1 < len(argv):
            like = argv[i + 1]; i += 2
        elif a == '--key' and i + 1 < len(argv):
            key = argv[i + 1]; i += 2
        elif a == '--min' and i + 1 < len(argv):
            minlen = int(argv[i + 1]); i += 2
        else:
            rest.append(a); i += 1
    cmd = rest[0] if rest else 'map'
    if cmd == 'map':
        return cmd_map(path)
    if cmd == 'files':
        return cmd_files(path, rest[1] if len(rest) > 1 else None)
    if cmd == 'classes':
        return cmd_classes(path, like)
    if cmd == 'ffi':
        return cmd_ffi(path)
    if cmd == 'strings':
        return cmd_strings(path, like, minlen)
    if cmd == 'keys':
        return cmd_keys(path, key)
    print(__doc__.strip())
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
