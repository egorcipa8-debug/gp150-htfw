#!/usr/bin/env python3
# suite_link.py - point Valeton Suite's own web link at GP-150 Studio.
#
# Suite is a Flutter app: its UI is AOT-compiled Dart in data/app.so, an ELF
# holding a Dart snapshot (magic F5F5DCDC at 0x200). Adding a screen to that
# would mean emitting new code objects with valid GC stack maps, registering
# classes in the snapshot's class table and matching its version hash - that is
# writing a Dart AOT backend, not patching bytes. So this does the one thing
# that is actually available: it repoints a link Suite already has.
#
# Suite carries "https://www.valeton.net/" as a Dart OneByteString. The object
# is laid out as
#
#     [8-byte header][8-byte length as a Smi][characters][NUL padding]
#
# and the Smi at -8 reads 0x30 = 48, which is 24 << 1 - exactly the string's
# length. Replacing the characters with a URL of the SAME length leaves the
# length field, the object size and every pointer to it untouched, so nothing
# else in the snapshot has to be understood or adjusted.
#
#     https://www.valeton.net/   24 characters
#     http://127.0.0.1:8765/gp   24 characters
#
# Writing into Program Files needs an elevated shell. app.so is copied to
# app.so.orig first, and `restore` puts it back.
#
#   suite_link.py status
#   suite_link.py patch [--url ...]
#   suite_link.py restore

import argparse
import os
import shutil
import sys

SUITE = os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'),
                     'Valeton Suite', 'Valeton Suite')
APPSO = os.path.join(SUITE, 'data', 'app.so')
BACKUP = APPSO + '.orig'

ORIGINAL = b'https://www.valeton.net/'
STUDIO = b'http://127.0.0.1:8765/gp'


def load():
    if not os.path.isfile(APPSO):
        raise SystemExit("not found: %s\nInstall Valeton Suite." % APPSO)
    return open(APPSO, 'rb').read()


def find(blob, needle):
    at = blob.find(needle)
    if at < 0:
        return None
    # sanity: the Smi eight bytes before the characters must encode the length
    smi = int.from_bytes(blob[at - 8:at], 'little')
    return at, smi, smi == len(needle) * 2


def cmd_status(_a):
    blob = load()
    print("app.so   : %s (%d bytes)" % (APPSO, len(blob)))
    print("backup   : %s" % (BACKUP if os.path.isfile(BACKUP) else "none"))
    for label, s in (("stock link", ORIGINAL), ("studio link", STUDIO)):
        hit = find(blob, s)
        if hit:
            at, smi, ok = hit
            print("%-12s: present at 0x%06X, length field %d %s"
                  % (label, at, smi // 2, "OK" if ok else "MISMATCH"))
        else:
            print("%-12s: not present" % label)


def cmd_patch(a):
    new = a.url.encode('ascii') if a.url else STUDIO
    if len(new) != len(ORIGINAL):
        raise SystemExit("the replacement must be exactly %d characters, "
                         "'%s' is %d - a different length would need the string's "
                         "length field and object size rewritten too."
                         % (len(ORIGINAL), new.decode(), len(new)))
    blob = load()
    hit = find(blob, ORIGINAL)
    if not hit:
        if find(blob, new):
            raise SystemExit("already patched - run `restore` first to change it.")
        raise SystemExit("the stock link was not found; this build of Suite "
                         "differs from the one this was worked out on.")
    at, smi, ok = hit
    if not ok:
        raise SystemExit("the length field at 0x%06X reads %d, expected %d - "
                         "refusing to touch an object that is not shaped the way "
                         "this expects." % (at - 8, smi // 2, len(ORIGINAL) * 2))
    if not os.path.isfile(BACKUP):
        shutil.copy2(APPSO, BACKUP)
        print("backed up -> %s" % BACKUP)
    out = bytearray(blob)
    out[at:at + len(new)] = new
    try:
        open(APPSO, 'wb').write(bytes(out))
    except PermissionError:
        raise SystemExit("permission denied writing %s - run this from an "
                         "elevated shell." % APPSO)
    print("patched 0x%06X: %s -> %s"
          % (at, ORIGINAL.decode(), new.decode()))
    print("Suite's website link now opens GP-150 Studio. Start Studio first:")
    print("   python studio/server.py \"<firmware>.bin\"")


def cmd_restore(_a):
    if not os.path.isfile(BACKUP):
        raise SystemExit("no backup at %s" % BACKUP)
    try:
        shutil.copy2(BACKUP, APPSO)
    except PermissionError:
        raise SystemExit("permission denied - run this from an elevated shell.")
    print("restored %s from %s" % (APPSO, BACKUP))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('status'); p.set_defaults(fn=cmd_status)
    p = sub.add_parser('patch')
    p.add_argument('--url', help="exactly %d characters" % len(ORIGINAL))
    p.set_defaults(fn=cmd_patch)
    p = sub.add_parser('restore'); p.set_defaults(fn=cmd_restore)
    a = ap.parse_args()
    sys.exit(a.fn(a) or 0)


if __name__ == '__main__':
    main()
