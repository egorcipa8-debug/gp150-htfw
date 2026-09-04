#!/usr/bin/env python3
"""gif_tool.py - the boot animation, which is an ordinary GIF.

Section `b` carries one 448 KB run of near-random bytes that no image descriptor
covers and that reads as noise at every width. It is not noise and it is not
compressed code: it is a **GIF**, 320x240 - the screen's own resolution - 57
frames at 40 ms, the "GP-150 HD MODELING TECH II" splash that resolves into
VALETON. Whoever built it left the comment extension in place:

    GIF compressed with https://ezgif.com/optimize

so the file went through a web optimiser on its way into the firmware.

Nothing indexes it. It is found by its own magic and walked block by block -
extension, image descriptor, sub-block chain - to its trailer, which is the only
way to know where it ends, since the bytes after it are more artwork.

    gif_tool.py list    <fw.bin>                  what is in there
    gif_tool.py extract <fw.bin> <out.gif> [n]
    gif_tool.py inject  <fw.bin> <in.gif> <out.bin> [n]

`inject` will not grow the slot: a replacement has to be the same size or
smaller, and a smaller one is padded with zeros after its trailer, which a GIF
reader never reaches. Section CRCs are recomputed, so the result is a valid
image; run `gp150.py seal` (or Studio's Build) to stamp the whole-file CRC.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

MAGIC = (b'GIF87a', b'GIF89a')


def _end_of_gif(buf, start):
    """Offset one past the GIF's trailer, or -1. Walks the block structure -
    there is no length field anywhere in the format."""
    n = len(buf)
    i = start + 10
    if i + 3 > n:
        return -1
    flags = buf[start + 10]
    i = start + 13
    if flags & 0x80:                                # global colour table
        i += 3 * (2 << (flags & 7))
    while i < n:
        b = buf[i]
        if b == 0x3B:                               # trailer
            return i + 1
        if b == 0x21:                               # extension
            i += 2
            while i < n and buf[i]:
                i += buf[i] + 1
            i += 1
        elif b == 0x2C:                             # image descriptor
            if i + 10 > n:
                return -1
            lct = buf[i + 9]
            i += 10
            if lct & 0x80:
                i += 3 * (2 << (lct & 7))
            i += 1                                  # LZW minimum code size
            while i < n and buf[i]:
                i += buf[i] + 1
            i += 1
        else:
            return -1
    return -1


def find(payload):
    """Every GIF in the payload: offset, length, size, frame count."""
    out = []
    buf = bytes(payload)
    at = 0
    while True:
        hit = -1
        for m in MAGIC:
            p = buf.find(m, at)
            if p >= 0 and (hit < 0 or p < hit):
                hit = p
        if hit < 0:
            break
        end = _end_of_gif(buf, hit)
        if end > hit:
            w, h = struct.unpack_from('<HH', buf, hit + 6)
            out.append({'off': hit, 'len': end - hit, 'w': w, 'h': h,
                        'frames': _frames(buf[hit:end])})
            at = end
        else:
            at = hit + 6
    return out


def _frames(data):
    try:
        from PIL import Image, ImageSequence
        import io
        return sum(1 for _ in ImageSequence.Iterator(Image.open(io.BytesIO(data))))
    except Exception:                                 # noqa: BLE001
        return None


def _load(path):
    import htfw_tool
    fw = htfw_tool.Firmware(open(path, 'rb').read())
    if fw.body is None:
        raise SystemExit("payload is packed and could not be unpacked")
    return fw


def cmd_list(path):
    fw = _load(path)
    gifs = find(fw.body)
    if not gifs:
        print("no GIF in %s" % os.path.basename(path))
        return
    for i, g in enumerate(gifs):
        sec = next((s.tag for s in fw.sections
                    if s.off <= g['off'] < s.off + s.len), '?')
        print("%d  section %s  0x%06X  %d bytes  %dx%d  %s frames"
              % (i, sec, g['off'], g['len'], g['w'], g['h'],
                 g['frames'] if g['frames'] is not None else '?'))


def cmd_extract(path, out, which=0):
    fw = _load(path)
    gifs = find(fw.body)
    if which >= len(gifs):
        raise SystemExit("only %d GIF(s) in this image" % len(gifs))
    g = gifs[which]
    open(out, 'wb').write(bytes(fw.body[g['off']:g['off'] + g['len']]))
    print("%d bytes -> %s  (%dx%d, %s frames)"
          % (g['len'], out, g['w'], g['h'],
             g['frames'] if g['frames'] is not None else '?'))


def cmd_inject(path, gif, out, which=0):
    import htfw_tool
    fw = _load(path)
    gifs = find(fw.body)
    if which >= len(gifs):
        raise SystemExit("only %d GIF(s) in this image" % len(gifs))
    g = gifs[which]
    new = open(gif, 'rb').read()
    if new[:6] not in MAGIC:
        raise SystemExit("%s is not a GIF" % gif)
    if len(new) > g['len']:
        raise SystemExit("replacement is %d bytes, the slot holds %d - "
                         "optimise it down (fewer frames, fewer colours) and "
                         "try again" % (len(new), g['len']))
    body = bytearray(fw.body)
    body[g['off']:g['off'] + g['len']] = new + b'\0' * (g['len'] - len(new))
    blob = bytearray(fw.blob)
    if fw.packed:
        raise SystemExit("this image is LZO-packed; use Studio, which repacks, "
                         "or unpack and repack with htfw_tool.py")
    base = fw.payload
    blob[base:base + len(body)] = bytes(body)
    for s in fw.sections:
        crc = htfw_tool.crc16_modbus(bytes(body[s.off:s.off + s.len]))
        struct.pack_into('>H', blob, s.rec, crc)
    data = htfw_tool.seal(bytes(blob))
    open(out, 'wb').write(data)
    print("%s -> slot %d at 0x%06X (%d of %d bytes used)"
          % (gif, which, g['off'], len(new), g['len']))
    print("wrote %s, %d bytes, section CRCs and the whole-file CRC restamped"
          % (out, len(data)))


def main(argv):
    if len(argv) >= 2 and argv[0] == 'list':
        return cmd_list(argv[1])
    if len(argv) >= 3 and argv[0] == 'extract':
        return cmd_extract(argv[1], argv[2],
                           int(argv[3]) if len(argv) > 3 else 0)
    if len(argv) >= 4 and argv[0] == 'inject':
        return cmd_inject(argv[1], argv[2], argv[3],
                          int(argv[4]) if len(argv) > 4 else 0)
    print(__doc__.strip())
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
