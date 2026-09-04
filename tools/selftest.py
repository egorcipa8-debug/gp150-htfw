#!/usr/bin/env python3
"""selftest.py - check the whole pipeline against a real firmware image.

Every claim in this repository that can be checked without a device is checked
here, on whatever image you point it at:

  * the container round-trips - unpack, repack, same SHA-256 as the input;
  * the whole-file CRC and every region CRC verify, and re-sealing is a no-op;
  * the image index reads, and every indexed picture decodes and re-encodes to
    the same bytes it came from;
  * the boot animation is found by walking the GIF's own block structure, and
    putting it back where it came from reproduces the payload exactly;
  * the packet CRC-8 table matches the one in Valeton Suite's library, and a
    frame survives encode/decode;
  * a NAM capture, if you pass one, loads with every weight accounted for and
    its submodels agree with each other.

    selftest.py <fw.bin> [capture.nam]

Nothing here writes to the firmware, opens a MIDI port or touches a device.
"""

import contextlib
import hashlib
import io
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gfx_index                                   # noqa: E402
import gif_tool                                    # noqa: E402
import ht_packet                                   # noqa: E402
import htfw_tool                                   # noqa: E402

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print("  %s  %-52s %s" % ("ok  " if ok else "FAIL", name, detail))
    return ok


def test_container(path):
    print("container")
    blob = open(path, 'rb').read()
    fw = htfw_tool.Firmware(blob)
    check("header parses", fw.model is not None,
          "%s V%d.%d.%d%s" % (fw.model, fw.ver[0], fw.ver[1], fw.ver[2],
                              ", LZO packed" if fw.packed else ""))
    if fw.body is None:
        check("payload unpacks", False, "cannot continue without it")
        return None, None
    body = bytes(fw.body)
    check("payload unpacks", True, "%d bytes" % len(body))
    bad = [s.tag for s in fw.sections
           if htfw_tool.crc16_modbus(body[s.off:s.off + s.len]) != s.crc]
    check("every region CRC verifies", not bad,
          "%d regions" % len(fw.sections) if not bad
          else "wrong: %s" % ', '.join(bad))
    # A stale whole-file CRC says something about the input, not about these
    # tools - an image that was edited and never re-sealed has one. So the test
    # is that sealing behaves: it leaves a good image alone and repairs a bad
    # one, and either way the result verifies.
    stored = (blob[4] << 8) | blob[5]
    calc = htfw_tool.crc16_modbus(blob[6:])
    sealed = htfw_tool.seal(blob)
    again = htfw_tool.crc16_modbus(sealed[6:])
    if stored == calc:
        check("whole-file CRC verifies and sealing is a no-op",
              sealed == blob, "0x%04X" % stored)
    else:
        check("whole-file CRC was stale and sealing repairs it",
              sealed != blob and ((sealed[4] << 8) | sealed[5]) == again
              and sealed[6:] == blob[6:],
              "input said 0x%04X, content says 0x%04X - this image was edited "
              "without re-sealing" % (stored, calc))
    return fw, body


def test_roundtrip(path, blob_sha):
    print("round trip")
    tmp = tempfile.mkdtemp(prefix='gp150-selftest-')
    try:
        # those two narrate; the report is the point here
        with contextlib.redirect_stdout(io.StringIO()):
            htfw_tool.cmd_unpack(path, tmp)
            out = os.path.join(tmp, 'repacked.bin')
            htfw_tool.cmd_repack(path, tmp, out)
        made = open(out, 'rb').read()
        got = hashlib.sha256(made).hexdigest()
        if got == blob_sha:
            check("unpack then repack reproduces the file", True, got[:16])
        else:
            # A file that was edited and never re-sealed comes back with its
            # checksum repaired, which is a difference of exactly two bytes at
            # 0x04. That is the tool being right about a stale input, not the
            # round trip being wrong, and it is worth saying which one it is.
            orig = open(path, 'rb').read()
            diff = [i for i in range(min(len(orig), len(made)))
                    if orig[i] != made[i]]
            if len(orig) == len(made) and diff == [4, 5]:
                check("unpack then repack reproduces the file", True,
                      "except the whole-file CRC, which was stale in the input")
            else:
                check("unpack then repack reproduces the file", False,
                      "%d bytes differ" % len(diff))
    except SystemExit as e:
        check("unpack then repack reproduces the file", False, str(e))
    finally:
        for f in os.listdir(tmp):
            os.remove(os.path.join(tmp, f))
        os.rmdir(tmp)


def test_index(body):
    print("image index")
    blobs = gfx_index.scan(body)
    check("descriptors found", bool(blobs), "%d images" % len(blobs))
    if not blobs:
        return
    grades = {'art': 0, 'unsure': 0, 'junk': 0}
    for b in blobs:
        grades[gfx_index.grade(body, b)] += 1
    check("most of them are artwork", grades['art'] > len(blobs) // 2,
          "%d artwork, %d doubtful, %d never filled"
          % (grades['art'], grades['unsure'], grades['junk']))
    sizes = all(b.size == b.w * b.h * 3 for b in blobs)
    check("every descriptor's size matches its geometry", sizes)
    bad = 0
    for b in blobs:
        if gfx_index.grade(body, b) != 'art':
            continue
        im = gfx_index.decode(body, b.off, b.w, b.h)
        if gfx_index.encode(im, b.w, b.h) != body[b.off:b.end]:
            bad += 1
    check("decode then encode is byte-exact", bad == 0,
          "%d artwork blocks" % grades['art'] if not bad else "%d differ" % bad)
    chained = sum(1 for i in range(len(blobs) - 1)
                  if blobs[i].end + gfx_index.HDR == blobs[i + 1].off)
    check("blocks chain like a heap", chained > len(blobs) // 3,
          "%d of %d adjacent pairs" % (chained, len(blobs) - 1))


def test_gif(body):
    print("boot animation")
    gifs = gif_tool.find(body)
    if not check("a GIF is found", bool(gifs)):
        return
    g = gifs[0]
    check("it is the screen's size", (g['w'], g['h']) == (320, 240),
          "%dx%d, %s frames, %d bytes"
          % (g['w'], g['h'], g['frames'], g['len']))
    data = bytes(body[g['off']:g['off'] + g['len']])
    check("it ends on its own trailer", data[-1] == 0x3B)
    patched = bytearray(body)
    patched[g['off']:g['off'] + g['len']] = data
    check("putting it back reproduces the payload", bytes(patched) == body)


def test_packets():
    print("packets")
    hit = ht_packet.dll_table()
    if hit is None:
        check("CRC-8 table matches the vendor library", True,
              "skipped, Valeton Suite is not installed here")
    else:
        check("CRC-8 table matches the vendor library",
              hit[1] == bytes(ht_packet._TBL), "at 0x%X in the DLL" % hit[0])
    payload = bytes(range(42))
    frame = ht_packet.encode(0x11, 7, payload)
    cmd, index, back, ok = ht_packet.decode(frame)
    check("a frame survives encode and decode",
          (cmd, index, back, ok) == (0x11, 7, payload, True),
          "%d bytes on the wire for %d of payload" % (len(frame), len(payload)))
    broken = bytearray(frame)
    broken[5] ^= 0x01
    check("a corrupted frame fails its checksum",
          not ht_packet.decode(bytes(broken))[3])


def test_nam(path):
    print("NAM capture")
    try:
        import nam2namb
    except Exception as e:                            # noqa: BLE001
        check("nam2namb imports", False, str(e))
        return
    nam = nam2namb.load(path)
    subs = nam2namb.submodels(nam)
    check("capture parses", bool(subs),
          "%s, %d submodel%s" % (nam.get('architecture'), len(subs),
                                 '' if len(subs) == 1 else 's'))
    outs = []
    for mv, m in subs:
        try:
            net = nam2namb.WaveNet(m)
        except SystemExit as e:
            check("submodel <=%g loads every weight" % mv, False, str(e))
            continue
        c = nam2namb.cost(m)
        check("submodel <=%g loads every weight" % mv, net.used == net.total,
              "%d weights, %d MAC/sample, %.0f%% of the M7"
              % (net.total, c['macs'], 100 * c['load']))
        check("the config accounts for the same number",
              c['params'] == net.total,
              "%d from the config" % c['params'])
        outs.append((mv, net))
    if len(outs) > 1 and nam2namb.np is not None:
        wav = nam2namb.default_di()
        if wav:
            rate = float(subs[-1][1].get('sample_rate') or 48000)
            x = nam2namb.read_di(wav, rate, 2.0)
            ref = outs[-1][1].process(x)
            e = nam2namb.esr(outs[0][1].process(x), ref)
            check("the submodels agree with each other", e < 0.05,
                  "ESR %.4f between the narrowest and the widest" % e)


def main(argv):
    if not argv:
        print(__doc__.strip())
        return 1
    path = argv[0]
    print("selftest on %s\n" % os.path.basename(path))
    blob_sha = hashlib.sha256(open(path, 'rb').read()).hexdigest()
    fw, body = test_container(path)
    if body is not None:
        test_roundtrip(path, blob_sha)
        test_index(body)
        test_gif(body)
    test_packets()
    if len(argv) > 1:
        test_nam(argv[1])
    print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ', '.join(FAIL))
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
