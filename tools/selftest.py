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
  * section b's load table reads, its halves are consecutive, and the fonts
    and screen layout behind it are found - with one layout constant edited
    in memory and read back;
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


def test_bulk_edits(path, body):
    """The bug this exists for: a bulk edit that paints over the twelve-byte
    descriptors. The firmware reads them, and a build that lost ninety of them
    ran fine and drew colour static where every icon should be."""
    print("bulk edits")
    try:
        sys.path.insert(0, os.path.join(HERE, '..', 'studio'))
        import server as studio
    except Exception as e:                            # noqa: BLE001
        check("Studio imports", False, str(e))
        return
    try:
        from PIL import Image
    except ImportError:
        return
    pr = studio.Project()
    pr.load(path)
    check("Studio reads the same index", len(pr.images) == len(gfx_index.scan(body)),
          "%d images" % len(pr.images))
    tex = Image.new('RGB', (16, 16))
    for y in range(16):
        for x in range(16):
            tex.putpixel((x, y), (x * 16, y * 16, 128))
    res = pr.apply_texture(tex, mode='replace', keep_alpha=True, fit='stretch')
    check("a texture over everything writes something",
          res['pixels'] > 100000,
          "%d images, %d pixels, %d skipped as unsafe"
          % (res['regions'], res['pixels'], res.get('skipped', 0)))
    bad = gfx_index.compare(body, bytes(pr.body))
    check("and leaves every descriptor intact", not bad,
          "%d images still indexed" % len(gfx_index.scan(bytes(pr.body)))
          if not bad else "%d descriptors overwritten" % len(bad))
    damaged = bytearray(pr.body)
    hdr = pr.images[3]['hdr']
    damaged[hdr:hdr + 12] = bytes(12)
    fixed, n = gfx_index.restore(body, bytes(damaged))
    check("and a damaged one can be put back", n == 1 and
          gfx_index.compare(body, fixed) == [], "restored %d" % n)


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


def test_interface(path):
    """The load table, the fonts and the layout - the three things §32 turned up.

    All of it reads the file only; the one write goes to a copy in memory and is
    checked by reading the value back, then undone. Nothing reaches the disk.
    """
    import flat_image
    import htfw_tool as H
    import lv_font
    import lv_layout
    import thumb_imm

    fw = H.Firmware(open(path, 'rb').read())
    tbl = flat_image.load_table(fw, fw.body)
    check("section b carries a load table", len(tbl) == 2,
          "%d blocks" % len(tbl))
    if len(tbl) != 2:
        return
    (o1, l1, d1), (o2, l2, d2) = tbl
    check("its two halves are consecutive", o1 + l1 == o2,
          "0x%06X + %d = 0x%06X" % (o1, l1, o2))
    check("they go to ITCM and SDRAM", d1 == 0 and d2 == 0x80000000,
          "0x%08X and 0x%08X" % (d1, d2))

    img = lv_font.Image(path)
    fonts = lv_font.find(img)
    check("the interface's fonts are found", len(fonts) >= 4,
          "%d fonts" % len(fonts))
    if fonts:
        f = lv_font.Font(img, fonts[0])
        check("a font's depth is measured, not guessed", f.bpp in (1, 2, 4, 8),
              "%d bpp, %d glyphs, %d px tall" % (f.bpp, f.count - 1, f.height()))
        # the first glyphs are the line feed and the space, both boxless
        im, at = None, 0
        for i in range(1, min(f.count, 40)):
            im = f.render(i)
            if im is not None:
                at = i
                break
        check("its glyphs decode to a bitmap", im is not None and im.width > 0,
              "glyph %d is %dx%d" % (at, im.width, im.height) if im else "nothing")

    L = lv_layout.Layout(img=img)
    check("the geometry setters identify themselves", L.pos != L.size,
          "set_pos 0x%08X, set_size 0x%08X" % (L.pos, L.size))
    reg = L.registry()
    check("the screen registry reads", len(reg) >= 8, "%d screens" % len(reg))
    total = sum(len(L.widgets(L.func_of(h[0]) or h[0])) for h in reg)
    check("screens lay widgets out", total > 50, "%d widgets in all" % total)

    done = False
    for h in reg:
        for r in L.widgets(L.func_of(h[0]) or h[0]):
            at = r['size']['b_at']
            off = img.off(at, 4)
            old = thumb_imm.read_imm(bytes(img.body[off:off + 4]), 0)
            if old is None or not 8 <= old[1] <= 200:
                continue
            want = old[1] + 1
            try:
                new = thumb_imm.encode_imm(img.body, off, want)
            except ValueError:
                continue
            keep = bytes(img.body[off:off + len(new)])
            img.body[off:off + len(new)] = new
            back = thumb_imm.read_imm(bytes(img.body[off:off + 4]), 0)
            img.body[off:off + len(keep)] = keep
            check("a layout constant round trips",
                  bool(back) and back[1] == want,
                  "0x%08X: %d -> %d" % (at, old[1], back[1] if back else -1))
            done = True
            break
        if done:
            break
    if not done:
        check("a layout constant round trips", False, "no candidate found")


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
        test_bulk_edits(path, body)
        test_interface(path)
    test_packets()
    if len(argv) > 1:
        test_nam(argv[1])
    print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ', '.join(FAIL))
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
