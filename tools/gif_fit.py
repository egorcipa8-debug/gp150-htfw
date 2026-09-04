#!/usr/bin/env python3
"""gif_fit.py - squeeze an animation into the firmware's boot slot.

The slot is fixed: whatever the stock animation occupies, 474 509 bytes on
GP-150 V1.1.1, and the screen is 320x240. An 18 MB clip has to lose 97% of
itself to fit, and there are only three places to take it from - the frame
count, the palette and the picture size - so this tries the first two against
the budget and says what it had to give up.

It writes the same *shape* of GIF the firmware already carries, which is the
conservative choice for a decoder nobody has the source of: every frame
full-size, one global palette, no local colour tables, no transparency and no
disposal tricks. The stock file is exactly that - 320x240, 57 frames, 128
colours, 40 ms - so that shape is known to play on the pedal.

    gif_fit.py fit <in.gif> <out.gif> [--slot fw.bin | --budget N]
                   [--size 320x240] [--fit letterbox|crop|stretch]
                   [--colors N] [--frames N] [--fps N] [--clip a:b]
                   [--quant octree|maxcov|medcut] [--dither]

With only a budget it searches every palette size, reports what each one buys,
and keeps the smoothest - preferring the richer palette when it costs almost
nothing in frames. `--colors` or `--frames` pins one side and searches the other.

`--clip 3500:` keeps everything from 3.5 s on, which is usually a better trade
than halving the frame rate of the whole clip: the budget is per file, not per
second.
"""

import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from PIL import Image, ImageSequence
except ImportError:                                   # pragma: no cover
    raise SystemExit("needs pillow:  python -m pip install pillow")

PALETTES = (128, 64, 32, 16)
MIN_FRAMES = 8


def load(path, clip=None):
    """Frames as RGB, with their durations in ms."""
    im = Image.open(path)
    frames, times = [], []
    t = 0
    for f in ImageSequence.Iterator(im):
        d = f.info.get('duration') or im.info.get('duration') or 40
        if clip and (t < clip[0] or (clip[1] and t >= clip[1])):
            t += d
            continue
        frames.append(f.convert('RGB').copy())
        times.append(d)
        t += d
    if not frames:
        raise SystemExit("no frames in that clip range")
    return frames, times


def resize(frames, size, how='letterbox'):
    w, h = size
    out = []
    for f in frames:
        if how == 'stretch':
            out.append(f.resize((w, h), Image.LANCZOS))
            continue
        sw, sh = f.size
        s = max(w / sw, h / sh) if how == 'crop' else min(w / sw, h / sh)
        nw, nh = max(1, int(round(sw * s))), max(1, int(round(sh * s)))
        r = f.resize((nw, nh), Image.LANCZOS)
        canvas = Image.new('RGB', (w, h), (0, 0, 0))
        canvas.paste(r, ((w - nw) // 2, (h - nh) // 2))
        out.append(canvas)
    return out


def sample(frames, n):
    """n frames spread evenly over the animation, first and last kept."""
    if n >= len(frames):
        return list(range(len(frames)))
    if n <= 1:
        return [0]
    step = (len(frames) - 1) / (n - 1)
    return [int(round(i * step)) for i in range(n)]


QUANT = {'octree': Image.FASTOCTREE,
         'maxcov': Image.MAXCOVERAGE,
         'medcut': Image.MEDIANCUT}


def _palette(frames, colors, quant='octree'):
    """One palette for the whole animation, from a strip of sample frames. A
    per-frame palette would mean a local colour table on every frame, which is
    both bigger and further from what the firmware's own file does.

    The method matters more than it looks. Median cut - what `convert('P',
    ADAPTIVE)` uses - spends its palette where the pixels are, and in a clip
    with a dark background that means thirty shades of near-black and nothing
    left for the gold and pink that the picture is actually about; the result
    is recognisable and completely desaturated. Octree keeps the hues.
    """
    idx = sample(frames, min(12, len(frames)))
    w, h = frames[0].size
    strip = Image.new('RGB', (w, h * len(idx)))
    for k, i in enumerate(idx):
        strip.paste(frames[i], (0, k * h))
    return strip.quantize(colors=colors, method=QUANT.get(quant, Image.FASTOCTREE))


def build(frames, times, keep, colors, out=None, dither=False,
          quant='octree'):
    """Encode `keep` frames at `colors` colours. Returns (bytes, frame count).

    Dithering is off by default, and that is not a detail: its noise is exactly
    what LZW cannot compress, and it costs a third of the file - a third that
    buys frames instead.
    """
    idx = sample(frames, keep)
    pal = _palette([frames[i] for i in idx], colors, quant)
    mode = Image.FLOYDSTEINBERG if dither else Image.NONE
    conv = [frames[i].quantize(palette=pal, dither=mode) for i in idx]
    # A dropped frame's time goes to the frame that replaced it, so an
    # animation that ran six seconds still runs six seconds.
    dur = []
    for k, i in enumerate(idx):
        nxt = idx[k + 1] if k + 1 < len(idx) else len(frames)
        dur.append(max(20, sum(times[i:nxt])))
    buf = io.BytesIO()
    conv[0].save(buf, 'GIF', save_all=True, append_images=conv[1:],
                 duration=dur, loop=0, optimize=False, disposal=0)
    data = buf.getvalue()
    if out:
        open(out, 'wb').write(data)
    return data, len(conv)


def fit(frames, times, budget, colors=None, frames_wanted=None, log=print,
        dither=False, quant='octree'):
    """What fits at each palette size, and which of those to take.

    Measuring every combination would mean re-encoding the animation dozens of
    times. Instead each palette is probed once at a fixed frame count to learn
    its bytes per frame, the count that would fill the budget is extrapolated,
    and only that one is encoded for real - then nudged if the estimate was off.
    """
    probe = min(20, len(frames))
    rows = []
    for c in ([colors] if colors else PALETTES):
        data, n = build(frames, times, probe, c, dither=dither, quant=quant)
        per = len(data) / float(n)
        want = frames_wanted or max(MIN_FRAMES,
                                    min(len(frames), int(budget / per)))
        data, n = build(frames, times, want, c, dither=dither, quant=quant)
        while len(data) > budget and n > MIN_FRAMES:
            want = max(MIN_FRAMES, int(want * budget / float(len(data))) - 1)
            data, n = build(frames, times, want, c, dither=dither, quant=quant)
        if not frames_wanted and n < len(frames):
            step = max(2, n // 10)
            up, un = build(frames, times, min(len(frames), n + step), c,
                           dither=dither, quant=quant)
            if len(up) <= budget:
                data, n = up, un
        if len(data) <= budget:
            rows.append((c, n, data))
            log("  %3d colours -> %3d frames, %7d bytes (%.0f%% of the slot)"
                % (c, n, len(data), 100.0 * len(data) / budget))
        else:
            log("  %3d colours -> nothing fits, even at %d frames" % (c, n))
    if not rows:
        return None, []
    # Smoothness first - a boot splash that stutters looks broken - but take the
    # richer palette when it costs almost nothing in frames.
    best = max(rows, key=lambda r: r[1])
    for row in rows:
        if row[0] > best[0] and row[1] >= best[1] * 0.85:
            best = row
    return best, rows


def slot_budget(path):
    import gif_tool
    import htfw_tool
    fw = htfw_tool.Firmware(open(path, 'rb').read())
    if fw.body is None:
        raise SystemExit("payload is packed and could not be unpacked")
    gifs = gif_tool.find(fw.body)
    if not gifs:
        raise SystemExit("no GIF slot in %s" % path)
    return gifs[0]['len'], (gifs[0]['w'], gifs[0]['h'])


def cmd_fit(src, dst, budget=None, slot=None, size=(320, 240), how='letterbox',
            colors=None, frames_wanted=None, fps=None, clip=None, dither=False,
            quant='octree'):
    if slot:
        budget, size = slot_budget(slot)
        print("slot in %s: %d bytes, %dx%d"
              % (os.path.basename(slot), budget, size[0], size[1]))
    if not budget:
        raise SystemExit("give a --budget or a --slot")
    frames, times = load(src, clip)
    src_ms = sum(times)
    print("%s: %dx%d, %d frames, %.1f s, %d bytes"
          % (os.path.basename(src), frames[0].size[0], frames[0].size[1],
             len(frames), src_ms / 1000.0, os.path.getsize(src)))
    frames = resize(frames, size, how)
    if fps:
        frames_wanted = max(MIN_FRAMES, int(round(src_ms / 1000.0 * fps)))
    print("searching under %d bytes at %dx%d (%s, %s palette, dither %s):"
          % (budget, size[0], size[1], how, quant, "on" if dither else "off"))
    best, rows = fit(frames, times, budget, colors, frames_wanted,
                     dither=dither, quant=quant)
    if not best:
        raise SystemExit("nothing fits - clip it shorter (--clip), or force "
                         "--colors 16 and accept the banding")
    c, n, data = best
    open(dst, 'wb').write(data)
    rate = n / (src_ms / 1000.0)
    print("")
    print("%s: %d bytes of %d (%.0f%% of the slot)"
          % (os.path.basename(dst), len(data), budget,
             100.0 * len(data) / budget))
    print("  %dx%d, %d frames of the original %d, %d colours, %.1f s"
          % (size[0], size[1], n, len(frames), c, src_ms / 1000.0))
    print("  %.1f frames a second on the pedal" % rate)
    others = [r for r in rows if r is not best]
    if others:
        print("  the others: "
              + ", ".join("%d colours at %d frames" % (r[0], r[1])
                          for r in others))
    if rate < 12:
        print("")
        print("  That is choppy, and the slot is what it is, so the way to buy")
        print("  frames is to make the animation shorter - --clip 3500: keeps")
        print("  the last part at twice the frame rate for the same bytes.")
    if slot:
        print("")
        print("put it in with:  gif_tool.py inject <fw.bin> %s <out.bin>"
              % os.path.basename(dst))
        print("or click the animation tile in Studio's Graphics tab.")
    return 0


def main(argv):
    if not argv or argv[0] != 'fit' or len(argv) < 3:
        print(__doc__.strip())
        return 1
    src, dst = argv[1], argv[2]
    budget = slot = colors = frames_wanted = fps = clip = None
    size, how, dither, quant = (320, 240), 'letterbox', False, 'octree'
    i = 3
    while i < len(argv):
        a = argv[i]
        if a == '--budget' and i + 1 < len(argv):
            budget = int(argv[i + 1], 0); i += 2
        elif a == '--slot' and i + 1 < len(argv):
            slot = argv[i + 1]; i += 2
        elif a == '--size' and i + 1 < len(argv):
            w, h = argv[i + 1].lower().split('x')
            size = (int(w), int(h)); i += 2
        elif a == '--fit' and i + 1 < len(argv):
            how = argv[i + 1]; i += 2
        elif a == '--colors' and i + 1 < len(argv):
            colors = int(argv[i + 1]); i += 2
        elif a == '--frames' and i + 1 < len(argv):
            frames_wanted = int(argv[i + 1]); i += 2
        elif a == '--fps' and i + 1 < len(argv):
            fps = float(argv[i + 1]); i += 2
        elif a == '--clip' and i + 1 < len(argv):
            a0, _, a1 = argv[i + 1].partition(':')
            clip = (int(a0 or 0), int(a1) if a1 else None); i += 2
        elif a == '--dither':
            dither = True; i += 1
        elif a == '--quant' and i + 1 < len(argv):
            quant = argv[i + 1]; i += 2
        else:
            print("unknown option %s" % a)
            return 1
    return cmd_fit(src, dst, budget, slot, size, how, colors, frames_wanted,
                   fps, clip, dither, quant)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
