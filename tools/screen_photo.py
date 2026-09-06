#!/usr/bin/env python3
"""screen_photo.py - find the display in a photograph of the pedal.

A picture taken by hand has the bezel, the panel, the knobs and a bit of the
room in it. The display is the largest bright thing in the frame, so it can be
found without asking: threshold on brightness and take the biggest connected
region. Looking for long bright rows instead - the first thing tried - is
satisfied just as well by a reflection off the panel, and collapsed to a sliver
on half of these photographs.

    screen_photo.py find  <photo.jpg> [-o marked.png]
    screen_photo.py crop  <photo.jpg> -o display.png
    screen_photo.py sheet <dir> -o contact.png

`find` prints the crop as the four fractions Studio stores, so a photograph can
be lined up from the command line as well as with the sliders.
"""

import os
import sys


def _lum(im):
    return im.convert('L')


def find(path, thresh=0.45):
    """(left, top, right, bottom) as fractions of the photograph.

    The display is the largest bright thing in the picture, so the honest way
    to find it is to threshold on brightness and take the biggest connected
    region - not to look for long bright rows, which a reflection off the panel
    satisfies just as well and which collapsed to a sliver on half the photos
    the first time this was tried.
    """
    from PIL import Image
    im = Image.open(path)
    g = _lum(im)
    w, h = g.size
    sw = 200
    sh = max(1, int(sw * h / float(w)))
    s = g.resize((sw, sh), Image.BILINEAR)
    px = s.load()
    vals = sorted(px[x, y] for y in range(sh) for x in range(sw))
    hi = vals[int(len(vals) * 0.995)]
    cut = max(40, hi * thresh)

    xs, ys = [], []
    for y in range(sh):
        for x in range(sw):
            if px[x, y] > cut:
                xs.append(x)
                ys.append(y)
    if len(xs) < sw * sh * 0.01:
        return 0.0, 0.0, 1.0, 1.0
    xs.sort()
    ys.sort()

    def band(v, lo=0.01, hi_=0.99):
        return v[int(len(v) * lo)], v[min(len(v) - 1, int(len(v) * hi_))] + 1

    l, r = band(xs)
    t, b = band(ys)

    # The display is 320x240. A photograph of it is not always caught whole -
    # the dark bands inside the interface break the lit area up - so once the
    # bright pixels have given a box, stretch it to the shape the screen
    # actually is, about its own centre and inside the picture.
    want = 320.0 / 240.0
    bw, bh = (r - l) * (w / float(sw)), (b - t) * (h / float(sh))
    cx = (l + r) / 2.0 * (w / float(sw))
    cy = (t + b) / 2.0 * (h / float(sh))
    if bw / max(bh, 1.0) > want:
        bh = bw / want
    else:
        bw = bh * want
    x0 = max(0.0, cx - bw / 2)
    y0 = max(0.0, cy - bh / 2)
    x1 = min(float(w), x0 + bw)
    y1 = min(float(h), y0 + bh)
    return x0 / w, y0 / h, x1 / w, y1 / h


def crop(path, box=None):
    from PIL import Image
    im = Image.open(path).convert('RGB')
    l, t, r, b = box or find(path)
    return im.crop((int(im.width * l), int(im.height * t),
                    int(im.width * r), int(im.height * b)))


def cmd_find(path, out=None):
    from PIL import Image, ImageDraw
    box = find(path)
    print('%s  crop l=%.4f t=%.4f r=%.4f b=%.4f' % (os.path.basename(path), *box))
    if out:
        im = Image.open(path).convert('RGB')
        d = ImageDraw.Draw(im)
        d.rectangle([im.width * box[0], im.height * box[1],
                     im.width * box[2] - 1, im.height * box[3] - 1],
                    outline=(255, 60, 60), width=4)
        im.save(out)
        print('  marked -> %s' % out)


def cmd_crop(path, out):
    im = crop(path)
    im.save(out)
    print('%s -> %s  %dx%d' % (os.path.basename(path), out, im.width, im.height))


def cmd_sheet(d, out, cols=5):
    from PIL import Image, ImageDraw
    fs = sorted((os.path.join(d, f) for f in os.listdir(d)
                 if f.lower().endswith(('.jpg', '.jpeg', '.png'))))
    if not fs:
        raise SystemExit('no pictures in %s' % d)
    tw, th = 320, 260
    rows = (len(fs) + cols - 1) // cols
    m = Image.new('RGB', (cols * tw, rows * th), (18, 18, 20))
    dr = ImageDraw.Draw(m)
    for i, f in enumerate(fs):
        try:
            im = crop(f).resize((tw - 8, th - 28), Image.LANCZOS)
        except Exception as e:                            # noqa: BLE001
            print('  %s: %s' % (os.path.basename(f), e))
            continue
        x, y = (i % cols) * tw, (i // cols) * th
        m.paste(im, (x + 4, y + 22))
        dr.text((x + 8, y + 5), '%d  %s' % (i + 1, os.path.basename(f)[:34]),
                fill=(255, 220, 120))
    m.save(out)
    print('%d pictures -> %s' % (len(fs), out))


def main(argv):
    if not argv:
        print(__doc__.strip())
        return 1
    cmd, rest = argv[0], argv[1:]
    out = None
    args = []
    i = 0
    while i < len(rest):
        if rest[i] in ('-o', '--out'):
            out = rest[i + 1]; i += 2
        else:
            args.append(rest[i]); i += 1
    if cmd == 'find' and args:
        return cmd_find(args[0], out)
    if cmd == 'crop' and args and out:
        return cmd_crop(args[0], out)
    if cmd == 'sheet' and args and out:
        return cmd_sheet(args[0], out)
    print(__doc__.strip())
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
