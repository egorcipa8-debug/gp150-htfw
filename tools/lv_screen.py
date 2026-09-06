#!/usr/bin/env python3
"""lv_screen.py - draw the pedal's screen the way the pedal draws it.

`lv_layout.py` reads the numbers a screen is built from and shows them as
boxes. Boxes are enough to move something and not enough to recognise it. This
goes the rest of the way: it follows the builder with `lv_trace.py`, works out
which object is which, who its parent is, and what was put inside it, and
renders that - nested, with the real artwork and the real lettering, in the
pedal's own fonts.

Everything it needs identifies itself in the image rather than being written
down here:

* **create** is the call whose result is stored into a struct slot most often;
* **set_pos** and **set_size** are the two setters that pass LVGL style
  properties 7/8 and 1/4 to the common property helper - checked, not assumed;
* **the picture setter** is the call handed a pointer that lands exactly on an
  image descriptor the graphics index already knows about;
* **a label's text** is a call handed a pointer to printable bytes.

Coordinates in LVGL are relative to a widget's parent, which is why a flat list
of rectangles never looked like a screen. With the tree in hand they compose,
and the result is the layout as the device lays it out.

    lv_screen.py list   <fw.bin>
    lv_screen.py draw   <fw.bin> --screen N -o screen.png [--scale 2]
"""

import bisect
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gfx_index
import lv_font
import lv_layout
import lv_trace

SD = 0x80000000


class Screen(object):
    """One screen, as a tree of widgets with their contents."""

    def __init__(self, L, which, images=None):
        self.L = L
        self.img = L.img
        self.which = which
        self.images = images if images is not None else index_images(L.img)
        self.entry = L.entry(which)
        i = bisect.bisect_right(L.funcs, self.entry)
        self.end = L.funcs[i] if i < len(L.funcs) else self.entry + 0x4000
        self.calls = lv_trace.trace(L.code, SD, self.entry, self.end)
        self.create = self._create()
        self.set_img = self._img_setter()
        self.objs = self._build()

    # -- who does what ---------------------------------------------------
    def _create(self):
        """The constructor: its result is what ends up in the struct slots."""
        n = {}
        for c in self.calls:
            if c['stored']:
                n[c['target']] = n.get(c['target'], 0) + 1
        return max(n, key=n.get) if n else None

    def _img_setter(self):
        """The call given a pointer that is exactly an image descriptor."""
        n = {}
        for c in self.calls:
            v = c['args'].get(1)
            if v is not None and v.kind == 'lit' and v.v in self.images:
                n[c['target']] = n.get(c['target'], 0) + 1
        return max(n, key=n.get) if n else None

    # -- the tree --------------------------------------------------------
    def _build(self):
        objs = {}
        order = []

        def get(key):
            if key not in objs:
                objs[key] = {'key': key, 'parent': None, 'x': 0, 'y': 0,
                             'w': None, 'h': None, 'img': None, 'text': None,
                             'x_at': None, 'y_at': None, 'w_at': None,
                             'h_at': None}
                order.append(key)
            return objs[key]

        ret_slot = {}
        for c in self.calls:
            if c['target'] == self.create and c['stored']:
                key = ('slot',) + c['stored']
                ret_slot[c['ret'].v] = key
                o = get(key)
                p = c['args'].get(0)
                o['parent'] = p.key() if p is not None else None

        for c in self.calls:
            who = c['args'].get(0)
            if who is None:
                continue
            key = who.key()
            if key is not None and key[0] == 'ret':
                key = ret_slot.get(key[1], key)
            if key is None:
                continue
            # a widget built by a helper never passes through a create call we
            # can see, but it still gets its geometry set here - so give it an
            # entry rather than dropping it, with no parent we can name
            o = get(key)
            a, b = c['args'].get(1), c['args'].get(2)
            if c['target'] == self.L.pos and a is not None and b is not None \
                    and a.kind == 'imm' and b.kind == 'imm':
                o['x'], o['y'] = a.v, b.v
                o['x_at'], o['y_at'] = a.at, b.at
            elif c['target'] == self.L.size and a is not None and b is not None \
                    and a.kind == 'imm' and b.kind == 'imm':
                o['w'], o['h'] = a.v, b.v
                o['w_at'], o['h_at'] = a.at, b.at
            elif c['target'] == self.set_img and a is not None \
                    and a.kind == 'lit' and a.v in self.images:
                o['img'] = a.v
            elif a is not None and a.kind == 'lit':
                s = text_at(self.img, a.v)
                if s and s != '%s':
                    o['text'] = s
        return [objs[k] for k in order]

    def place(self):
        """Absolute boxes, by composing each widget onto its parent."""
        by = {o['key']: o for o in self.objs}
        out = []
        for o in self.objs:
            x, y = o['x'], o['y']
            p, guard = o['parent'], 0
            while p in by and guard < 16:
                x += by[p]['x']
                y += by[p]['y']
                p = by[p]['parent']
                guard += 1
            out.append(dict(o, ax=x, ay=y,
                            depth=self._depth(by, o['key'])))
        return out

    @staticmethod
    def _depth(by, key, guard=0):
        d = 0
        while key in by and by[key]['parent'] in by and guard < 16:
            key = by[key]['parent']
            d += 1
            guard += 1
        return d


def index_images(img):
    """Image descriptors by the SDRAM address the code points at them with."""
    out = {}
    for b in gfx_index.scan(img.body):
        if b.hdr >= img.sd_off:
            out[SD + (b.hdr - img.sd_off)] = b
    return out


def text_at(img, addr, limit=48):
    try:
        o = img.off(addr, 1)
    except ValueError:
        return None
    b = img.body
    e = o
    while e < min(o + limit, len(b)) and b[e] not in (0,):
        e += 1
    s = bytes(b[o:e])
    if len(s) < 1 or not all(32 <= c < 127 for c in s):
        return None
    return s.decode('latin1')


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

PANEL = [(28, 31, 38), (38, 42, 52), (48, 54, 66), (60, 67, 82), (74, 82, 99)]


def render(sc, scale=2, font=None):
    from PIL import Image as PILImage, ImageDraw
    W, H = 320, 240
    im = PILImage.new('RGB', (W, H), (10, 11, 14))
    dr = ImageDraw.Draw(im)
    boxes = sc.place()
    for o in boxes:
        w = o['w'] if o['w'] is not None else 0
        h = o['h'] if o['h'] is not None else 0
        if w <= 0 or h <= 0:
            continue
        x, y = o['ax'], o['ay']
        dr.rectangle([x, y, x + w - 1, y + h - 1],
                     fill=PANEL[min(o['depth'], len(PANEL) - 1)],
                     outline=(70, 78, 94))
    for o in boxes:
        if not o['img']:
            continue
        b = sc.images.get(o['img'])
        if b is None:
            continue
        try:
            pic = gfx_index.decode(sc.img.body, b.off, b.w, b.h).convert('RGBA')
        except Exception:                                     # noqa: BLE001
            continue
        im.paste(pic, (o['ax'], o['ay']), pic)
    if font is not None:
        for o in boxes:
            if not o['text']:
                continue
            draw_text(im, font, o['text'], o['ax'] + 2, o['ay'] + 1)
    if scale > 1:
        im = im.resize((W * scale, H * scale), PILImage.NEAREST)
    return im


def draw_text(im, f, s, x, y, colour=(235, 238, 245)):
    """One line, in one of the pedal's own fonts."""
    from PIL import Image as PILImage
    cx = x
    for ch in s:
        i = f.gid + (ord(ch) - f.first)
        if not 1 <= i < f.count:
            continue
        g = f.entry(i)
        adv = max(1, g['adv'] // 16)
        gl = f.render(i)
        if gl is not None:
            tint = PILImage.new('RGB', gl.size, colour)
            im.paste(tint, (cx + g['ox'], y + (f.height() - g['h'] - g['oy'])), gl)
        cx += adv
    return cx - x


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def open_image(path):
    img = lv_font.Image(path)
    return img, lv_layout.Layout(img=img)


def cmd_list(path):
    img, L = open_image(path)
    imgs = index_images(img)
    ids = L.ids()
    print("%-4s %-6s %-9s %-9s %-8s %s"
          % ("#", "id", "widgets", "pictures", "labels", "create / set_img"))
    for k in range(len(L.registry())):
        sc = Screen(L, k, imgs)
        pics = sum(1 for o in sc.objs if o['img'])
        txt = sum(1 for o in sc.objs if o['text'])
        print("%-4d %-6s %-9d %-9d %-8d %s / %s"
              % (k, ('0x%02X' % ids[k]) if k < len(ids) else '?',
                 len(sc.objs), pics, txt,
                 '0x%08X' % sc.create if sc.create else '-',
                 '0x%08X' % sc.set_img if sc.set_img else '-'))


def cmd_draw(path, which, out, scale=2):
    img, L = open_image(path)
    sc = Screen(L, which)
    fonts = lv_font.find(img)
    f = None
    for d in fonts:
        cand = lv_font.Font(img, d)
        if 12 <= cand.height() <= 18 and cand.n_ascii:
            f = cand
            break
    im = render(sc, scale, f)
    im.save(out)
    pics = sum(1 for o in sc.objs if o['img'])
    print("screen %d: %d widgets, %d pictures, %d labels -> %s"
          % (which, len(sc.objs), pics,
             sum(1 for o in sc.objs if o['text']), out))


def main(argv):
    if not argv:
        print(__doc__.strip())
        return 1
    cmd, rest = argv[0], argv[1:]
    opt = {}
    args = []
    i = 0
    while i < len(rest):
        if rest[i] in ('--screen', '-s'):
            opt['screen'] = int(rest[i + 1], 0); i += 2
        elif rest[i] in ('-o', '--out'):
            opt['out'] = rest[i + 1]; i += 2
        elif rest[i] == '--scale':
            opt['scale'] = int(rest[i + 1]); i += 2
        else:
            args.append(rest[i]); i += 1
    if cmd == 'list' and args:
        return cmd_list(args[0])
    if cmd == 'draw' and args:
        return cmd_draw(args[0], opt.get('screen', 0),
                        opt.get('out', 'screen.png'), opt.get('scale', 2))
    print(__doc__.strip())
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
