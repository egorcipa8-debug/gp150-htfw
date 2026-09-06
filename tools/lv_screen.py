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
SCREEN_W, SCREEN_H = 320, 240


class Screen(object):
    """One screen, as a tree of widgets with their contents."""

    def __init__(self, L, which, images=None, depth=2, roles=None):
        self.L = L
        self.img = L.img
        self.which = which
        self.images = images if images is not None else index_images(L.img)
        self.entry = L.entry(which)
        self.end = self._end(self.entry)
        self.calls = lv_trace.trace(L.code, SD, self.entry, self.end)
        # A screen whose handler delegates everything has no create call of
        # its own to learn from, so the roles are worked out once across all
        # fifteen and handed in.
        if roles:
            self.create, self.set_img, self.align = roles
        else:
            self.create, self.set_img = self._create(), self._img_setter()
            self.align = None
        self.depth = depth
        self.objs = self._build()

    def _end(self, entry):
        i = bisect.bisect_right(self.L.funcs, entry)
        return (self.L.funcs[i] if i < len(self.L.funcs)
                else entry + 0x4000)

    def _builds_widgets(self, target):
        """Does this function put widgets on the screen itself?

        A screen handler hands most of its work to helpers - a row, a tile, a
        meter - and those helpers are where the pictures and the captions are.
        A helper is recognised the only way that is safe: by whether its own
        body calls the constructor or the geometry setters.
        """
        if not (SD <= target < SD + len(self.L.code)):
            return None
        if target in (self.create, self.L.pos, self.L.size, self.set_img):
            return None
        cached = self._sub.get(target)
        if cached is not None:
            return cached
        cs = lv_trace.trace(self.L.code, SD, target, self._end(target))
        keep = [c for c in cs
                if c['target'] in (self.create, self.L.pos, self.L.size,
                                   self.set_img)]
        self._sub[target] = bool(keep)
        return bool(keep)

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
        self._sub = {}
        objs = {}
        order = []

        def get(key):
            if key not in objs:
                objs[key] = {'key': key, 'parent': None, 'x': 0, 'y': 0,
                             'w': None, 'h': None, 'img': None, 'text': None,
                             'align': None, 'ax_off': 0, 'ay_off': 0,
                             'x_at': None, 'y_at': None, 'w_at': None,
                             'h_at': None}
                order.append(key)
            return objs[key]

        self._walk(self.calls, objs, order, get, tag=(), parent=None,
                   left=self.depth)
        return [objs[k] for k in order]

    def _walk(self, calls, objs, order, get, tag, parent, left):
        """Read one function's calls into the tree, following its helpers.

        Only a call that is one of the four recognised setters, or the
        constructor, brings a widget into being. An earlier version made one
        for every call whose first argument it could name, which filled a
        screen with dozens of things that were never on it - seventy-three of
        the home screen's eighty-three, all of them sizeless and parentless.

        `tag` keeps two invocations of the same helper apart, so the second row
        of a list does not land on top of the first.
        """
        known = (self.create, self.L.pos, self.L.size, self.set_img,
                 self.align)

        def name(v):
            k = v.key() if v is not None else None
            return (tag + k) if k is not None else None

        ret_slot = {}
        for c in calls:
            if c['target'] != self.create:
                continue
            key = (tag + ('slot',) + c['stored']) if c['stored'] \
                else (tag + ('ret', c['ret'].v))
            ret_slot[c['ret'].v] = key
            o = get(key)
            p = c['args'].get(0)
            who = name(p)
            if who is not None and who[len(tag)] == 'ret':
                who = ret_slot.get(p.v, who)
            o['parent'] = who if who in objs else parent

        for c in calls:
            who = c['args'].get(0)
            key = name(who)
            if key is not None and key[len(tag)] == 'ret':
                key = ret_slot.get(who.v, key)
            a = c['args'].get(1)
            b = c['args'].get(2)

            if c['target'] in known and c['target'] != self.create \
                    and key is not None:
                o = get(key)
                if o['parent'] is None and key != parent:
                    o['parent'] = parent
                if c['target'] == self.L.pos and a is not None \
                        and b is not None and a.kind == 'imm' \
                        and b.kind == 'imm':
                    o['x'], o['y'] = a.v, b.v
                    o['x_at'], o['y_at'] = a.at, b.at
                elif c['target'] == self.L.size and a is not None \
                        and b is not None and a.kind == 'imm' \
                        and b.kind == 'imm':
                    o['w'], o['h'] = a.v, b.v
                    o['w_at'], o['h_at'] = a.at, b.at
                elif c['target'] == self.set_img and a is not None \
                        and a.kind == 'lit' and a.v in self.images:
                    o['img'] = a.v
                    pic = self.images[a.v]
                    if o['w'] is None:
                        # an image with no size of its own takes the picture's
                        o['w'], o['h'] = pic.w, pic.h
                elif c['target'] == self.align and a is not None \
                        and a.kind == 'imm' and a.v in ALIGN:
                    o['align'] = a.v
                    d = c['args'].get(3)
                    o['ax_off'] = b.v if b is not None and b.kind == 'imm' else 0
                    o['ay_off'] = d.v if d is not None and d.kind == 'imm' else 0
                continue

            # a caption, but only for something already known to be a widget
            if key in objs and a is not None and a.kind == 'lit':
                t = text_at(self.img, a.v)
                if t and t != '%s':
                    objs[key]['text'] = t
                    continue

            if left > 0 and self._builds_widgets(c['target']):
                # hand the callee the arguments it was called with, so the
                # parent it was given is the parent its widgets get
                sub = lv_trace.trace(self.L.code, SD, c['target'],
                                     self._end(c['target']), init=c['args'])
                self._walk(sub, objs, order, get,
                           tag + ('@%X' % c['at'],),
                           key if key in objs else parent, left - 1)

    def place(self):
        """Absolute boxes, by composing each widget onto its parent.

        A widget is put either at a position of its own or against one of its
        parent's edges, and LVGL's aligned form is the commoner of the two, so
        both are resolved here - the aligned ones need the parent's box, which
        is why this walks the tree from the top rather than each widget alone.
        """
        by = {o['key']: o for o in self.objs}
        box = {}

        def solve(key, guard=0):
            if key in box:
                return box[key]
            o = by.get(key)
            if o is None or guard > 16:
                return (0, 0, 320, 240)
            w = o['w'] if o['w'] else 0
            h = o['h'] if o['h'] else 0
            px, py, pw, ph = (solve(o['parent'], guard + 1)
                              if o['parent'] in by else (0, 0, 320, 240))
            if o['align'] in ALIGN:
                hx, hy = ALIGN[o['align']]
                x = {'l': 0, 'c': (pw - w) // 2, 'r': pw - w}[hx] + o['ax_off']
                y = {'t': 0, 'c': (ph - h) // 2, 'b': ph - h}[hy] + o['ay_off']
            else:
                x, y = o['x'], o['y']
            box[key] = (px + x, py + y, w, h)
            return box[key]

        root = self.objs[0]['key'] if self.objs else None

        def rooted(key, guard=0):
            """Does this widget's parent chain actually reach the screen?

            One whose parent could not be worked out has coordinates relative
            to a container we never identified, so placing it against the
            screen puts it somewhere it is not. Better to know which boxes are
            trustworthy than to draw them all and be wrong about half.
            """
            while key is not None and guard < 16:
                if key == root:
                    return True
                o = by.get(key)
                if o is None or o['parent'] is None:
                    return key == root
                key = o['parent']
                guard += 1
            return False

        out = []
        for o in self.objs:
            x, y, _w, _h = solve(o['key'])
            r = rooted(o['key'])
            # a box the size of a house came from a pairing that was not a
            # widget at all; say so rather than draw it over the screen
            if r and (not 0 < (o['w'] or 0) <= 2 * SCREEN_W
                      or not 0 < (o['h'] or 0) <= 2 * SCREEN_H
                      or not -SCREEN_W <= x <= 2 * SCREEN_W
                      or not -SCREEN_H <= y <= 2 * SCREEN_H):
                r = False
            out.append(dict(o, ax=x, ay=y, depth=self._depth(by, o['key']),
                            rooted=r))
        return out

    @staticmethod
    def _depth(by, key, guard=0):
        d = 0
        while key in by and by[key]['parent'] in by and guard < 16:
            key = by[key]['parent']
            d += 1
            guard += 1
        return d


# LVGL's alignments, in its own order. Only the nine inside a parent are used
# here; the OUT_* ones place a widget beside its parent and do not appear.
ALIGN = {1: ('l', 't'), 2: ('c', 't'), 3: ('r', 't'),
         4: ('l', 'b'), 5: ('c', 'b'), 6: ('r', 'b'),
         7: ('l', 'c'), 8: ('r', 'c'), 9: ('c', 'c')}


def discover(L, images):
    """The constructor, the picture setter and the align call, agreed across
    every screen - each found by what it is handed rather than by address."""
    made, imgs, alg = {}, {}, {}
    for k in range(len(L.registry())):
        entry = L.entry(k)
        i = bisect.bisect_right(L.funcs, entry)
        end = L.funcs[i] if i < len(L.funcs) else entry + 0x4000
        for c in lv_trace.trace(L.code, SD, entry, end):
            if c['stored']:
                made[c['target']] = made.get(c['target'], 0) + 1
            v = c['args'].get(1)
            if v is not None and v.kind == 'lit' and v.v in images:
                imgs[c['target']] = imgs.get(c['target'], 0) + 1
            a1, a2, a3 = (c['args'].get(1), c['args'].get(2),
                          c['args'].get(3))
            if (a1 is not None and a2 is not None and a3 is not None
                    and a1.kind == 'imm' and a2.kind == 'imm'
                    and a3.kind == 'imm' and a1.v in ALIGN):
                alg[c['target']] = alg.get(c['target'], 0) + 1
    return (max(made, key=made.get) if made else None,
            max(imgs, key=imgs.get) if imgs else None,
            max(alg, key=alg.get) if alg else None)


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
        if w <= 0 or h <= 0 or not o['rooted']:
            continue
        x, y = o['ax'], o['ay']
        dr.rectangle([x, y, x + w - 1, y + h - 1],
                     fill=PANEL[min(o['depth'], len(PANEL) - 1)],
                     outline=(70, 78, 94))
    for o in boxes:
        if not o['img'] or not o['rooted']:
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
    roles = discover(L, imgs)
    ids = L.ids()
    print("%-4s %-6s %-9s %-9s %-8s %s"
          % ("#", "id", "widgets", "pictures", "labels", "create / set_img"))
    for k in range(len(L.registry())):
        sc = Screen(L, k, imgs, roles=roles)
        pics = sum(1 for o in sc.objs if o['img'])
        txt = sum(1 for o in sc.objs if o['text'])
        print("%-4d %-6s %-9d %-9d %-8d %s / %s"
              % (k, ('0x%02X' % ids[k]) if k < len(ids) else '?',
                 len(sc.objs), pics, txt,
                 '0x%08X' % sc.create if sc.create else '-',
                 '0x%08X' % sc.set_img if sc.set_img else '-'))


def cmd_draw(path, which, out, scale=2):
    img, L = open_image(path)
    imgs = index_images(img)
    sc = Screen(L, which, imgs, roles=discover(L, imgs))
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
