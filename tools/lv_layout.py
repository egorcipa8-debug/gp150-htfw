#!/usr/bin/env python3
"""lv_layout.py - the pedal's own screens, as rectangles you can move.

The GP-150 draws its interface with LVGL, and an LVGL screen is assembled by
calling setters with plain numbers. Those numbers are immediates in the
instruction stream of the SDRAM half of section b (`FINDINGS.md` §32), so the
position, size and colour of every widget on every screen is a constant sitting
in a file we can rebuild and flash.

Nothing here is hard-coded to one firmware. The setters **identify themselves**:
scan every `BL` in the interface code, keep the ones reached with two constant
arguments, and rank the targets by how often that happens. On V1.1.1 the top
two are called 267 and 182 times with pairs that look like sizes and
coordinates, and they are exactly the two functions the decompiler shows setting
LVGL style properties 1/4 (width, height) and 7/8 (x, y). A different build
would name different addresses and the same reasoning would find them.

    lv_layout.py setters <fw.bin>            what the scan identifies, and why
    lv_layout.py screens <fw.bin>            the screen registry
    lv_layout.py show    <fw.bin> --screen N     one screen's widgets
    lv_layout.py draw    <fw.bin> --screen N -o wireframe.png
    lv_layout.py set     <fw.bin> --at 0xADDR --value N -o new.bin

`set` rewrites one immediate in place and re-seals the container. It refuses if
the new value needs a longer instruction than the one that is there, because
there is nowhere to put the extra bytes.
"""

import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lv_font
import thumb_imm

SDRAM = 0x80000000
SCREEN = (320, 240)

# How far into the SDRAM block the interface code runs. Past this it is
# artwork, strings and fonts; scanning them as code only wastes time.
CODE_LEN = 0x60000

# A widget's set_pos and set_size are emitted together - ten bytes apart in the
# code read so far. Anything further apart belongs to another object.
PAIR_SPAN = 64


class Layout(object):
    def __init__(self, path=None, img=None):
        self.img = img or lv_font.Image(path)
        self.code = bytes(self.img.body[self.img.sd_off:
                                        self.img.sd_off + CODE_LEN])
        self.calls = thumb_imm.calls(self.code, SDRAM)
        self.pos, self.size = self._setters()
        self.reg = self._registry()
        self.funcs = self._prologues()

    # -- who is who ------------------------------------------------------
    def _setters(self):
        """The geometry setters, found by what they are called with.

        A size setter is handed a width and a height, so its arguments cluster
        near the screen's own 320x240; a position setter is handed coordinates,
        which cluster lower and include zero far more often. Rank by how often
        a target is called with two constants, then tell the top two apart by
        which one is given the larger numbers.
        """
        n = collections.Counter()
        vals = collections.defaultdict(list)
        for c in self.calls:
            if 1 in c['args'] and 2 in c['args']:
                a, b = c['args'][1][0], c['args'][2][0]
                if a <= 4096 and b <= 4096:
                    n[c['target']] += 1
                    vals[c['target']].append((a, b))
        top = [t for t, _ in n.most_common(6)]
        if len(top) < 2:
            raise SystemExit("no geometry setters found in this image")

        def score(t):
            v = vals[t]
            big = sum(1 for a, b in v if a >= 40 and b >= 20)
            return big / float(len(v))
        top.sort(key=score, reverse=True)
        return top[1], top[0]                       # (position, size)

    def _prologues(self):
        """Function starts, so a call can be attributed to the screen it is in.

        A `push {..., lr}` is only a guess - the same halfword occurs in data,
        and a spurious start in the middle of a handler would split it and hand
        half its widgets to the wrong screen. The registry's own entry points
        are not guesses, so they are added and win ties.
        """
        out = set()
        for i in range(0, len(self.code) - 2, 2):
            w = struct.unpack_from('<H', self.code, i)[0]
            if (w & 0xFF00) == 0xB500 or w == 0xE92D:
                out.add(SDRAM + i)
        for h in self.reg:
            out.update(h)
        return sorted(out)

    def entry(self, which):
        """Where screen `which`'s first handler begins."""
        h = self.reg[which][0]
        f = self.func_of(h)
        return f if f == h else h

    def func_of(self, addr):
        import bisect
        i = bisect.bisect_right(self.funcs, addr)
        return self.funcs[i - 1] if i else None

    # -- the registry ----------------------------------------------------
    def ids(self):
        """The screen numbers the firmware itself uses.

        The registrar is called once per screen with the id as a plain constant
        and the three handlers as literal-pool loads, so the id is the one
        argument a scan of the ITCM half can see. Find the function called ten
        or more times with nothing but a small constant in r0, and its calls -
        in order - are the ids that go with the pointer triples in the pool.

        Returns [] rather than guessing if that shape is not there, and the
        caller falls back to numbering the screens in the order it found them.
        """
        itcm = bytes(self.img.body[self.img.itcm_off:
                                   self.img.itcm_off + self.img.itcm_len])
        cs = thumb_imm.calls(itcm, 0)
        by = collections.defaultdict(list)
        for c in cs:
            a = c['args']
            if 0 in a and a[0][0] <= 0x1F:
                by[c['target']].append((c['at'], a[0][0]))
        # the registrar is called once per screen, so its ids are all
        # different - which is what tells it apart from the many functions
        # that take a small number and are called repeatedly
        best = []
        for v in by.values():
            if len(set(x for _a, x in v)) == len(v) and len(v) > len(best):
                best = v
        if len(best) < 10 or len(best) != len(self.reg):
            return []
        best.sort()
        return [v for _at, v in best]

    def registry(self):
        return self.reg

    def _registry(self):
        """The screen table: id -> three handlers, read out of the ITCM half.

        The init routine registers each screen with three function pointers, and
        those pointers sit together in one literal pool. Finding the longest run
        of SDRAM addresses in ITCM finds the pool without knowing where the
        routine is.
        """
        body = self.img.body
        base, n = self.img.itcm_off, self.img.itcm_len
        best, run = None, []
        for k in range(0, n - 4, 4):
            v = struct.unpack_from('<I', body, base + k)[0]
            if SDRAM <= v < SDRAM + CODE_LEN and v & 1:
                run.append((SDRAM + 0, v))
            else:
                if len(run) >= 24 and (best is None or len(run) > len(best)):
                    best = run
                run = []
        if len(run) >= 24 and (best is None or len(run) > len(best)):
            best = run
        if not best:
            return []
        ptrs = [v for _a, v in best]
        # three per screen, and the pool is written back to front per screen
        out = []
        for i in range(0, len(ptrs) - 2, 3):
            out.append([ptrs[i + 2] & ~1, ptrs[i + 1] & ~1, ptrs[i] & ~1])
        return out

    # -- the layout ------------------------------------------------------
    def widgets(self, entry):
        """The rectangles a screen's handler lays out, in the order it does it.

        A widget is a `set_pos` and a `set_size` on the same object, and LVGL
        code writes them one after the other, so pairing them is a matter of
        walking the calls in address order and closing a rectangle when the
        second of the pair arrives.
        """
        fn = entry
        got = [c for c in self.calls
               if c['target'] in (self.pos, self.size)
               and self.func_of(c['at']) == fn]
        got.sort(key=lambda c: c['at'])
        out = []
        pend = None
        for c in got:
            a1 = c['args'].get(1)
            a2 = c['args'].get(2)
            if a1 is None or a2 is None:
                continue
            rec = {'at': c['at'],
                   'a': a1[0], 'a_at': a1[1], 'a_w': a1[2],
                   'b': a2[0], 'b_at': a2[1], 'b_w': a2[2]}
            if c['target'] == self.pos:
                pend = rec
            else:
                # the two calls for one object sit within a few instructions of
                # each other; anything further apart is a different object and
                # pairing them would invent a rectangle
                if pend is not None and c['at'] - pend['at'] > PAIR_SPAN:
                    pend = None
                out.append({'x': pend['a'] if pend else 0,
                            'y': pend['b'] if pend else 0,
                            'w': rec['a'], 'h': rec['b'],
                            'pos': pend, 'size': rec})
                pend = None
        return out


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_setters(path):
    L = Layout(path)
    n = collections.Counter()
    for c in L.calls:
        if 1 in c['args'] and 2 in c['args']:
            n[c['target']] += 1
    print("%d BL sites in %d bytes of interface code" % (len(L.calls), CODE_LEN))
    print()
    print("  %-12s %-7s %s" % ("target", "calls", "sample arguments"))
    for t, k in n.most_common(8):
        ex = [(c['args'][1][0], c['args'][2][0]) for c in L.calls
              if c['target'] == t and 1 in c['args'] and 2 in c['args']][:4]
        tag = ''
        if t == L.size:
            tag = '   <- set_size'
        elif t == L.pos:
            tag = '   <- set_pos'
        print("  0x%08X   %-7d %s%s" % (t, k, ex, tag))


def cmd_screens(path):
    L = Layout(path)
    reg = L.registry()
    ids = L.ids()
    print("%d screens registered%s"
          % (len(reg), "" if ids else "  (their own ids could not be read)"))
    print()
    print("  %-4s %-6s %-34s %s"
          % ("#", "id", "handlers", "widgets laid out"))
    for i, h in enumerate(reg):
        w = L.widgets(L.entry(i))
        print("  %-4d %-6s %-34s %d"
              % (i, ('0x%02X' % ids[i]) if i < len(ids) else '?',
                 ' '.join('0x%08X' % x for x in h), len(w)))


def cmd_show(path, which):
    L = Layout(path)
    reg = L.registry()
    if which >= len(reg):
        raise SystemExit("there are only %d screens" % len(reg))
    entry = L.entry(which)
    w = L.widgets(entry)
    print("screen %d, handler 0x%08X: %d widgets" % (which, entry, len(w)))
    print()
    print("  %-3s %-22s %-22s %s"
          % ("#", "x, y", "w, h", "where each constant lives"))
    for k, r in enumerate(w):
        px = "0x%08X" % r['pos']['a_at'] if r['pos'] else '-'
        py = "0x%08X" % r['pos']['b_at'] if r['pos'] else '-'
        print("  %-3d %-22s %-22s x %s  y %s  w 0x%08X  h 0x%08X"
              % (k, "%d, %d" % (r['x'], r['y']), "%d, %d" % (r['w'], r['h']),
                 px, py, r['size']['a_at'], r['size']['b_at']))
    print()
    print("  Positions are parent-relative, the way LVGL means them, so the")
    print("  wireframe `draw` makes is indicative rather than a render.")
    print("  `set --at <one of those addresses> --value N` changes the number.")


def cmd_draw(path, which, out):
    from PIL import Image, ImageDraw
    L = Layout(path)
    reg = L.registry()
    entry = L.entry(which)
    ws = L.widgets(entry)
    scale = 3
    im = Image.new('RGB', (SCREEN[0] * scale, SCREEN[1] * scale), (16, 18, 24))
    d = ImageDraw.Draw(im)
    for k, r in enumerate(ws):
        x, y, w, h = r['x'] * scale, r['y'] * scale, r['w'] * scale, r['h'] * scale
        hue = (60 + k * 37) % 360
        col = (100 + (hue % 155), 80 + ((hue * 3) % 175), 200 - (hue % 150))
        d.rectangle([x, y, x + w - 1, y + h - 1], outline=col)
        d.text((x + 3, y + 2), "%d" % k, fill=col)
    im.save(out)
    print("screen %d: %d widgets -> %s" % (which, len(ws), out))


def cmd_set(path, at, value, out):
    L = Layout(path)
    off = L.img.off(at, 4)
    old = thumb_imm.read_imm(bytes(L.img.body[off:off + 4]), 0)
    if old is None:
        raise SystemExit("0x%08X is not an immediate load" % at)
    new = thumb_imm.encode_imm(L.img.body, off, value)
    L.img.body[off:off + len(new)] = new
    chk = thumb_imm.read_imm(bytes(L.img.body[off:off + 4]), 0)
    print("0x%08X: r%d = %d -> %d" % (at, old[0], old[1], chk[1]))
    if chk[1] != value:
        raise SystemExit("re-encoding did not round trip; nothing written")
    n = L.img.save(out)
    print("wrote %s (%d bytes), CRCs restamped" % (out, n))


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
        elif rest[i] == '--at':
            opt['at'] = int(rest[i + 1], 0); i += 2
        elif rest[i] == '--value':
            opt['value'] = int(rest[i + 1], 0); i += 2
        else:
            args.append(rest[i]); i += 1
    if cmd == 'setters' and args:
        return cmd_setters(args[0])
    if cmd == 'screens' and args:
        return cmd_screens(args[0])
    if cmd == 'show' and args:
        return cmd_show(args[0], opt.get('screen', 0))
    if cmd == 'draw' and args:
        return cmd_draw(args[0], opt.get('screen', 0),
                        opt.get('out', 'screen.png'))
    if cmd == 'set' and args and 'at' in opt and 'value' in opt and 'out' in opt:
        return cmd_set(args[0], opt['at'], opt['value'], opt['out'])
    print(__doc__.strip())
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
