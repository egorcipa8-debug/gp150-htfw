#!/usr/bin/env python3
"""lv_trace.py - what a screen builder actually does, argument by argument.

`thumb_imm.py` reads the constants a call is given. That is enough to move a
box, and not enough to draw one: to render a screen you need to know *which*
object each call is about, who its parent is, and what was put inside it - and
all three of those travel through registers and struct slots rather than
through immediates.

The code is stereotyped enough to follow. Every widget on a screen is built the
same way:

```
    bl   lv_obj_create          ; r0 = parent, or nothing for the screen itself
    str  r0,[r4,#0x2c]          ; the handle goes in a slot of the screen struct
    ldr  r0,[r4,#0x2c]          ; and comes back out for each setter
    movs r1,#0
    movs r2,#44
    bl   set_pos
```

So this tracks four kinds of value in the low registers - a constant, a word
from the literal pool, the handle a call returned, and the handle held in a
struct slot - through the loads, stores and moves that shuffle them. What comes
back is a list of calls whose arguments are named rather than numeric, which is
what `lv_screen.py` turns into a tree.

Literal-pool loads matter as much as immediates: a string to put in a label and
a picture to put in an image are both `ldr rN,[pc,#imm]`, and the pool is right
there in the file.
"""

import struct

import thumb_imm

__all__ = ['trace', 'Val']


class Val(object):
    """What a register holds, as far as we can tell.

    `kind` is 'imm' for a constant, 'lit' for a word fetched from the literal
    pool, 'ret' for whatever a call returned, and 'slot' for a handle living in
    a struct slot. Anything else is not represented at all - the register is
    simply forgotten, so a caller never has to wonder whether a value is real.
    """

    __slots__ = ('kind', 'v', 'at', 'width', 'base', 'off', 'tag')

    def __init__(self, kind, v=None, at=None, width=0, base=None, off=None,
                 tag=None):
        self.kind, self.v, self.at, self.width = kind, v, at, width
        self.base, self.off = base, off
        # Which function's namespace this value belongs to. A helper receives
        # its parent as an argument, and that handle was named by the caller -
        # tagging it with the callee's name would invent an object nobody made.
        self.tag = tag

    def retag(self, tag):
        return Val(self.kind, self.v, self.at, self.width, self.base,
                   self.off, tag)

    def key(self):
        """What identifies the same object across two mentions."""
        if self.kind == 'slot':
            return ('slot', self.base, self.off)
        if self.kind == 'ret':
            return ('ret', self.v)
        return None

    def __repr__(self):
        if self.kind in ('imm', 'lit'):
            return '%s(0x%X)' % (self.kind, self.v)
        if self.kind == 'slot':
            return 'slot(r%d+0x%X)' % (self.base, self.off)
        return 'ret(%s)' % (self.v,)


def _u16(b, i):
    return struct.unpack_from('<H', b, i)[0]


def trace(code, base, start, end, init=None):
    """Follow one function, returning its calls with symbolic arguments.

    `start` and `end` are addresses inside `code`, which begins at `base`.
    Every call comes back as {'at', 'target', 'args': {reg: Val}, 'ret': Val},
    and a store of a call's result into a struct slot is attached to that call
    as 'stored', because that is how a widget gets a name.
    """
    out = []
    # a helper receives its parent as an argument, so tracing it with empty
    # registers loses the one thing that connects its widgets to the screen
    regs = dict(init) if init else {}
    i = start - base
    stop = end - base
    n = len(code)
    while i < min(stop, n - 2):
        w = _u16(code, i)

        # a constant
        imm = thumb_imm.read_imm(code, i)
        if imm is not None:
            rd, val, width = imm
            regs[rd] = Val('imm', val, base + i, width)
            i += width
            continue

        # a word from the literal pool, which is where strings, pictures and
        # colours come from
        if (w & 0xF800) == 0x4800:
            rd = (w >> 8) & 7
            at = (((base + i + 4) & ~3) - base) + (w & 0xFF) * 4
            if 0 <= at <= n - 4:
                regs[rd] = Val('lit', struct.unpack_from('<I', code, at)[0],
                               base + at, 4)
            else:
                regs.pop(rd, None)
            i += 2
            continue

        # ldr rD,[rB,#imm5*4] - a handle coming out of a struct slot
        if (w & 0xF800) == 0x6800:
            rd, rb, off = w & 7, (w >> 3) & 7, ((w >> 6) & 0x1F) * 4
            regs[rd] = Val('slot', base=rb, off=off)
            i += 2
            continue

        # str rS,[rB,#imm5*4] - and a handle going into one
        if (w & 0xF800) == 0x6000:
            rs, rb, off = w & 7, (w >> 3) & 7, ((w >> 6) & 0x1F) * 4
            src = regs.get(rs)
            if src is not None and src.kind == 'ret' and out:
                for c in reversed(out):
                    if c['ret'] is src:
                        c['stored'] = (rb, off)
                        break
            i += 2
            continue

        # the wide forms, for offsets a five-bit field cannot reach
        if i + 4 <= n and (w & 0xFFF0) == 0xF8D0:                # ldr.w
            w2 = _u16(code, i + 2)
            rd, rb, off = (w2 >> 12) & 0xF, w & 0xF, w2 & 0xFFF
            if rd < 8 and rb < 8:
                regs[rd] = Val('slot', base=rb, off=off)
            elif rd < 8:
                regs.pop(rd, None)
            i += 4
            continue
        if i + 4 <= n and (w & 0xFFF0) == 0xF8C0:                # str.w
            w2 = _u16(code, i + 2)
            rs, rb, off = (w2 >> 12) & 0xF, w & 0xF, w2 & 0xFFF
            src = regs.get(rs)
            if src is not None and src.kind == 'ret' and out:
                for c in reversed(out):
                    if c['ret'] is src:
                        c['stored'] = (rb, off)
                        break
            i += 4
            continue

        # mov rD,rS - and the high registers matter, because a builder that
        # has more than a couple of widgets in flight parks their handles in
        # r8..r11 rather than in the screen struct
        if (w & 0xFF00) == 0x4600:
            rd = (w & 7) | ((w >> 4) & 8)
            rs = (w >> 3) & 0xF
            if rs in regs:
                regs[rd] = regs[rs]
            else:
                regs.pop(rd, None)
            i += 2
            continue

        tgt = thumb_imm._bl(code, i)
        if tgt is not None:
            ret = Val('ret', len(out))
            out.append({'at': base + i, 'target': base + i + tgt,
                        'args': {r: v for r, v in regs.items() if r < 4},
                        'ret': ret, 'stored': None})
            # r4..r11 are callee-saved, so a call does not disturb a handle
            # parked in one - which is the whole reason a builder puts it there
            regs = {r: v for r, v in regs.items() if 4 <= r <= 11}
            regs[0] = ret
            i += 4
            continue

        if (w & 0xF800) in (0xE800, 0xF000, 0xF800):
            hit = thumb_imm.wide_writes(w, _u16(code, i + 2))
            if hit == 'all':
                regs.clear()
            else:
                regs.pop(hit, None)
            i += 4
            continue

        hit = thumb_imm.writes(w)
        if hit == 'all':
            regs.clear()
        elif hit is not None:
            regs.pop(hit, None)
        i += 2
    return out
