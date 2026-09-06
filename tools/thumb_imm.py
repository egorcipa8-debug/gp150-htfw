#!/usr/bin/env python3
"""thumb_imm.py - the constants a Thumb-2 function hands to its calls.

The GP-150's interface is LVGL, and an LVGL screen is built by calling setters
with plain numbers: `set_size(obj, 320, 240)`, `set_pos(obj, 10, 12)`. Those
numbers are **immediates in the instruction stream**, so the layout of every
screen can be read - and changed - without understanding a line of the code
around them.

This is the part that reads and writes them: a decoder for the handful of Thumb
instructions that put a constant in a register, a scanner for `BL`, and an
encoder that can put a different constant back **only where it fits the same
instruction**, because an instruction cannot change length in place.

    MOVS  Rd,#imm8      2 bytes, Rd < 8, 0..255
    MOV.W Rd,#imm12     4 bytes, whatever ThumbExpandImm can make
    MOVW  Rd,#imm16     4 bytes, 0..65535
    MVN   Rd,#imm12     4 bytes, the bitwise-not of the above

Nothing here knows what the numbers mean; `lv_layout.py` is what gives them
names.
"""

import struct

__all__ = ['calls', 'expand_imm', 'read_imm', 'encode_imm']


def _u16(b, i):
    return struct.unpack_from('<H', b, i)[0]


def expand_imm(imm12):
    """ARM's ThumbExpandImm, which is how a 12-bit field spells a 32-bit value."""
    if (imm12 >> 10) == 0:
        code = (imm12 >> 8) & 3
        v = imm12 & 0xFF
        if code == 0:
            return v
        if code == 1:
            return (v << 16) | v
        if code == 2:
            return (v << 24) | (v << 8)
        return (v << 24) | (v << 16) | (v << 8) | v
    un = 0x80 | (imm12 & 0x7F)
    rot = (imm12 >> 7) & 0x1F
    return ((un >> rot) | (un << (32 - rot))) & 0xFFFFFFFF


def _pack_imm12(value):
    """The inverse, or None when the value simply cannot be spelled."""
    if value <= 0xFF:
        return value
    for code, pat in ((1, lambda v: (v << 16) | v),
                      (2, lambda v: (v << 24) | (v << 8)),
                      (3, lambda v: (v << 24) | (v << 16) | (v << 8) | v)):
        for v in range(1, 256):
            if pat(v) == value:
                return (code << 8) | v
    for rot in range(1, 32):
        un = ((value << rot) | (value >> (32 - rot))) & 0xFFFFFFFF
        if un & 0x80 and un <= 0xFF:
            return (rot << 7) | (un & 0x7F)
    return None


def read_imm(b, i):
    """(register, value, width) if `b[i:]` loads a constant, else None."""
    w = _u16(b, i)
    if (w & 0xF800) == 0x2000:                       # MOVS Rd,#imm8
        return (w >> 8) & 7, w & 0xFF, 2
    if i + 4 > len(b):
        return None
    w2 = _u16(b, i + 2)
    if w2 & 0x8000:                                  # not a data-processing T3
        return None
    rd = (w2 >> 8) & 0xF
    imm = ((w >> 10) & 1) << 11 | ((w2 >> 12) & 7) << 8 | (w2 & 0xFF)
    if (w & 0xFBEF) == 0xF04F:                       # MOV.W Rd,#imm12
        return rd, expand_imm(imm), 4
    if (w & 0xFBEF) == 0xF06F:                       # MVN Rd,#imm12
        return rd, (~expand_imm(imm)) & 0xFFFFFFFF, 4
    if (w & 0xFBF0) == 0xF240:                       # MOVW Rd,#imm16
        return rd, ((w & 0xF) << 12) | imm, 4
    return None


def encode_imm(b, i, value):
    """Rewrite the constant at `b[i:]`, keeping the instruction's own shape.

    Returns the new bytes, or raises if the value will not fit what is there.
    A wider value would need a longer instruction, and there is nowhere to put
    the extra bytes without moving everything after them.
    """
    cur = read_imm(bytes(b[i:i + 4]), 0)
    if cur is None:
        raise ValueError("no immediate load at that address")
    rd, _old, width = cur
    w = _u16(b, i)
    if width == 2:
        if not 0 <= value <= 0xFF:
            raise ValueError("MOVS holds 0..255; %d does not fit" % value)
        return struct.pack('<H', (w & 0xFF00) | value)
    w2 = _u16(b, i + 2)
    if (w & 0xFBF0) == 0xF240:                       # MOVW
        if not 0 <= value <= 0xFFFF:
            raise ValueError("MOVW holds 0..65535; %d does not fit" % value)
        imm4 = (value >> 12) & 0xF
        i1 = (value >> 11) & 1
        imm3 = (value >> 8) & 7
        imm8 = value & 0xFF
        nw = (w & 0xFBF0) | imm4 | (i1 << 10)
        nw2 = (w2 & 0x8F00) | (imm3 << 12) | imm8
        return struct.pack('<HH', nw, nw2)
    want = value if (w & 0xFBEF) == 0xF04F else (~value) & 0xFFFFFFFF
    p = _pack_imm12(want & 0xFFFFFFFF)
    if p is None:
        raise ValueError("%d cannot be spelled as a Thumb modified immediate"
                         % value)
    nw = (w & 0xFBEF) | (((p >> 11) & 1) << 10)
    nw2 = (w2 & 0x8F00) | (((p >> 8) & 7) << 12) | (p & 0xFF)
    return struct.pack('<HH', nw, nw2)


def _bl(b, i):
    """Target of the BL at `b[i:]`, relative to the instruction's address."""
    w = _u16(b, i)
    if (w & 0xF800) != 0xF000 or i + 4 > len(b):
        return None
    w2 = _u16(b, i + 2)
    if (w2 & 0xD000) != 0xD000:                      # BL, not BLX or a branch
        return None
    s = (w >> 10) & 1
    j1 = (w2 >> 13) & 1
    j2 = (w2 >> 11) & 1
    i1 = 1 - (j1 ^ s)
    i2 = 1 - (j2 ^ s)
    off = (s << 24) | (i1 << 23) | (i2 << 22) | ((w & 0x3FF) << 12) | \
          ((w2 & 0x7FF) << 1)
    if s:
        off -= 1 << 25
    return off + 4


def calls(code, base, lookback=12):
    """Every BL, with whatever constants were in r0-r3 when it was reached.

    Walks forward through the halfword stream, remembering the last few
    immediate loads, and at each BL reports the registers whose value is known.
    A register written by anything else - a load, a move, arithmetic - is
    forgotten, so what comes back is the arguments that really are constants.
    """
    out = []
    regs = {}
    i = 0
    n = len(code) - 4
    while i < n:
        imm = read_imm(code, i)
        if imm is not None:
            rd, val, width = imm
            if rd < 4:
                regs[rd] = (val, base + i, width)
            i += width
            continue
        w = _u16(code, i)
        tgt = _bl(code, i)
        if tgt is not None:
            out.append({'at': base + i, 'target': base + i + tgt,
                        'args': dict(regs)})
            regs = {}
            i += 4
            continue
        # anything that writes a low register with something we cannot follow
        if (w & 0xF800) == 0x4800:                   # LDR Rd,[pc,#imm]
            regs.pop((w >> 8) & 7, None)
        elif (w & 0xFE00) in (0x1800, 0x1A00):       # ADD/SUB register
            regs.pop(w & 7, None)
        elif (w & 0xF800) in (0x3000, 0x3800):       # ADDS/SUBS Rd,#imm8
            regs.pop((w >> 8) & 7, None)
        elif (w & 0xFC00) == 0x4600:                 # MOV Rd,Rm
            regs.pop((w & 7) | ((w >> 4) & 8), None)
        elif (w & 0xF000) in (0x5000, 0x6000, 0x7000, 0x9000):   # loads
            regs.pop(w & 7, None)
        elif (w & 0xE000) == 0xE000 and (w & 0xF800) != 0xE000:
            i += 4                                   # a 32-bit instruction
            regs.clear()
            continue
        i += 2
    return out
