#!/usr/bin/env python3
"""nam_distill.py - a capture at a width the GP-150 can actually afford.

An A2 capture ships as a SlimmableContainer with two trained submodels: three
channels and eight. Valeton Suite takes the three-channel one and that is the
end of it. On clean captures that costs nothing you can hear - ESR 0.001 to
0.003 measured across ten Soldano captures - but on high-gain ones it costs
real detail: the Randall X2 captures measure 0.020 to 0.029, around -15 dB.
The eight-channel submodel would fix that and cannot run: 11776 MAC/sample is
94% of the M7 on its own, before the other ten slots exist.

Nothing forces the choice to be three or eight. The `.namb` the pedal reads
carries a **binary description of the architecture** - the channel count sits in
two bytes, `channels` at 0x5E and `bottleneck` at 0x60 - and the vendor's own
converter emits whatever width the source `.nam` asks for; a five-channel model
converts to a well-formed 20124-byte `.namb` with the checksum computed for us.
So the width is ours to choose, and the only question is what weights to put at
that width.

This trains them: the eight-channel submodel is the teacher, a wider-than-stock
student learns to reproduce its output on a DI, and the three-channel submodel
is folded into the student first so training starts from what Suite would have
shipped and can only improve on it.

    nam_distill.py cost   <file.nam>                 what each width would cost
    nam_distill.py check  <file.nam> <student.nam>   ESR against the 8-channel
    nam_distill.py train  <file.nam> [-c 4] [-o out.nam] [--minutes 20]

The forward pass is `nam2namb.WaveNet`'s, re-derived here with gradients; the
two agree to 1e-12 on the same weights, which `--selftest` checks along with the
gradients themselves against finite differences.

Nothing here talks to a device. `nam2namb.py convert` turns the result into a
`.namb`.
"""

import copy
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import numpy as np
except ImportError:                                       # pragma: no cover
    np = None

import nam2namb as N

CORE_HZ = 600e6


# --------------------------------------------------------------------------
# the model, as flat tensors
# --------------------------------------------------------------------------

def layer_of(model):
    las = model['config']['layers']
    if len(las) != 1:
        raise SystemExit("this handles one layer array; found %d" % len(las))
    return las[0]


def nweights(la):
    """How many weights a config of this shape needs, in NAM's own order."""
    c = int(la['channels'])
    n = c * int(la['input_size'])
    for k in la['kernel_sizes']:
        n += c * c * int(k) + c + c * int(la['condition_size']) + c * c + c
    h = la['head']
    n += int(h['out_channels']) * c * int(h['kernel_size'])
    if h.get('bias'):
        n += int(h['out_channels'])
    return n + 1                                   # head_scale rides at the end


def unpack(model):
    """Weights -> tensors, in the order nam2namb.WaveNet reads them."""
    la = layer_of(model)
    w = np.asarray(model['weights'], dtype=np.float64)
    c = int(la['channels'])
    ins, cond = int(la['input_size']), int(la['condition_size'])
    i = [0]

    def take(n, shape=None):
        j = i[0]
        i[0] = j + n
        v = w[j:j + n]
        return v if shape is None else v.reshape(shape)

    P = {'c': c, 'rech': take(c * ins, (c, ins)), 'layers': []}
    for k, d, act in zip(la['kernel_sizes'], la['dilations'], la['activation']):
        k, d = int(k), int(d)
        P['layers'].append({
            'cw': take(c * c * k, (c, c, k)), 'cb': take(c),
            'mw': take(c * cond, (c, cond)),
            'ow': take(c * c, (c, c)), 'ob': take(c),
            'd': d, 'k': k,
            'slope': float(act.get('negative_slope', 0.01)),
        })
    h = la['head']
    ho, hk = int(h['out_channels']), int(h['kernel_size'])
    P['hw'] = take(ho * c * hk, (ho, c, hk))
    P['hb'] = take(ho) if h.get('bias') else np.zeros(ho)
    tail = float(take(1)[0])
    # the weight stream ends with a rounded copy of head_scale; the config
    # holds the exact one, and that is the value nam2namb runs with
    P['head_scale'] = float(model['config'].get('head_scale', tail))
    if i[0] != len(w):
        raise SystemExit("weight layout mismatch: read %d of %d" % (i[0], len(w)))
    return P


def pack(P, model):
    """Tensors -> a weight list, same order, ready for a .nam."""
    out = [P['rech'].ravel()]
    for L in P['layers']:
        out += [L['cw'].ravel(), L['cb'], L['mw'].ravel(), L['ow'].ravel(), L['ob']]
    out += [P['hw'].ravel(), P['hb'], np.array([P['head_scale']])]  # noqa
    v = np.concatenate(out)
    want = nweights(layer_of(model))
    if len(v) != want:
        raise SystemExit("packed %d weights, config wants %d" % (len(v), want))
    return v


def receptive(la):
    return 1 + sum((int(k) - 1) * int(d)
                   for k, d in zip(la['kernel_sizes'], la['dilations'])) \
             + int(la['head']['kernel_size']) - 1


def macs(la):
    """Multiply-accumulates per output sample."""
    c = int(la['channels'])
    n = c * int(la['input_size'])
    for k in la['kernel_sizes']:
        n += c * c * int(k) + c * int(la['condition_size']) + c * c
    h = la['head']
    n += int(h['out_channels']) * c * int(h['kernel_size'])
    return n


# --------------------------------------------------------------------------
# forward and backward
# --------------------------------------------------------------------------

def _conv(h, w, b, d):
    c_out, _, k = w.shape
    n = h.shape[1]
    out = np.repeat(b[:, None], n, 1)
    for tap in range(k):
        back = (k - 1 - tap) * d
        if back >= n:
            continue
        if back:
            out[:, back:] += w[:, :, tap] @ h[:, :n - back]
        else:
            out += w[:, :, tap] @ h
    return out


def _conv_back(g, h, w, d, need_h=True):
    """Gradients of _conv: (dW, db, dh)."""
    c_out, c_in, k = w.shape
    n = h.shape[1]
    dw = np.zeros_like(w)
    dh = np.zeros_like(h) if need_h else None
    for tap in range(k):
        back = (k - 1 - tap) * d
        if back >= n:
            continue
        gs = g[:, back:] if back else g
        hs = h[:, :n - back] if back else h
        dw[:, :, tap] = gs @ hs.T
        if need_h:
            if back:
                dh[:, :n - back] += w[:, :, tap].T @ gs
            else:
                dh += w[:, :, tap].T @ gs
    return dw, g.sum(1), dh


def forward(P, x, keep=False):
    cond = x[None, :]
    h = P['rech'] @ cond
    head = np.zeros((P['c'], len(x)))
    cache = [] if keep else None
    for L in P['layers']:
        pre = _conv(h, L['cw'], L['cb'], L['d']) + L['mw'] @ cond
        z = np.where(pre >= 0.0, pre, pre * L['slope'])
        if keep:
            cache.append((h, pre, z))
        head = head + z
        h = h + (L['ow'] @ z + L['ob'][:, None])
    y = _conv(head, P['hw'], P['hb'], 1)
    out = P['head_scale'] * y[0]
    if keep:
        return out, (cond, head, y, cache)
    return out


def backward(P, x, cache, gout):
    """d(loss)/d(params) given d(loss)/d(output)."""
    cond, head, y, layers = cache
    G = {'layers': [{} for _ in P['layers']]}
    G['head_scale'] = float((gout * y[0]).sum())
    gy = (P['head_scale'] * gout)[None, :]
    G['hw'], G['hb'], ghead = _conv_back(gy, head, P['hw'], 1)
    gh = np.zeros_like(head)                        # gradient flowing into h
    for i in range(len(P['layers']) - 1, -1, -1):
        L = P['layers'][i]
        h, pre, z = layers[i]
        # h_out = h + ow @ z + ob   (gh is d/d h_out)
        gz = L['ow'].T @ gh + ghead
        G['layers'][i]['ow'] = gh @ z.T
        G['layers'][i]['ob'] = gh.sum(1)
        gpre = np.where(pre >= 0.0, gz, gz * L['slope'])
        dw, db, dh = _conv_back(gpre, h, L['cw'], L['d'])
        G['layers'][i]['cw'] = dw
        G['layers'][i]['cb'] = db
        G['layers'][i]['mw'] = gpre @ cond.T
        gh = gh + dh                                # h feeds the conv and the skip
    G['rech'] = gh @ cond.T
    return G


def flat(P, key='w'):
    """Every trainable tensor, as a list, so the optimiser can be generic."""
    out = [P['rech']]
    for L in P['layers']:
        out += [L['cw'], L['cb'], L['mw'], L['ow'], L['ob']]
    out += [P['hw'], P['hb']]
    return out


def flat_g(G):
    out = [G['rech']]
    for L in G['layers']:
        out += [L['cw'], L['cb'], L['mw'], L['ow'], L['ob']]
    out += [G['hw'], G['hb']]
    return out


# --------------------------------------------------------------------------
# widening
# --------------------------------------------------------------------------

def widen(model, c_new):
    """A wider model that starts as the narrow one.

    The extra channels are zeroed on every path that leaves them, so the new
    model's output is identical to the old one's; the extra rows are seeded with
    small noise so the gradients have somewhere to go.
    """
    la = layer_of(model)
    c_old = int(la['channels'])
    if c_new < c_old:
        raise SystemExit("widen only goes up: %d -> %d" % (c_old, c_new))
    P = unpack(model)
    rng = np.random.default_rng(0)
    eps = 1e-3

    def grow(a, shape, seed_axes=()):
        b = np.zeros(shape)
        sl = tuple(slice(0, s) for s in a.shape)
        b[sl] = a
        for ax in seed_axes:
            idx = [slice(None)] * len(shape)
            idx[ax] = slice(a.shape[ax], shape[ax])
            b[tuple(idx)] += eps * rng.standard_normal(b[tuple(idx)].shape)
        return b

    Q = {'c': c_new, 'head_scale': P['head_scale'], 'layers': []}
    Q['rech'] = grow(P['rech'], (c_new, P['rech'].shape[1]), (0,))
    for L in P['layers']:
        Q['layers'].append({
            'cw': grow(L['cw'], (c_new, c_new, L['k']), (0,)),
            'cb': grow(L['cb'], (c_new,)),
            'mw': grow(L['mw'], (c_new, L['mw'].shape[1]), (0,)),
            # new channels must not feed the old ones yet: ow's new columns
            # stay zero, only its new rows are seeded
            'ow': grow(L['ow'], (c_new, c_new), (0,)),
            'ob': grow(L['ob'], (c_new,)),
            'd': L['d'], 'k': L['k'], 'slope': L['slope'],
        })
    Q['hw'] = grow(P['hw'], (P['hw'].shape[0], c_new, P['hw'].shape[2]))
    Q['hb'] = P['hb'].copy()

    m = copy.deepcopy(model)
    lb = layer_of(m)
    lb['channels'] = c_new
    if 'bottleneck' in lb and lb['bottleneck'] is not None:
        lb['bottleneck'] = c_new
    m['weights'] = list(pack(Q, m))
    return m, Q


# --------------------------------------------------------------------------
# training
# --------------------------------------------------------------------------

def teacher_output(nam, x):
    subs = N.submodels(nam)
    big = subs[-1][1]
    return N.WaveNet(big).process(x), big


def train(nam, c_new, x, minutes=20.0, window=6000, batch=4, lr=3e-4, seed=0,
          report=print, should_stop=None):
    subs = N.submodels(nam)
    small = subs[0][1]
    la = layer_of(small)
    rf = receptive(la)
    report("  teacher: %d channels; student: %d; receptive field %d samples"
           % (int(layer_of(subs[-1][1])['channels']), c_new, rf))
    t0 = time.time()
    y_t = N.WaveNet(subs[-1][1]).process(x)
    report("  teacher rendered %d samples in %.1f s" % (len(x), time.time() - t0))

    model, P = widen(small, c_new)
    tensors = flat(P)
    m = [np.zeros_like(t) for t in tensors]
    v = [np.zeros_like(t) for t in tensors]
    rng = np.random.default_rng(seed)
    b1, b2, eps = 0.9, 0.999, 1e-8

    # a gain that matches the student's level to the teacher's, refreshed rarely
    def esr_full():
        y = forward(P, x)
        return N.esr(y[rf:], y_t[rf:])

    e0 = esr_full()
    report("  start ESR %.5f (%.1f dB) - this is what Suite would ship"
           % (e0, 10 * np.log10(max(e0, 1e-12))))
    best = e0
    best_w = [t.copy() for t in tensors]
    step = 0
    t_start = time.time()
    total = minutes * 60.0
    deadline = t_start + total
    span = len(x) - window - rf - 1
    while time.time() < deadline:
        if should_stop is not None and should_stop():
            report("  stopped on request")
            break
        step += 1
        gs = None
        loss = 0.0
        for _ in range(batch):
            i0 = int(rng.integers(0, span))
            seg = x[i0:i0 + rf + window]
            tgt = y_t[i0 + rf:i0 + rf + window]
            out, cache = forward(P, seg, keep=True)
            err = out[rf:] - tgt
            loss += float((err * err).mean())
            g = np.zeros_like(out)
            g[rf:] = 2.0 * err / window
            G = backward(P, seg, cache, g)
            fg = flat_g(G)
            gs = fg if gs is None else [a + b for a, b in zip(gs, fg)]
        # a fixed step keeps overshooting once the model is close - the run
        # that ended at ESR 0.0059 was bouncing between 0.016 and 0.024 on its
        # last steps. Decay to a tenth over the run and it settles.
        frac = min(1.0, (time.time() - t_start) / max(total, 1e-9))
        lr_t = lr * (0.1 ** frac)
        for j, (t, g) in enumerate(zip(tensors, gs)):
            g = g / batch
            m[j] = b1 * m[j] + (1 - b1) * g
            v[j] = b2 * v[j] + (1 - b2) * (g * g)
            mh = m[j] / (1 - b1 ** step)
            vh = v[j] / (1 - b2 ** step)
            t -= lr_t * mh / (np.sqrt(vh) + eps)
        if step % 50 == 0:
            e = esr_full()
            if e < best:
                best = e
                best_w = [t.copy() for t in tensors]
            report("    step %-5d lr %.1e  loss %.3e   ESR %.5f (%.1f dB)%s"
                   % (step, lr_t, loss / batch, e, 10 * np.log10(max(e, 1e-12)),
                      '  best' if e == best else ''))
    for t, b in zip(tensors, best_w):
        t[...] = b
    e = esr_full()
    report("  finished after %d steps: ESR %.5f (%.1f dB), started at %.5f"
           % (step, e, 10 * np.log10(max(e, 1e-12)), e0))
    model['weights'] = [float(w) for w in pack(P, model)]
    return model, e0, e


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_cost(path):
    nam = N.load(path)
    subs = N.submodels(nam)
    la = layer_of(subs[0][1])
    print(os.path.basename(path))
    print("  %d layers, receptive field %d samples (%.0f ms at 48 kHz)"
          % (len(la['kernel_sizes']), receptive(la), receptive(la) / 48.0))
    print()
    print("  %-9s %-10s %-9s %-9s %s"
          % ("channels", "weights", "MAC/samp", "namb", "M7 at 48 kHz"))
    for c in range(3, 9):
        lb = copy.deepcopy(la)
        lb['channels'] = c
        n = nweights(lb)
        mm = macs(lb)
        load = mm * 48000.0 / CORE_HZ
        stock = ' <- Suite ships this' if c == 3 else (
                ' <- will not fit' if load > 0.6 else '')
        print("  %-9d %-10d %-9d %-9s %.0f%%%s"
              % (c, n, mm, "%.1f KB" % ((n * 4 + 496) / 1024.0), 100 * load, stock))
    print()
    print("  The pedal runs a whole signal chain besides the amp block; the")
    print("  GP-200 project measured its own amp engine at 22% of one audio")
    print("  block, so a student anywhere near that is in familiar territory.")


def cmd_check(path, student):
    nam = N.load(path)
    x = N.read_di(N.default_di(), 48000, 10.0)
    subs = N.submodels(nam)
    y_t = N.WaveNet(subs[-1][1]).process(x)
    rf = receptive(layer_of(subs[0][1]))
    rows = [('Suite, 3 channels', N.WaveNet(subs[0][1]).process(x))]
    st = N.load(student)
    rows.append(('%s, %d channels' % (os.path.basename(student),
                                      int(layer_of(st)['channels'])),
                 N.WaveNet(st).process(x)))
    print("  against the 8-channel submodel, %d s of DI" % 10)
    for name, y in rows:
        e = N.esr(y[rf:], y_t[rf:])
        print("    %-34s ESR %.5f  (%.1f dB)"
              % (name, e, 10 * np.log10(max(e, 1e-12))))


def cmd_train(path, c_new, out, minutes, seconds, window, batch, lr):
    return run_train(path, c_new, out, minutes, seconds, window, batch, lr)


def run_train(path, c_new, out, minutes=20.0, seconds=20.0, window=6000,
              batch=4, lr=3e-4, report=print, should_stop=None):
    nam = N.load(path)
    di = N.default_di()
    if di is None:
        raise SystemExit("no DI wav found; Valeton Suite ships the one the "
                         "vendor's converter uses")
    x = N.read_di(di, 48000, seconds)
    report("%s -> %d channels" % (os.path.basename(path), c_new))
    report("  DI %s, %.0f s" % (os.path.basename(di), len(x) / 48000.0))
    model, e0, e1 = train(nam, c_new, x, minutes=minutes, window=window,
                          batch=batch, lr=lr, report=report,
                          should_stop=should_stop)
    if out is None:
        out = os.path.splitext(path)[0] + '-%dch.nam' % c_new
    with open(out, 'w', encoding='utf-8') as fh:
        json.dump(model, fh)
    report("  wrote %s (%d weights)" % (out, len(model['weights'])))
    report("  ESR %.5f -> %.5f  (%.1f dB -> %.1f dB)"
           % (e0, e1, 10 * np.log10(max(e0, 1e-12)), 10 * np.log10(max(e1, 1e-12))))
    return {'out': out, 'esr_before': e0, 'esr_after': e1,
            'weights': len(model['weights']), 'channels': c_new}


def cmd_selftest(path):
    """The forward pass matches nam2namb's, and the gradients match finite
    differences. Both on the real model, not a toy."""
    nam = N.load(path)
    small = N.submodels(nam)[0][1]
    x = N.read_di(N.default_di(), 48000, 0.02)
    P = unpack(small)
    a = forward(P, x)
    b = N.WaveNet(small).process(x)
    d = float(np.abs(a - b).max())
    print("  forward vs nam2namb.WaveNet: max |diff| = %.3g   %s"
          % (d, "ok" if d < 1e-12 else "MISMATCH"))

    out, cache = forward(P, x, keep=True)
    g = np.zeros_like(out)
    g[:] = 2.0 * out / len(out)
    G = backward(P, x, cache, g)
    ts, gsv = flat(P), flat_g(G)
    rng = np.random.default_rng(3)
    worst = 0.0
    for t, gg in zip(ts, gsv):
        for _ in range(2):
            idx = tuple(int(rng.integers(0, s)) for s in t.shape)
            old = t[idx]
            h = 1e-6 * max(1.0, abs(old))
            t[idx] = old + h
            lp = float((forward(P, x) ** 2).mean())
            t[idx] = old - h
            lm = float((forward(P, x) ** 2).mean())
            t[idx] = old
            num = (lp - lm) / (2 * h)
            den = max(abs(num), abs(gg[idx]), 1e-9)
            worst = max(worst, abs(num - gg[idx]) / den)
    print("  gradients vs finite differences: worst relative error %.3g   %s"
          % (worst, "ok" if worst < 5e-4 else "MISMATCH"))

    m2, Q = widen(small, int(P['c']) + 2)
    y2 = forward(Q, x)
    d2 = float(np.abs(y2 - b).max())
    print("  widening is output-preserving: max |diff| = %.3g   %s"
          % (d2, "ok" if d2 < 1e-12 else "MISMATCH"))
    n = nweights(layer_of(m2))
    print("  widened weight count %d, config wants %d   %s"
          % (len(m2['weights']), n, "ok" if len(m2['weights']) == n else "MISMATCH"))
    return 0


def main(argv):
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    if np is None:
        raise SystemExit("numpy is needed")
    if not argv:
        print(__doc__.strip())
        return 1
    cmd, rest = argv[0], argv[1:]
    opt = {}
    args = []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ('-c', '--channels'):
            opt['c'] = int(rest[i + 1]); i += 2
        elif a in ('-o', '--out'):
            opt['out'] = rest[i + 1]; i += 2
        elif a == '--minutes':
            opt['minutes'] = float(rest[i + 1]); i += 2
        elif a == '--seconds':
            opt['seconds'] = float(rest[i + 1]); i += 2
        elif a == '--window':
            opt['window'] = int(rest[i + 1]); i += 2
        elif a == '--batch':
            opt['batch'] = int(rest[i + 1]); i += 2
        elif a == '--lr':
            opt['lr'] = float(rest[i + 1]); i += 2
        else:
            args.append(a); i += 1
    if cmd == 'cost' and args:
        return cmd_cost(args[0])
    if cmd == 'check' and len(args) == 2:
        return cmd_check(args[0], args[1])
    if cmd == 'selftest' and args:
        return cmd_selftest(args[0])
    if cmd == 'train' and args:
        return cmd_train(args[0], opt.get('c', 4), opt.get('out'),
                         opt.get('minutes', 20.0), opt.get('seconds', 20.0),
                         opt.get('window', 6000), opt.get('batch', 4),
                         opt.get('lr', 3e-4))
    print(__doc__.strip())
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
