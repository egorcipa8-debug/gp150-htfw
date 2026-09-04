#!/usr/bin/env python3
"""nam2namb.py - fit a NAM capture to what the GP-150 can actually run.

The GP-150 does not read `.nam`. Valeton Suite converts a capture into a
**`.namb`** - a binary NAM, magic `BMAN` - and that is what reaches the pedal.
The conversion lives in Suite's own `assets/5868USB.dll` and is exported as
plain C, so it can be driven from here:

    const char *convertNamToNambAtPath(const char *in, const char *out,
                                       double slim);
    const char *convertNamToNambWithSlim(const char *in, double slim);
    const char *convertNamToNamb(const char *in);
    const char *getLastNamToNambError(void);

The captures people download today (TONE3000, NAM 0.7.0) are
**SlimmableContainers**: one file holding several trained submodels of the same
amp at different widths, each tagged with a `max_value`. `slim` picks one - the
smallest submodel whose `max_value` is above the factor. That is the whole of
the vendor's "optimisation", and it tells you nothing about what the choice
costs you, which is what this tool adds:

  * what each submodel costs to run - multiply-accumulates per sample, and what
    that is as a share of the pedal's Cortex-M7 budget at 48 kHz;
  * what each submodel costs in quality - ESR against the largest submodel in
    the same file, measured by running both, so "the small one is fine here" is
    a measurement rather than a hope;
  * the conversion itself, one file or a whole folder.

The WaveNet forward pass is implemented here in numpy. It is not a guess: the
weight layout it assumes reproduces the exact weight count of every submodel in
a file (1871 for a 3-channel model, 12146 for an 8-channel one, both to the
byte), and the two independently trained submodels of one capture come out of it
correlated at 0.996 - which they only can be if both are being read correctly.

    nam2namb.py info    <file.nam>                  submodels, cost, sizes
    nam2namb.py check   <file.nam> [--wav di.wav]   ESR of each submodel
    nam2namb.py convert <file.nam> [-o out.namb] [--slim F]
    nam2namb.py batch   <dir> [-o outdir] [--slim F]
    nam2namb.py namb    <file.namb>                 header of a converted file
"""

import ctypes
import json
import os
import struct
import sys
import wave

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import numpy as np
except ImportError:                                   # pragma: no cover
    np = None

NAMB_MAGIC = b'BMAN'
# The pedal runs an i.MX RT1064 - a 600 MHz Cortex-M7 with a single-precision
# FPU that retires roughly one multiply-accumulate per cycle. The amp model is
# not the only thing on it, so treat anything past a third of that as "no".
CORE_HZ = 600e6
SAMPLE_RATE = 48000.0


# --------------------------------------------------------------------------
# the capture
# --------------------------------------------------------------------------

def load(path):
    with open(path, 'r', encoding='utf-8') as fh:
        return json.load(fh)


def submodels(nam):
    """[(max_value, model)] - a plain capture is one submodel with no limit."""
    if nam.get('architecture') == 'SlimmableContainer':
        return [(float(s.get('max_value', 1.0)), s['model'])
                for s in nam['config']['submodels']]
    return [(1.0, nam)]


def pick(nam, slim):
    """The submodel Suite's converter would choose for this slim factor: the
    first whose max_value is at or above it."""
    subs = submodels(nam)
    for mv, m in subs:
        if slim <= mv:
            return mv, m
    return subs[-1]


def cost(model):
    """Multiply-accumulates per output sample, plus the shape of the model."""
    cfg = model['config']
    macs = 0
    params = 0
    receptive = 1
    chans = []
    layers = 0
    for la in cfg['layers']:
        c = int(la['channels'])
        chans.append(c)
        ins = int(la['input_size'])
        cond = int(la['condition_size'])
        params += c * ins
        macs += c * ins
        for k, d in zip(la['kernel_sizes'], la['dilations']):
            layers += 1
            params += c * c * k + c + c * cond + c * c + c
            macs += c * c * k + c * cond + c * c
            receptive += (int(k) - 1) * int(d)
        hd = la['head']
        hk, ho = int(hd['kernel_size']), int(hd['out_channels'])
        params += ho * c * hk + (ho if hd.get('bias') else 0)
        macs += ho * c * hk
        receptive += hk - 1
    params += 1                                        # head_scale
    return {'macs': macs, 'params': params, 'channels': chans,
            'layers': layers, 'receptive': receptive,
            'namb_bytes': 496 + 4 * params,
            'load': macs * SAMPLE_RATE / CORE_HZ}


# --------------------------------------------------------------------------
# the model, run
# --------------------------------------------------------------------------

class WaveNet(object):
    """NAM's WaveNet, offline. Weights are read in the order the C++ core
    flattens them: per layer array a 1x1 rechannel, then for every layer the
    dilated conv (out, in, tap) and its bias, the condition mixin, the 1x1 and
    its bias; then the array's head conv; then head_scale."""

    def __init__(self, model):
        if np is None:
            raise SystemExit("numpy is needed to run a model")
        cfg = model['config']
        w = model['weights']
        self.pos = [0]
        self.arrays = []
        for la in cfg['layers']:
            c = int(la['channels'])
            rech = self._take(w, c * int(la['input_size'])).reshape(c, -1)
            layers = []
            for k, d, act in zip(la['kernel_sizes'], la['dilations'],
                                 la['activation']):
                k, d = int(k), int(d)
                cw = self._take(w, c * c * k).reshape(c, c, k)
                cb = self._take(w, c)
                mw = self._take(w, c * int(la['condition_size'])).reshape(c, -1)
                ow = self._take(w, c * c).reshape(c, c)
                ob = self._take(w, c)
                if act.get('type') != 'LeakyReLU':
                    raise SystemExit("unsupported activation %r" % act.get('type'))
                layers.append((cw, cb, mw, ow, ob, d,
                               float(act.get('negative_slope', 0.01))))
            hd = la['head']
            hk, ho = int(hd['kernel_size']), int(hd['out_channels'])
            hw = self._take(w, ho * c * hk).reshape(ho, c, hk)
            hb = self._take(w, ho) if hd.get('bias') else np.zeros(ho)
            self.arrays.append((rech, layers, hw, hb, c))
        # head_scale is both a config field and the last weight in the vector
        tail = self._take(w, 1)
        self.head_scale = float(cfg['head_scale'])
        if abs(float(tail[0]) - self.head_scale) > 1e-6 * max(1.0, abs(self.head_scale)):
            raise SystemExit("head_scale disagrees: config %g, weights %g"
                             % (self.head_scale, tail[0]))
        self.used, self.total = self.pos[0], len(w)
        if self.used != self.total:
            raise SystemExit("weight layout mismatch: read %d of %d"
                             % (self.used, self.total))

    def _take(self, w, n):
        i = self.pos[0]
        self.pos[0] = i + n
        return np.asarray(w[i:i + n], dtype=np.float64)

    @staticmethod
    def _conv(h, w, b, dilation):
        c_out, _, k = w.shape
        n = h.shape[1]
        out = np.repeat(b[:, None], n, 1)
        for tap in range(k):
            back = (k - 1 - tap) * dilation
            if back >= n:
                continue
            if back:
                out[:, back:] += w[:, :, tap] @ h[:, :n - back]
            else:
                out += w[:, :, tap] @ h
        return out

    def process(self, x):
        cond = x[None, :]
        sig = cond
        y = None
        for rech, layers, hw, hb, c in self.arrays:
            h = rech @ sig
            head = np.zeros((c, sig.shape[1]))
            for cw, cb, mw, ow, ob, d, slope in layers:
                z = self._conv(h, cw, cb, d) + mw @ cond
                z = np.where(z >= 0.0, z, z * slope)
                head += z
                h = h + (ow @ z + ob[:, None])
            y = self._conv(head, hw, hb, 1)
            sig = h
        return (self.head_scale * y)[0]


def read_di(path, want_rate, seconds):
    """One channel of a wav, resampled to the model's rate. Suite ships the DI
    the vendor's own converter uses; it is 44.1 kHz and the models are 48, so
    resampling is not optional."""
    with wave.open(path, 'rb') as wf:
        rate = wf.getframerate()
        ch = wf.getnchannels()
        if wf.getsampwidth() != 2:
            raise SystemExit("%s: only 16-bit wavs are read here" % path)
        n = min(wf.getnframes(), int(rate * seconds))
        raw = wf.readframes(n)
    x = np.frombuffer(raw, dtype='<i2').astype(np.float64) / 32768.0
    if ch > 1:
        x = x[::ch]
    if abs(rate - want_rate) > 1:
        m = int(len(x) * want_rate / rate)
        x = np.interp(np.arange(m) * (rate / want_rate),
                      np.arange(len(x)), x)
    return x


def default_di():
    p = os.path.join(SUITE, 'data', 'flutter_assets', 'assets', 'wavs',
                     'nam_input_wav.wav')
    return p if os.path.isfile(p) else None


def esr(a, b):
    """Error-to-signal ratio of `a` against reference `b`, level-matched first:
    submodels of one capture are trained separately and their output gains do
    not match to the last decimal, and an unmatched gain reads as error that
    nobody would hear."""
    g = float((a * b).sum() / max((a * a).sum(), 1e-20))
    d = g * a - b
    return float((d * d).sum() / max((b * b).sum(), 1e-20))


# --------------------------------------------------------------------------
# the vendor converter
# --------------------------------------------------------------------------

SUITE = os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'),
                     'Valeton Suite', 'Valeton Suite')
USBDLL = os.path.join(SUITE, 'assets', '5868USB.dll')

_dll = None


def dll():
    global _dll
    if _dll is None:
        if not os.path.isfile(USBDLL):
            raise SystemExit("not found: %s\nInstall Valeton Suite - the "
                             "converter is its library, not ours." % USBDLL)
        os.add_dll_directory(SUITE)
        os.add_dll_directory(os.path.join(SUITE, 'assets'))
        d = ctypes.CDLL(USBDLL)
        d.convertNamToNambAtPath.restype = ctypes.c_char_p
        d.convertNamToNambAtPath.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                             ctypes.c_double]
        d.getLastNamToNambError.restype = ctypes.c_char_p
        _dll = d
    return _dll


def convert(src, dst, slim=0.0):
    d = dll()
    out = d.convertNamToNambAtPath(os.path.abspath(src).encode('utf-8'),
                                   os.path.abspath(dst).encode('utf-8'),
                                   float(slim))
    err = (d.getLastNamToNambError() or b'').decode('utf-8', 'replace')
    if err or not out:
        raise SystemExit("conversion failed: %s" % (err or "no output"))
    return out.decode('utf-8', 'replace')


def namb_header(path):
    b = open(path, 'rb').read(0x50)
    if len(b) < 0x34 or b[:4] != NAMB_MAGIC:
        raise SystemExit("%s: not a NAMB file" % path)
    ver, size, woff, wcount, cfglen, cksum, _ = struct.unpack_from('<7I', b, 4)
    maj, mnr, pat, arch = struct.unpack_from('<4B', b, 0x20)
    rate, loud = struct.unpack_from('<dd', b, 0x24)
    return {'version': ver, 'size': size, 'weights_at': woff,
            'weights': wcount, 'config_bytes': cfglen, 'checksum': cksum,
            'nam_version': '%d.%d.%d' % (maj, mnr, pat), 'architecture': arch,
            'sample_rate': rate, 'loudness': loud}


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def _name(nam):
    return nam.get('metadata', {}).get('name') or '(unnamed)'


def cmd_info(path):
    nam = load(path)
    subs = submodels(nam)
    meta = nam.get('metadata', {})
    print("%s" % os.path.basename(path))
    print("  %s%s" % (_name(nam),
                      '  -  %s' % meta['gear_make'] if meta.get('gear_make') else ''))
    print("  %s, NAM %s, %g Hz, %d submodel%s"
          % (nam.get('architecture'), nam.get('version'),
             nam.get('sample_rate', 0), len(subs), '' if len(subs) == 1 else 's'))
    print()
    print("  %-6s %-8s %-7s %-9s %-8s %-9s %s"
          % ("slim", "channels", "layers", "MAC/samp", "namb", "M7 load", "receptive"))
    for mv, m in subs:
        c = cost(m)
        print("  <=%-4g %-8s %-7d %-9d %-8s %-9s %d samples (%.0f ms)"
              % (mv, '/'.join(str(x) for x in c['channels']), c['layers'],
                 c['macs'], "%.1f KB" % (c['namb_bytes'] / 1024.0),
                 "%.0f%%" % (100 * c['load']), c['receptive'],
                 1000.0 * c['receptive'] / SAMPLE_RATE))
    print()
    big = cost(subs[-1][1])
    small = cost(subs[0][1])
    if len(subs) > 1:
        print("  The GP-150's Cortex-M7 has one amp model's worth of headroom "
              "and a\n  whole pedal besides. %s"
              % ("Only the %d-channel submodel fits; that is what slim 0 picks."
                 % small['channels'][0] if big['load'] > 0.33 >= small['load']
                 else "Both submodels are within budget."))
        print("  `check` measures what the smaller one costs in accuracy.")


def cmd_check(path, wav=None, seconds=5.0):
    if np is None:
        raise SystemExit("numpy is needed for check")
    nam = load(path)
    subs = submodels(nam)
    if len(subs) < 2:
        print("one submodel - nothing to compare against")
        return cmd_info(path)
    wav = wav or default_di()
    if not wav:
        raise SystemExit("no DI wav: pass --wav, or install Valeton Suite for "
                         "the one its own converter uses")
    rate = float(subs[-1][1].get('sample_rate') or 48000)
    x = read_di(wav, rate, seconds)
    print("%s  -  %s" % (os.path.basename(path), _name(nam)))
    print("  DI %s, %.1f s at %g Hz" % (os.path.basename(wav), len(x) / rate, rate))
    ref = None
    rows = []
    for mv, m in reversed(subs):                      # largest first
        y = WaveNet(m).process(x)
        if ref is None:
            ref = y
        c = cost(m)
        rows.append((mv, c, esr(y, ref), float(np.sqrt((y * y).mean()))))
    print()
    print("  %-6s %-8s %-9s %-8s %-9s %s"
          % ("slim", "channels", "MAC/samp", "namb", "M7 load", "ESR vs best"))
    for mv, c, e, rms in reversed(rows):
        print("  <=%-4g %-8s %-9d %-8s %-9s %s"
              % (mv, '/'.join(str(x) for x in c['channels']), c['macs'],
                 "%.1f KB" % (c['namb_bytes'] / 1024.0),
                 "%.0f%%" % (100 * c['load']),
                 "reference" if e == 0.0 else "%.4f  (%.1f dB)"
                 % (e, 10 * np.log10(max(e, 1e-12)))))
    print()
    print("  ESR is measured after matching output gain, so it is the shape of\n"
          "  the difference and not a level offset. Under about 0.01 the two\n"
          "  are hard to tell apart on a guitar; 0.1 is audibly a different amp.")


def cmd_convert(path, out=None, slim=0.0):
    nam = load(path)
    mv, m = pick(nam, slim)
    out = out or os.path.splitext(path)[0] + '.namb'
    written = convert(path, out, slim)
    c = cost(m)
    h = namb_header(written)
    print("%s -> %s" % (os.path.basename(path), written))
    print("  slim %g picked the submodel tagged <=%g: %s channels, %d MAC/sample,"
          " %.0f%% of the M7"
          % (slim, mv, '/'.join(str(x) for x in c['channels']), c['macs'],
             100 * c['load']))
    print("  %d bytes, %d weights, %g Hz, loudness %.2f LUFS"
          % (h['size'], h['weights'], h['sample_rate'], h['loudness']))
    if h['weights'] != c['params']:
        print("  note: the file holds %d weights, the config accounts for %d"
              % (h['weights'], c['params']))


def cmd_batch(d, out=None, slim=0.0):
    out = out or d
    if not os.path.isdir(out):
        os.makedirs(out)
    names = sorted(f for f in os.listdir(d) if f.lower().endswith('.nam'))
    if not names:
        raise SystemExit("no .nam files in %s" % d)
    ok = 0
    for f in names:
        src = os.path.join(d, f)
        dst = os.path.join(out, os.path.splitext(f)[0] + '.namb')
        try:
            convert(src, dst, slim)
            mv, m = pick(load(src), slim)
            c = cost(m)
            print("  %-44s %8d B  %s ch  %.0f%% M7"
                  % (f[:44], os.path.getsize(dst),
                     '/'.join(str(x) for x in c['channels']), 100 * c['load']))
            ok += 1
        except SystemExit as e:
            print("  %-44s FAILED: %s" % (f[:44], e))
    print("\n%d of %d converted into %s" % (ok, len(names), out))


def cmd_namb(path):
    h = namb_header(path)
    print("%s" % os.path.basename(path))
    for k in ('version', 'size', 'weights', 'weights_at', 'config_bytes',
              'nam_version', 'architecture'):
        print("  %-13s %s" % (k, h[k]))
    print("  %-13s 0x%08X" % ('checksum', h['checksum']))
    print("  %-13s %g Hz" % ('sample_rate', h['sample_rate']))
    print("  %-13s %.3f LUFS" % ('loudness', h['loudness']))
    print("  weights are float32, %d of them, %d bytes"
          % (h['weights'], 4 * h['weights']))


def main(argv):
    if not argv:
        print(__doc__.strip())
        return 1
    cmd, args = argv[0], argv[1:]
    slim = 0.0
    out = None
    wav = None
    rest = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == '--slim' and i + 1 < len(args):
            slim = float(args[i + 1]); i += 2
        elif a in ('-o', '--out') and i + 1 < len(args):
            out = args[i + 1]; i += 2
        elif a == '--wav' and i + 1 < len(args):
            wav = args[i + 1]; i += 2
        else:
            rest.append(a); i += 1
    if cmd == 'info' and len(rest) == 1:
        return cmd_info(rest[0])
    if cmd == 'check' and len(rest) == 1:
        return cmd_check(rest[0], wav)
    if cmd == 'convert' and len(rest) == 1:
        return cmd_convert(rest[0], out, slim)
    if cmd == 'batch' and len(rest) == 1:
        return cmd_batch(rest[0], out, slim)
    if cmd == 'namb' and len(rest) == 1:
        return cmd_namb(rest[0])
    print(__doc__.strip())
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
