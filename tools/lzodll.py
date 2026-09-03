import ctypes, os, sys
DLL = r"C:\Program Files\Valeton Suite\Valeton Suite\minilzo_plugin.dll"
_l = ctypes.CDLL(DLL)
for f in ('startCompress','startDeCompress'):
    fn = getattr(_l, f)
    fn.restype = ctypes.c_int
    fn.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]

def compress(data):
    src = ctypes.create_string_buffer(data, len(data))
    cap = len(data) + len(data)//16 + 64 + 3
    dst = ctypes.create_string_buffer(cap)
    n = ctypes.c_size_t(cap)
    r = _l.startCompress(src, len(data), dst, ctypes.byref(n))
    if r != 0: raise RuntimeError("startCompress returned %d" % r)
    return dst.raw[:n.value]

def decompress(data, out_hint):
    src = ctypes.create_string_buffer(data, len(data))
    dst = ctypes.create_string_buffer(out_hint)
    n = ctypes.c_size_t(out_hint)
    r = _l.startDeCompress(src, len(data), dst, ctypes.byref(n))
    if r != 0: raise RuntimeError("startDeCompress returned %d" % r)
    return dst.raw[:n.value]
