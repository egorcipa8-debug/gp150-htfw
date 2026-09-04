#!/usr/bin/env python3
"""build_spy.py - build a logging stand-in for Valeton Suite's device library.

The protocol is not in the pedal's firmware image (FINDINGS: the code that
handles it runs from SDRAM and is not in the file) and the vendor library only
logs message *lengths*. What is left is to watch the real thing work, and the
safest way to do that is to sit in the middle of it: a DLL with the same 61
exports as `assets/5868USB.dll`, which forwards every call to the real library
and writes down the ones that carry protocol.

Nothing is sent that Suite would not have sent. This captures; it does not probe.

    build_spy.py generate            write spy.c and spy.def from the real DLL
    build_spy.py build               compile 5868USB.dll (needs MSVC)
    build_spy.py install             put it in place, keeping the original
    build_spy.py uninstall           put the original back
    build_spy.py status              what is installed right now

Add `--dir <folder>` to work on another copy of Suite - copy the install to
somewhere writable and no elevation is needed at all.

The install renames the vendor library to `5868USB_real.dll` and drops ours in
its place, so `uninstall` is a rename back. Writing into Program Files needs an
elevated shell.

The log lands in `%TEMP%\\gp150_spy.log`: one line per call, with the full
payload in hex for `sendMidiMessage`, which is the one that carries commands.
"""

import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SUITE = os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'),
                     'Valeton Suite', 'Valeton Suite')


def use(dirname):
    """Point the install commands at another copy of Suite - a portable one on
    the desktop needs no elevation and can be refreshed while the installed
    Suite is running."""
    global SUITE, ASSETS, REAL, KEPT
    SUITE = os.path.abspath(dirname)
    ASSETS = os.path.join(SUITE, 'assets')
    REAL = os.path.join(ASSETS, '5868USB.dll')
    KEPT = os.path.join(ASSETS, 'htusb_real.dll')


ASSETS = os.path.join(SUITE, 'assets')
REAL = os.path.join(ASSETS, '5868USB.dll')
# The forwarder target cannot start with a digit - the linker reads
# "5868USB_real.name" as a number and gives up - so the original is
# kept under a name that starts with a letter.
KEPT = os.path.join(ASSETS, 'htusb_real.dll')

# The calls worth writing down. Everything else is forwarded untouched.
#
# Every thunk takes six pointer-sized arguments and passes all six on,
# whatever the real function's arity is. That direction is safe - spare
# arguments in registers are ignored - while the other way round is not:
# declaring scanInDevice(void) when it really takes (filter, callback) left
# the real function reading whatever happened to be in rcx and rdx, which
# crashed it, and with it Suite's ability to find the pedal at all.
#
# 'payload' formats (device, command, data, length, flag); 'first' says so
# once and then keeps quiet, for the ones Suite polls.
HOOKS = {
    'sendMidiMessage': 'payload',
    'connectDevice': 'args',
    'disConnectDevice': 'args',
    'deviceStartUpdate': 'args',
    'deviceStartBoot': 'args',
    'setDeviceCompress': 'args',
    'isRealFirmware': 'args',
    'checkCrc': 'args',
    'checkDeviceConnecting': 'first',
    'scanInDevice': 'first',
    'scanOutDevice': 'first',
    'getVersionStringForFilePath': 'args',
    'registerSendPort': 'args',
    'deviceProcessCallback': 'first',
}


def exports(path=REAL):
    """Export names, straight out of the PE - no pefile needed."""
    blob = open(path, 'rb').read()
    pe = struct.unpack_from('<I', blob, 0x3C)[0]
    magic = struct.unpack_from('<H', blob, pe + 24)[0]
    dd = pe + 24 + (112 if magic == 0x20B else 96)
    rva = struct.unpack_from('<I', blob, dd)[0]
    nsec = struct.unpack_from('<H', blob, pe + 6)[0]
    opt = struct.unpack_from('<H', blob, pe + 20)[0]
    secs = []
    for i in range(nsec):
        o = pe + 24 + opt + i * 40
        vs, va, rawsz, raw = struct.unpack_from('<IIII', blob, o + 8)
        secs.append((va, max(vs, rawsz), raw))

    def off(v):
        for va, sz, raw in secs:
            if va <= v < va + max(sz, 1):
                return raw + (v - va)
        return None
    e = off(rva)
    n = struct.unpack_from('<I', blob, e + 24)[0]
    names = struct.unpack_from('<I', blob, e + 32)[0]
    base = off(names)
    out = []
    for i in range(n):
        p = off(struct.unpack_from('<I', blob, base + 4 * i)[0])
        out.append(blob[p:blob.index(b'\0', p)].decode('latin1'))
    return out


def cmd_generate():
    names = exports()
    hooked = [n for n in names if n in HOOKS]
    forwarded = [n for n in names if n not in HOOKS]
    print("%d exports: %d hooked, %d forwarded"
          % (len(names), len(hooked), len(forwarded)))

    with open(os.path.join(HERE, 'spy.def'), 'w', encoding='utf-8') as f:
        f.write("LIBRARY 5868USB\nEXPORTS\n")
        for n in hooked:
            f.write("    %s\n" % n)
        for n in forwarded:
            # A forwarder in the .def sends the call straight on to the real
            # library, so the 51 functions this does not care about cost nothing
            # and cannot be got wrong.
            f.write('    %s=htusb_real.%s\n' % (n, n))

    src = ['/* spy.c - generated by build_spy.py. Do not edit; regenerate. */',
           '#include <windows.h>', '#include <stdio.h>', '',
           'static HMODULE real;', 'static CRITICAL_SECTION lock;',
           'static FILE *spy_f;', '',
           'static void spy_open(void) {',
           '    char path[MAX_PATH];',
           '    if (spy_f) return;',
           '    GetTempPathA(sizeof(path), path);',
           '    strcat_s(path, sizeof(path), "gp150_spy.log");',
           '    fopen_s(&spy_f, path, "a");',
           '    if (!spy_f) {',
           '        /* a service or a sandboxed TEMP would swallow the capture */',
           '        DWORD n = GetEnvironmentVariableA("USERPROFILE", path, sizeof(path));',
           '        if (n && n < sizeof(path)) {',
           '            strcat_s(path, sizeof(path), "\\\\gp150_spy.log");',
           '            fopen_s(&spy_f, path, "a");',
           '        }',
           '    }',
           '}', '',
           'static void spy_line(const char *fmt, ...) {',
           '    va_list ap;',
           '    EnterCriticalSection(&lock);',
           '    spy_open();',
           '    if (spy_f) {',
           '        SYSTEMTIME t; GetLocalTime(&t);',
           '        fprintf(spy_f, "%02d:%02d:%02d.%03d ", t.wHour, t.wMinute,',
           '                t.wSecond, t.wMilliseconds);',
           '        va_start(ap, fmt); vfprintf(spy_f, fmt, ap); va_end(ap);',
           '        fputc(\'\\n\', spy_f); fflush(spy_f);',
           '    }',
           '    LeaveCriticalSection(&lock);',
           '}', '',
           'static void *sym(const char *name) {',
           '    if (!real) {',
           '        char path[MAX_PATH]; HMODULE self = NULL;',
           '        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |',
           '            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,',
           '            (LPCSTR)&sym, &self);',
           '        GetModuleFileNameA(self, path, sizeof(path));',
           '        char *slash = strrchr(path, \'\\\\\');',
           '        if (slash) slash[1] = 0;',
           '        strcat_s(path, sizeof(path), "htusb_real.dll");',
           '        real = LoadLibraryA(path);',
           '        spy_line("== spy attached, real library %s", real ? path : "NOT FOUND");',
           '    }',
           '    return real ? (void *)GetProcAddress(real, name) : NULL;',
           '}', '',
           'BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {',
           '    (void)h; (void)r;',
           '    if (reason == DLL_PROCESS_ATTACH) {',
           '        char exe[MAX_PATH];',
           '        InitializeCriticalSection(&lock);',
           '        GetModuleFileNameA(NULL, exe, sizeof(exe));',
           '        spy_line("== loaded into %s (pid %lu)", exe, GetCurrentProcessId());',
           '    }',
           '    return TRUE;',
           '}', '']

    src.append('typedef void *(*t_any)(void *, void *, void *, void *,')
    src.append('                          void *, void *);')
    src.append('')
    for name in hooked:
        kind = HOOKS[name]
        src.append('__declspec(dllexport) void *%s(void *a0, void *a1, void *a2,' % name)
        src.append('        void *a3, void *a4, void *a5) {')
        src.append('    static t_any fn; if (!fn) fn = (t_any)sym("%s");' % name)
        if kind == 'payload':
            src.append('    {')
            src.append('        const unsigned char *d = (const unsigned char *)a2;')
            src.append('        int len = (int)(size_t)a3;')
            src.append('        if (d && len > 0) {')
            src.append('            char hex[3 * 256 + 8]; int i, n = len > 256 ? 256 : len;')
            src.append('            for (i = 0; i < n; i++) sprintf_s(hex + 3 * i, 4, "%02X ", d[i]);')
            src.append('            hex[3 * n] = 0;')
            src.append('            spy_line("send cmd=0x%02X len=%d flag=%d  %s%s",')
            src.append('                     (unsigned)(size_t)a1 & 0xFF, len,')
            src.append('                     (unsigned)(size_t)a4 & 0xFF, hex, len > 256 ? "..." : "");')
            src.append('        } else {')
            src.append('            spy_line("send cmd=0x%02X len=%d flag=%d  (no payload)",')
            src.append('                     (unsigned)(size_t)a1 & 0xFF, len,')
            src.append('                     (unsigned)(size_t)a4 & 0xFF);')
            src.append('        }')
            src.append('    }')
        elif kind == 'first':
            src.append('    { static long once; if (!InterlockedExchange(&once, 1))')
            src.append('        spy_line("%s: first call"); }' % name)
        else:
            src.append('    spy_line("%s(%%p, %%p, %%p, %%p)", a0, a1, a2, a3);' % name)
        src.append('    {')
        src.append('        void *r = fn ? fn(a0, a1, a2, a3, a4, a5) : 0;')
        if kind == 'args':
            src.append('        spy_line("  %s -> %%lld", (long long)(size_t)r);' % name)
        src.append('        return r;')
        src.append('    }')
        src.append('}')
        src.append('')
    with open(os.path.join(HERE, 'spy.c'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(src))
    print("wrote spy.c and spy.def in %s" % HERE)


def _cl():
    root = os.path.join(os.environ.get('ProgramFiles(x86)',
                                       r'C:\Program Files (x86)'),
                        'Microsoft Visual Studio')
    for dirpath, _dirs, files in os.walk(root):
        if 'cl.exe' in files and os.sep + 'Hostx64' + os.sep + 'x64' in dirpath:
            return os.path.join(dirpath, 'cl.exe')
    raise SystemExit("no 64-bit cl.exe found - install the MSVC build tools")


def cmd_build():
    cl = _cl()
    vc = cl.split(os.sep + 'bin' + os.sep)[0]
    inc = os.path.join(vc, 'include')
    lib = os.path.join(vc, 'lib', 'x64')
    sdk = r'C:\Program Files (x86)\Windows Kits\10'
    vers = sorted(os.listdir(os.path.join(sdk, 'Include'))) if os.path.isdir(
        os.path.join(sdk, 'Include')) else []
    if not vers:
        raise SystemExit("no Windows SDK under %s" % sdk)
    v = vers[-1]
    incs = [inc, os.path.join(sdk, 'Include', v, 'ucrt'),
            os.path.join(sdk, 'Include', v, 'um'),
            os.path.join(sdk, 'Include', v, 'shared')]
    libs = [lib, os.path.join(sdk, 'Lib', v, 'ucrt', 'x64'),
            os.path.join(sdk, 'Lib', v, 'um', 'x64')]
    # A forwarder resolves against an *import library*, not the DLL, so one is
    # made for the vendor library under the name the forwarders use - which is
    # also the name it will have once installed.
    names = exports()
    with open(os.path.join(HERE, 'htusb_real.def'), 'w', encoding='utf-8') as f:
        f.write('LIBRARY htusb_real\nEXPORTS\n')
        for n in names:
            f.write('    %s\n' % n)
    libexe = os.path.join(os.path.dirname(cl), 'lib.exe')
    env = dict(os.environ)
    env['INCLUDE'] = ';'.join(incs)
    env['LIB'] = ';'.join([HERE] + libs)
    r = subprocess.run([libexe, '/nologo', '/def:htusb_real.def',
                        '/out:htusb_real.lib', '/machine:x64'],
                       cwd=HERE, env=env, capture_output=True, text=True)
    if r.returncode:
        print(r.stdout[-2000:], r.stderr[-2000:])
        raise SystemExit("could not make the import library")
    out = os.path.join(HERE, '5868USB.dll')
    # The import library has to be on the link line, not merely on LIB: a
    # forwarder resolves only against a library the linker has actually pulled
    # in, which is why every attempt without this said "unresolved external".
    cmd = [cl, '/nologo', '/O2', '/LD', 'spy.c', '/link', '/DEF:spy.def',
           'htusb_real.lib', '/OUT:' + out]
    print(' '.join(cmd))
    r = subprocess.run(cmd, cwd=HERE, env=env, capture_output=True, text=True)
    print(r.stdout[-3000:])
    if r.returncode:
        print(r.stderr[-3000:])
        raise SystemExit("build failed")
    print("built %s (%d bytes)" % (out, os.path.getsize(out)))


def cmd_status():
    print("Suite assets: %s" % ASSETS)
    for p, what in ((REAL, "5868USB.dll (what Suite loads)"),
                    (KEPT, "htusb_real.dll (the original, if installed)")):
        print("  %-34s %s" % (what,
              "%d bytes" % os.path.getsize(p) if os.path.isfile(p) else "absent"))
    mine = os.path.join(HERE, '5868USB.dll')
    print("  %-34s %s" % ("built spy",
          "%d bytes" % os.path.getsize(mine) if os.path.isfile(mine) else "not built"))
    log = os.path.join(os.environ.get('TEMP', ''), 'gp150_spy.log')
    print("  %-34s %s" % ("log",
          "%d bytes" % os.path.getsize(log) if os.path.isfile(log) else "none yet"))
    print("\ninstalled: %s" % ("yes" if os.path.isfile(KEPT) else "no"))


def cmd_install():
    mine = os.path.join(HERE, '5868USB.dll')
    if not os.path.isfile(mine):
        raise SystemExit("build it first")
    import shutil
    if os.path.isfile(KEPT):
        # already installed: just refresh our copy, the original stays put
        shutil.copy2(mine, REAL)
        print("refreshed the spy in place; the original is still %s" % KEPT)
        print("Restart Valeton Suite for it to take effect.")
        return
    os.rename(REAL, KEPT)
    shutil.copy2(mine, REAL)
    print("installed. The original is %s" % KEPT)
    print("Start Valeton Suite, connect the pedal, and do the things you want "
          "to see; the log is %%TEMP%%\\gp150_spy.log")


def cmd_uninstall():
    if not os.path.isfile(KEPT):
        raise SystemExit("not installed")
    os.remove(REAL)
    os.rename(KEPT, REAL)
    print("the vendor library is back in place")


def main(argv):
    cmds = {'generate': cmd_generate, 'build': cmd_build, 'install': cmd_install,
            'uninstall': cmd_uninstall, 'status': cmd_status}
    argv = list(argv)
    if '--dir' in argv:
        i = argv.index('--dir')
        use(argv[i + 1])
        del argv[i:i + 2]
    if not argv or argv[0] not in cmds:
        print(__doc__.strip())
        return 1
    return cmds[argv[0]]()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
