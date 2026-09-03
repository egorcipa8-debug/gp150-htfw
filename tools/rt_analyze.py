import os
os.environ.setdefault("GHIDRA_INSTALL_DIR", r"C:\Users\warde\tools\ghidra_12.1.3_PUBLIC")
import pyghidra
pyghidra.start()

from ghidra.base.project import GhidraProject
from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import ArmDisassembleCommand
from ghidra.app.plugin.core.analysis import AutoAnalysisManager
from ghidra.util.task import ConsoleTaskMonitor
from java.math import BigInteger

LOC = r"C:\Users\warde\AppData\Local\Temp\claude\C--Users-warde-Desktop\0e59dd09-6a7e-491c-a849-f9aee2155445\scratchpad\gproj2"
NAME = "rt1064"

monitor = ConsoleTaskMonitor()
project = GhidraProject.openProject(LOC, NAME, True)
program = project.openProgram("/", "flash.bin", False)
print("opened:", program.getName(), program.getLanguage().getLanguageID())

mem = program.getMemory()
af = program.getAddressFactory().getDefaultAddressSpace()
def A(x): return af.getAddress(x)

tx = program.startTransaction("rt1064 setup")
try:
    print("\n=== memory map ===")
    for name, start, size, ex in [
        ("ITCM", 0x00000000, 0x00080000, True),
        ("DTCM", 0x20000000, 0x00080000, False),
        ("OCRAM", 0x20200000, 0x00200000, False),
        ("SDRAM", 0x80000000, 0x02000000, True),
        ("AIPS", 0x40000000, 0x02000000, False),
    ]:
        try:
            b = mem.createUninitializedBlock(name, A(start), size, False)
            b.setRead(True); b.setWrite(True); b.setExecute(ex)
            print("  + %-6s 0x%08X + 0x%X" % (name, start, size))
        except Exception as e:
            print("  . %-6s exists/skip" % name)

    CODE = [
        (0x60038158, 0x6004BF58, "b-code"),
        (0x607FF748, 0x60845748, "d-code-1"),
        (0x60855748, 0x608D8748, "d-code-2"),
        (0x608DB748, 0x608FD748, "d-code-3"),
        (0x60901748, 0x609C0000, "d-code-4"),
    ]
    print("\n=== disassembling as Thumb ===")
    for lo, hi, nm in CODE:
        s = AddressSet(A(lo), A(hi - 1))
        cmd = ArmDisassembleCommand(s, None, True)   # True = Thumb
        ok = cmd.applyTo(program, monitor)
        print("  %-9s 0x%08X..0x%08X  %s" % (nm, lo, hi, "ok" if ok else cmd.getStatusMsg()))
finally:
    program.endTransaction(tx, True)

print("\n=== auto analysis ===")
tx = program.startTransaction("analyze")
try:
    mgr = AutoAnalysisManager.getAnalysisManager(program)
    mgr.reAnalyzeAll(None)
    mgr.startAnalysis(monitor)
finally:
    program.endTransaction(tx, True)

listing = program.getListing()
fm = program.getFunctionManager()
print("\n=== results ===")
print("  functions    : %d" % fm.getFunctionCount())
print("  instructions : %d" % listing.getNumInstructions())
print("  defined data : %d" % listing.getNumDefinedData())

rm = program.getReferenceManager()
buckets = {}
def bucket(t):
    if 0x60000000 <= t < 0x61000000: return "flash-XIP"
    if 0x80000000 <= t < 0x82000000: return "SDRAM"
    if 0x20200000 <= t < 0x20400000: return "OCRAM"
    if 0x20000000 <= t < 0x20080000: return "DTCM"
    if 0x40000000 <= t < 0x42000000: return "AIPS-periph"
    if t < 0x00080000: return "ITCM/small"
    return "other"
it = rm.getReferenceSourceIterator(A(0x60000000), True)
n = 0
while it.hasNext():
    a = it.next()
    for r in rm.getReferencesFrom(a):
        k = bucket(r.getToAddress().getOffset())
        buckets[k] = buckets.get(k, 0) + 1
    n += 1
print("  reference sources: %d" % n)
for k in sorted(buckets, key=lambda x: -buckets[x]):
    print("     %-12s %d" % (k, buckets[k]))

print("\n=== references into the UI string blob (flash 0x2B55FD..0x2B6000) ===")
hits = 0
a = A(0x602B55FD)
while a.getOffset() < 0x602B6000 and hits < 30:
    for r in rm.getReferencesTo(a):
        print("   %s -> %s  (%s)" % (r.getFromAddress(), a, r.getReferenceType()))
        hits += 1
    a = a.add(1)
print("  total: %d" % hits)

print("\n=== references into the graphics blob (flash 0x115F58..0x120000) ===")
g = 0
a = A(0x60115F58)
while a.getOffset() < 0x60120000 and g < 20:
    for r in rm.getReferencesTo(a):
        print("   %s -> %s" % (r.getFromAddress(), a))
        g += 1
    a = a.add(1)
print("  total: %d" % g)

project.save(program)
project.close()
print("\nsaved.")
