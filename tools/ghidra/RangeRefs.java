/* RangeRefs.java - everything that points into a range, and what points at it.
 *
 * `Refs.java` answers "who touches this address". This answers the question
 * that actually comes up: "does anything at all reach into this region, and
 * from where" - for a string table whose entries are addressed by index rather
 * than by name, for SDRAM that the file is supposed not to describe, for a
 * region that the structural searches said was unreferenced.
 *
 *   analyzeHeadless <proj> <name> -process flat.bin -noanalysis \
 *       -scriptPath tools/ghidra -postScript RangeRefs.java \
 *       <out-dir> 0x602C8000-0x602C9000 0x80000000-0x80030000 ...
 *
 * Writes one report per range listing every reference into it, the function it
 * comes from and the kind of reference, then decompiles the distinct functions.
 * A range with no references is reported as such, which is a result too.
 */

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.File;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Set;

public class RangeRefs extends GhidraScript {

    private Function functionAbove(Address at) {
        try {
            for (int back = 0; back < 4096; back += 2) {
                Address p = at.subtract(back);
                int lo = getByte(p) & 0xFF;
                int hi = getByte(p.add(1)) & 0xFF;
                if ((hi & 0xFE) != 0xB4 && !(lo == 0x2D && hi == 0xE9)) {
                    continue;
                }
                Function f = getFunctionContaining(p);
                if (f != null) {
                    return f;
                }
                f = createFunction(p, null);
                if (f != null && f.getBody().contains(at)) {
                    return f;
                }
            }
        } catch (Exception e) {                                     // noqa
            return null;
        }
        return null;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("usage: RangeRefs <out-dir> <lo>-<hi> ...");
            return;
        }
        File out = new File(args[0]);
        out.mkdirs();
        ReferenceManager rm = currentProgram.getReferenceManager();
        Set<Function> fns = new LinkedHashSet<>();
        PrintWriter rep = new PrintWriter(new File(out, "ranges.txt"), "UTF-8");

        for (int i = 1; i < args.length; i++) {
            String[] p = args[i].split("-");
            Address lo = toAddr(p[0].replaceFirst("^0x", ""));
            Address hi = toAddr(p[1].replaceFirst("^0x", ""));
            if (lo == null || hi == null) {
                rep.println(args[i] + ": not a range");
                continue;
            }
            AddressSet set = new AddressSet(lo, hi);
            int n = 0;
            rep.println("== " + args[i]);
            // getReferenceSourceIterator walks froms; we want tos, so ask the
            // manager for every reference whose destination is in the set.
            for (Address a : rm.getReferenceDestinationIterator(set, true)) {
                for (Reference r : rm.getReferencesTo(a)) {
                    Address from = r.getFromAddress();
                    Function f = getFunctionContaining(from);
                    if (f == null) {
                        f = functionAbove(from);
                    }
                    if (f != null) {
                        fns.add(f);
                    }
                    if (n < 400) {
                        rep.println("   " + from + " -> " + a + "  "
                                + r.getReferenceType() + "  in "
                                + (f == null ? "(none)" : f.getName()));
                    }
                    n++;
                }
                if (n > 4000) {
                    break;
                }
            }
            rep.println("   total " + n + " reference(s)");
            println(args[i] + " -> " + n + " reference(s)");
        }
        rep.close();

        DecompInterface dif = new DecompInterface();
        dif.toggleCCode(true);
        if (!dif.openProgram(currentProgram)) {
            println("decompiler would not open: " + dif.getLastMessage());
            return;
        }
        PrintWriter idx = new PrintWriter(new File(out, "index.txt"), "UTF-8");
        int ok = 0;
        for (Function f : fns) {
            if (ok > 120) {
                break;
            }
            DecompileResults r = dif.decompileFunction(f, 120, monitor);
            if (r == null || !r.decompileCompleted()
                    || r.getDecompiledFunction() == null) {
                idx.println(f.getName() + ", " + f.getEntryPoint() + ", FAILED");
                continue;
            }
            String c = r.getDecompiledFunction().getC();
            PrintWriter w = new PrintWriter(new File(out, f.getName() + ".c"), "UTF-8");
            w.println("/* " + f.getName() + " @ " + f.getEntryPoint() + " */");
            w.print(c);
            w.close();
            idx.println(f.getName() + ", " + f.getEntryPoint() + ", " + c.length());
            ok++;
        }
        idx.close();
        dif.dispose();
        println("wrote " + ok + " function(s) to " + out);
    }
}
