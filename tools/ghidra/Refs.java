/* Refs.java - who touches this address, and what does the code around it say?
 *
 * The blunt question that the structural searches outside Ghidra cannot answer.
 * A string chain is reached through its table's base, not through each entry;
 * a checksum table is reached from the one routine that uses it; a copy loop is
 * found by asking who writes to SDRAM. All of those are "who references this",
 * which is one call in Ghidra and a byte-grep that finds nothing outside it.
 *
 *   analyzeHeadless <proj> <name> -process flat.bin -noanalysis \
 *       -scriptPath tools/ghidra -postScript Refs.java \
 *       <out-dir> 0x6006B1A8 0x602C85B1 ...
 *
 * For every address it prints the references to it, the function each one sits
 * in, and - when the reference is inside a function - decompiles that function
 * into <out-dir>. A reference that is not inside any function gets one made,
 * the same way DecompileAt does it, by walking back to a prologue.
 */

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class Refs extends GhidraScript {

    private Function functionAbove(Address at) {
        try {
            for (int back = 0; back < 4096; back += 2) {
                Address p = at.subtract(back);
                int lo = getByte(p) & 0xFF;
                int hi = getByte(p.add(1)) & 0xFF;
                boolean push = (hi & 0xFE) == 0xB4;
                boolean pushw = (lo == 0x2D && hi == 0xE9);
                if (!push && !pushw) {
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
            println("usage: Refs <out-dir> <address> ...");
            return;
        }
        File out = new File(args[0]);
        out.mkdirs();
        Set<Function> fns = new LinkedHashSet<>();
        PrintWriter rep = new PrintWriter(new File(out, "refs.txt"), "UTF-8");
        for (int i = 1; i < args.length; i++) {
            Address target = toAddr(args[i].replaceFirst("^0x", ""));
            if (target == null) {
                rep.println(args[i] + ": not an address");
                continue;
            }
            List<String> lines = new ArrayList<>();
            ReferenceIterator it = currentProgram.getReferenceManager()
                    .getReferencesTo(target);
            int n = 0;
            while (it.hasNext() && n < 200) {
                Reference r = it.next();
                Address from = r.getFromAddress();
                Function f = getFunctionContaining(from);
                if (f == null) {
                    f = functionAbove(from);
                }
                if (f != null) {
                    fns.add(f);
                }
                lines.add("    " + from + "  " + r.getReferenceType()
                        + "  in " + (f == null ? "(no function)" : f.getName()
                        + " @ " + f.getEntryPoint()));
                n++;
            }
            rep.println(args[i] + " -> " + n + " reference(s)");
            for (String s : lines) {
                rep.println(s);
            }
            println(args[i] + " -> " + n + " reference(s)");
        }
        rep.close();

        DecompInterface dif = new DecompInterface();
        dif.toggleCCode(true);
        if (!dif.openProgram(currentProgram)) {
            println("decompiler would not open: " + dif.getLastMessage());
            return;
        }
        int ok = 0;
        PrintWriter idx = new PrintWriter(new File(out, "index.txt"), "UTF-8");
        for (Function f : fns) {
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
