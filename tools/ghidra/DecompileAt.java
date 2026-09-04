/* DecompileAt.java - decompile whatever function contains each address.
 *
 * The blunt instrument. When a scan outside Ghidra has found the interesting
 * instructions - every site that builds the framebuffer address, say, which is
 * a MOVW/MOVT pair and so has no reference Ghidra would have made - this takes
 * the list and gives back the functions they sit in.
 *
 *   analyzeHeadless <proj> <name> -process flat.bin -noanalysis \
 *       -scriptPath tools/ghidra -postScript DecompileAt.java \
 *       <out-dir> 0x6080046C 0x608005DC ...
 *
 * or with a file of addresses, one per line, first token used:
 *
 *       <out-dir> @sites.txt
 */

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class DecompileAt extends GhidraScript {

    private Function makeFunctionAbove(Address at) {
        try {
            for (int back = 0; back < 4096; back += 2) {
                Address p = at.subtract(back);
                int lo = getByte(p) & 0xFF;
                int hi = getByte(p.add(1)) & 0xFF;
                boolean push = (hi & 0xFE) == 0xB4;                 // push {...}
                boolean pushw = (lo == 0x2D && hi == 0xE9);          // push.w
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
            println("usage: DecompileAt <out-dir> <address|@file> ...");
            return;
        }
        File out = new File(args[0]);
        out.mkdirs();
        List<String> addrs = new ArrayList<>();
        for (int i = 1; i < args.length; i++) {
            if (args[i].startsWith("@")) {
                BufferedReader r = new BufferedReader(new FileReader(args[i].substring(1)));
                String line;
                while ((line = r.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty()) {
                        addrs.add(line.split("\\s+")[0]);
                    }
                }
                r.close();
            } else {
                addrs.add(args[i]);
            }
        }
        Set<Function> fns = new LinkedHashSet<>();
        int missed = 0;
        for (String a : addrs) {
            Address at = toAddr(a.replaceFirst("^0x", ""));
            Function f = (at == null) ? null : getFunctionContaining(at);
            if (f == null && at != null) {
                // A raw binary has no entry points, so Ghidra makes functions
                // only where something calls one. Walk back to the nearest
                // prologue - push {..., lr}, or the wide form - and declare it.
                f = makeFunctionAbove(at);
            }
            if (f == null) {
                missed++;
                continue;
            }
            fns.add(f);
        }
        println(addrs.size() + " address(es) -> " + fns.size() + " function(s), "
                + missed + " outside any function");

        DecompInterface dif = new DecompInterface();
        dif.toggleCCode(true);
        if (!dif.openProgram(currentProgram)) {
            println("decompiler would not open: " + dif.getLastMessage());
            return;
        }
        PrintWriter idx = new PrintWriter(new File(out, "index.txt"), "UTF-8");
        int ok = 0;
        for (Function f : fns) {
            DecompileResults r = dif.decompileFunction(f, 120, monitor);
            if (r == null || !r.decompileCompleted() || r.getDecompiledFunction() == null) {
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
