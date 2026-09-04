/* DecompileExports.java - decompile named functions, and what they call, to C.
 *
 * Written for Valeton Suite's assets/5868USB.dll: the library that talks to the
 * pedal, checks a firmware image and converts a NAM capture. The exports are
 * plain C, so a name is enough to find the entry point; everything interesting
 * is a few calls below it, which is what `depth` is for.
 *
 *   analyzeHeadless <proj-dir> <proj-name> -import 5868USB.dll \
 *       -scriptPath tools/ghidra -postScript DecompileExports.java \
 *       <out-dir> <depth> [name ...] -deleteProject
 *
 * With no names it does every export. Output is one .c per function, named
 * after it, plus index.txt listing what was written and how big each one is.
 * The decompiled listings are Valeton's code however it is spelled, so keep
 * them out of the repository - work/ is gitignored for this.
 */

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class DecompileExports extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("usage: DecompileExports <out-dir> [depth] [name ...]");
            return;
        }
        File out = new File(args[0]);
        out.mkdirs();
        int depth = args.length > 1 ? Integer.parseInt(args[1]) : 1;
        Set<String> want = new HashSet<>();
        for (int i = 2; i < args.length; i++) {
            want.add(args[i]);
        }

        List<Function> seeds = new ArrayList<>();
        SymbolTable st = currentProgram.getSymbolTable();
        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolIterator it = st.getAllSymbols(true);
        while (it.hasNext()) {
            Symbol s = it.next();
            if (!s.isExternalEntryPoint() && !want.contains(s.getName())) {
                continue;
            }
            if (!want.isEmpty() && !want.contains(s.getName())) {
                continue;
            }
            Function f = fm.getFunctionAt(s.getAddress());
            if (f != null && !seeds.contains(f)) {
                seeds.add(f);
            }
        }
        println("seeds: " + seeds.size());

        // Breadth-first over callees, so `depth` means what it looks like it
        // means: 0 is the export itself, 1 adds what it calls directly.
        Map<Function, Integer> reach = new LinkedHashMap<>();
        Deque<Function> queue = new ArrayDeque<>(seeds);
        for (Function f : seeds) {
            reach.put(f, 0);
        }
        while (!queue.isEmpty()) {
            Function f = queue.removeFirst();
            int d = reach.get(f);
            if (d >= depth) {
                continue;
            }
            for (Function c : f.getCalledFunctions(monitor)) {
                if (c.isThunk() || c.isExternal() || reach.containsKey(c)) {
                    continue;
                }
                reach.put(c, d + 1);
                queue.addLast(c);
            }
        }
        println("with callees to depth " + depth + ": " + reach.size());

        DecompInterface dif = new DecompInterface();
        dif.toggleCCode(true);
        dif.toggleSyntaxTree(true);
        if (!dif.openProgram(currentProgram)) {
            println("decompiler would not open: " + dif.getLastMessage());
            return;
        }
        PrintWriter index = new PrintWriter(new File(out, "index.txt"), "UTF-8");
        index.println("# function, depth, address, bytes of C");
        int ok = 0;
        for (Map.Entry<Function, Integer> e : reach.entrySet()) {
            Function f = e.getKey();
            if (monitor.isCancelled()) {
                break;
            }
            DecompileResults r = dif.decompileFunction(f, 120, monitor);
            if (r == null || !r.decompileCompleted() || r.getDecompiledFunction() == null) {
                index.println(f.getName() + ", " + e.getValue() + ", "
                        + f.getEntryPoint() + ", FAILED");
                continue;
            }
            String c = r.getDecompiledFunction().getC();
            String safe = f.getName().replaceAll("[^A-Za-z0-9_.@$-]", "_");
            if (safe.length() > 120) {
                safe = safe.substring(0, 120);
            }
            File dst = new File(out, safe + "_" + f.getEntryPoint() + ".c");
            PrintWriter w = new PrintWriter(dst, "UTF-8");
            w.println("/* " + f.getName() + " @ " + f.getEntryPoint()
                    + "  (depth " + e.getValue() + ") */");
            w.print(c);
            w.close();
            index.println(f.getName() + ", " + e.getValue() + ", "
                    + f.getEntryPoint() + ", " + c.length());
            ok++;
        }
        index.close();
        dif.dispose();
        println("wrote " + ok + " of " + reach.size() + " to " + out);
    }
}
