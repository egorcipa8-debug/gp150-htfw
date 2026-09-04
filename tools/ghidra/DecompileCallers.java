/* DecompileCallers.java - decompile whoever uses a symbol, and whoever calls them.
 *
 * The other direction from DecompileExports: start at a name that is *used*
 * rather than exported - an import like `midiOutLongMsg`, a string, a table -
 * take every function that references it, and walk up the call graph.
 *
 *   analyzeHeadless <proj-dir> <proj-name> -process 5868USB.dll -noanalysis \
 *       -scriptPath tools/ghidra -postScript DecompileCallers.java \
 *       <out-dir> <depth> midiOutLongMsg midiOutShortMsg
 *
 * Same output shape as DecompileExports: one .c per function plus index.txt.
 * Keep the listings out of the repository.
 */

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
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

public class DecompileCallers extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            println("usage: DecompileCallers <out-dir> <depth> <symbol> [symbol ...]");
            return;
        }
        File out = new File(args[0]);
        out.mkdirs();
        int depth = Integer.parseInt(args[1]);
        Set<String> want = new HashSet<>();
        for (int i = 2; i < args.length; i++) {
            want.add(args[i]);
        }

        SymbolTable st = currentProgram.getSymbolTable();
        FunctionManager fm = currentProgram.getFunctionManager();
        List<Function> seeds = new ArrayList<>();
        // An argument that parses as an address is taken as one: a table with no
        // symbol on it - a CRC table, say - is exactly the kind of thing worth
        // asking "who uses this?" about.
        for (String a : want) {
            if (!a.startsWith("0x")) {
                continue;
            }
            Address at = currentProgram.getAddressFactory().getAddress(a.substring(2));
            if (at == null) {
                continue;
            }
            ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(at);
            while (ri.hasNext()) {
                Function f = fm.getFunctionContaining(ri.next().getFromAddress());
                if (f != null && !seeds.contains(f)) {
                    seeds.add(f);
                }
            }
        }
        SymbolIterator it = st.getAllSymbols(true);
        while (it.hasNext()) {
            Symbol s = it.next();
            if (!want.contains(s.getName())) {
                continue;
            }
            ReferenceIterator refs = currentProgram.getReferenceManager()
                    .getReferencesTo(s.getAddress());
            while (refs.hasNext()) {
                Reference r = refs.next();
                Address from = r.getFromAddress();
                Function f = fm.getFunctionContaining(from);
                if (f != null && !seeds.contains(f)) {
                    seeds.add(f);
                }
            }
        }
        println("functions using those symbols: " + seeds.size());

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
            for (Function c : f.getCallingFunctions(monitor)) {
                if (reach.containsKey(c)) {
                    continue;
                }
                reach.put(c, d + 1);
                queue.addLast(c);
            }
        }
        println("with callers to depth " + depth + ": " + reach.size());

        DecompInterface dif = new DecompInterface();
        dif.toggleCCode(true);
        if (!dif.openProgram(currentProgram)) {
            println("decompiler would not open: " + dif.getLastMessage());
            return;
        }
        PrintWriter index = new PrintWriter(new File(out, "index.txt"), "UTF-8");
        index.println("# function, distance from the symbol, address, bytes of C");
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
            PrintWriter w = new PrintWriter(
                    new File(out, safe + "_" + f.getEntryPoint() + ".c"), "UTF-8");
            w.println("/* " + f.getName() + " @ " + f.getEntryPoint()
                    + "  (" + e.getValue() + " calls above the symbol) */");
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
