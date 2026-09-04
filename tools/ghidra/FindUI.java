/* FindUI.java - find the code that draws a screen, by the words on it.
 *
 * The pedal's menus are the one part of the interface that is definitely in the
 * file: the labels. "Global Settings", "TAP Settings", "Input Level" are all in
 * region b as ordinary NUL-terminated strings, so whatever builds that page has
 * to hold their addresses - in a literal pool, because that is how Thumb loads a
 * 32-bit constant.
 *
 * So: find each string, find every word in the image that equals its address,
 * take the function containing that word, and decompile it. That lands directly
 * on the page-building code, and from there the drawing primitives are one call
 * down and the coordinates are the immediates around them.
 *
 *   analyzeHeadless <proj> <name> -process flat.bin -noanalysis \
 *       -scriptPath tools/ghidra -postScript FindUI.java \
 *       <out-dir> "Global Settings" "TAP Settings" ...
 *
 * With no strings it uses a list from the screens in the photographs. Writes one
 * .c per function plus index.txt, and prints where each string lives and who
 * points at it.
 */

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class FindUI extends GhidraScript {

    private static final String[] DEFAULTS = {
        "Global Settings", "Input/Output", "USB Settings", "GLOBAL EQ",
        "TAP Settings", "EXP Calibrate", "Footswitch", "Input Level",
        "No CAB Mode", "NAM MODE", "P-VOL", "Threshold",
    };

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("usage: FindUI <out-dir> [string ...]");
            return;
        }
        File out = new File(args[0]);
        out.mkdirs();
        List<String> want = new ArrayList<>();
        for (int i = 1; i < args.length; i++) {
            want.add(args[i]);
        }
        if (want.isEmpty()) {
            for (String s : DEFAULTS) {
                want.add(s);
            }
        }

        Memory mem = currentProgram.getMemory();
        Map<Function, String> hits = new LinkedHashMap<>();
        PrintWriter idx = new PrintWriter(new File(out, "index.txt"), "UTF-8");
        idx.println("# string, address, word that points at it, function");

        for (String s : want) {
            byte[] pat = (s + "\0").getBytes(StandardCharsets.ISO_8859_1);
            Address at = null;
            for (MemoryBlock b : mem.getBlocks()) {
                if (!b.isInitialized()) {
                    continue;
                }
                Address f = mem.findBytes(b.getStart(), b.getEnd(), pat, null, true, monitor);
                if (f != null) {
                    at = f;
                    break;
                }
            }
            if (at == null) {
                println("  \"" + s + "\" not in the image");
                idx.println(s + ", not found");
                continue;
            }
            println(String.format("  \"%s\" at %s", s, at));
            // Every word equal to that address - the literal pools that load it.
            byte[] le = new byte[4];
            long v = at.getOffset();
            for (int i = 0; i < 4; i++) {
                le[i] = (byte) ((v >> (8 * i)) & 0xFF);
            }
            int found = 0;
            for (MemoryBlock b : mem.getBlocks()) {
                if (!b.isInitialized()) {
                    continue;
                }
                Address p = b.getStart();
                while (p != null && p.compareTo(b.getEnd()) < 0) {
                    p = mem.findBytes(p, b.getEnd(), le, null, true, monitor);
                    if (p == null) {
                        break;
                    }
                    Function f = getFunctionContaining(p);
                    String where = (f != null) ? f.getName() : "(no function)";
                    idx.println(s + ", " + at + ", " + p + ", " + where);
                    if (f != null && !hits.containsKey(f)) {
                        hits.put(f, s);
                    }
                    found++;
                    if (found > 40) {
                        break;
                    }
                    p = p.add(1);
                }
            }
            println("      " + found + " word(s) point at it");
        }

        DecompInterface dif = new DecompInterface();
        dif.toggleCCode(true);
        if (!dif.openProgram(currentProgram)) {
            println("decompiler would not open: " + dif.getLastMessage());
            idx.close();
            return;
        }
        int ok = 0;
        for (Map.Entry<Function, String> e : hits.entrySet()) {
            Function f = e.getKey();
            DecompileResults r = dif.decompileFunction(f, 120, monitor);
            if (r == null || !r.decompileCompleted() || r.getDecompiledFunction() == null) {
                continue;
            }
            String c = r.getDecompiledFunction().getC();
            String safe = f.getName().replaceAll("[^A-Za-z0-9_.@$-]", "_");
            PrintWriter w = new PrintWriter(new File(out, safe + ".c"), "UTF-8");
            w.println("/* " + f.getName() + " @ " + f.getEntryPoint()
                    + "   found through \"" + e.getValue() + "\" */");
            w.print(c);
            w.close();
            ok++;
        }
        idx.close();
        dif.dispose();
        println("decompiled " + ok + " function(s) into " + out);
    }
}
