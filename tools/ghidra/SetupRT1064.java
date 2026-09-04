/* SetupRT1064.java - give Ghidra the chip's memory map, then disassemble Thumb.
 *
 * Run as a -preScript when importing the flat image tools/flat_image.py writes:
 * the file is already at its real addresses, so all this adds is the RAM and
 * peripheral windows the code talks to, and the initial disassembly - without
 * which a binary import of an 11 MB blob finds nothing at all.
 *
 *   analyzeHeadless <proj-dir> <name> -import flat.bin \
 *       -processor ARM:LE:32:Cortex -loader BinaryLoader \
 *       -loader-baseAddr 0x60038000 \
 *       -scriptPath tools/ghidra -preScript SetupRT1064.java
 *
 * Optional arguments are extra "start:end" Thumb ranges; with none it takes the
 * bootstrap in region b and the whole of region d, which is where the
 * application lives (FINDINGS: 798 self-references at 0x60800000, more than
 * three times any other candidate base).
 */

import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class SetupRT1064 extends GhidraScript {

    private static final long[][] BLOCKS = {
        // name index, start, size, executable
        {0, 0x00000000L, 0x00080000L, 1},   // ITCM
        {1, 0x20000000L, 0x00080000L, 0},   // DTCM
        {2, 0x20200000L, 0x00200000L, 0},   // OCRAM
        {3, 0x80000000L, 0x02000000L, 1},   // SDRAM, through the SEMC
        {4, 0x40000000L, 0x02000000L, 0},   // AIPS: peripherals, eLCDIF included
    };
    private static final String[] NAMES = {"ITCM", "DTCM", "OCRAM", "SDRAM", "AIPS"};

    private static final long[][] THUMB = {
        {0x60038158L, 0x6004BF58L},         // the bootstrap in region b
        {0x60800000L, 0x6092E3F0L},         // the application, region d
    };

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        for (long[] b : BLOCKS) {
            String name = NAMES[(int) b[0]];
            Address at = toAddr(b[1]);
            if (mem.getBlock(at) != null) {
                println("  . " + name + " already mapped");
                continue;
            }
            MemoryBlock blk = mem.createUninitializedBlock(name, at, b[2], false);
            blk.setRead(true);
            blk.setWrite(true);
            blk.setExecute(b[3] != 0);
            println(String.format("  + %-6s 0x%08X + 0x%X", name, b[1], b[2]));
        }

        String[] args = getScriptArgs();
        long[][] ranges = THUMB;
        if (args.length > 0) {
            ranges = new long[args.length][2];
            for (int i = 0; i < args.length; i++) {
                String[] p = args[i].split(":");
                ranges[i][0] = Long.decode(p[0]);
                ranges[i][1] = Long.decode(p[1]);
            }
        }
        for (long[] r : ranges) {
            AddressSet set = new AddressSet(toAddr(r[0]), toAddr(r[1] - 1));
            ArmDisassembleCommand cmd = new ArmDisassembleCommand(set, null, true);
            boolean ok = cmd.applyTo(currentProgram, monitor);
            println(String.format("  thumb 0x%08X..0x%08X  %s", r[0], r[1],
                    ok ? "ok" : cmd.getStatusMsg()));
        }
    }
}
