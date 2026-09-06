/* SetupSplit.java - load the firmware the way the boot loader lays it out.
 *
 * `SetupRT1064.java` assumes the whole image is executed in place from flash at
 * 0x60000000. For section b that is wrong: it carries its own load table and is
 * copied in two halves, one to ITCM at 0x00000000 and one to SDRAM at
 * 0x80000000 (see FINDINGS, and `flat_image.py loadmap`). Disassembled at the
 * flash base, every address inside it is off by a constant and nothing
 * resolves - which is exactly why the interface looked absent from the image.
 *
 * Import the SDRAM half as the program, then run this as a -preScript to bring
 * in the other halves at their real addresses:
 *
 *   analyzeHeadless <proj> <name> -import gp.80000000.bin \
 *       -processor ARM:LE:32:Cortex -loader BinaryLoader \
 *       -loader-baseAddr 0x80000000 \
 *       -scriptPath tools/ghidra -preScript SetupSplit.java \
 *       ITCM:0x00000000:C:\...\gp.00000000.bin \
 *       FLASH_D:0x60800000:C:\...\gp.60800000.bin \
 *       ...
 *
 * Each extra argument is name:address:file. Blocks the chip has but the image
 * does not carry - DTCM, OCRAM, the peripheral window - are added empty so that
 * references into them resolve to something.
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.io.File;
import java.io.FileInputStream;

public class SetupSplit extends GhidraScript {

    private static final Object[][] EMPTY = {
        {"DTCM",  0x20000000L, 0x00080000L, false},
        {"OCRAM", 0x20200000L, 0x00200000L, false},
        {"AIPS",  0x40000000L, 0x02000000L, false},
    };

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();

        for (String a : getScriptArgs()) {
            // name:address:path, and the path has a drive letter in it, so
            // split on the first two colons only.
            int c1 = a.indexOf(':');
            int c2 = a.indexOf(':', c1 + 1);
            if (c1 < 0 || c2 < 0) {
                println("  ? cannot read region argument: " + a);
                continue;
            }
            String name = a.substring(0, c1);
            long addr = Long.decode(a.substring(c1 + 1, c2));
            File f = new File(a.substring(c2 + 1));
            if (!f.isFile()) {
                println("  ? no such file: " + f);
                continue;
            }
            Address at = toAddr(addr);
            if (mem.getBlock(at) != null) {
                println("  . " + name + " already mapped");
                continue;
            }
            FileInputStream in = new FileInputStream(f);
            MemoryBlock blk = mem.createInitializedBlock(
                    name, at, in, f.length(), monitor, false);
            in.close();
            blk.setRead(true);
            blk.setWrite(true);
            blk.setExecute(true);
            println(String.format("  + %-8s 0x%08X + 0x%X  from %s",
                    name, addr, f.length(), f.getName()));
        }

        for (Object[] b : EMPTY) {
            Address at = toAddr((Long) b[1]);
            if (mem.getBlock(at) != null) {
                continue;
            }
            MemoryBlock blk = mem.createUninitializedBlock(
                    (String) b[0], at, (Long) b[2], false);
            blk.setRead(true);
            blk.setWrite(true);
            blk.setExecute((Boolean) b[3]);
            println(String.format("  + %-8s 0x%08X + 0x%X  (empty)",
                    b[0], b[1], b[2]));
        }
    }
}
