# gp150-htfw

Tools and notes for Valeton's **HTFW** firmware container, worked out from the
GP-150 images. The container is shared across the GP-5 / GP-50 / GP-150 family.

Two things here are, as far as we can tell, not published anywhere else:

- **the region checksum algorithm** — CRC-16/MODBUS, stored big-endian;
- **the payload packing** — LZO1X with a 4-byte length prefix, which is what makes
  GP-150 **V1.1.1 and later editable at all**.

Both are verified byte-exactly, not inferred. Prior work by
[drewmerc302/valeton-gp50](https://github.com/drewmerc302/valeton-gp50) documents
the same container but records the checksum only as "u16 checksum of the region"
and lists the compressed region as unexamined.

No firmware is distributed here. Download images from valeton.net yourself.

---

## Container format

```
0x00  char[4]   "HTFW"
0x04  u32       build id (high half 0x0001); not derived from content
0x08  u32       total file size
0x0C  char[16]  model name, NUL padded — "GP-150"
0x1C  u16       0x0156 constant
0x1E  u8        minor version
0x1F  u8        patch version
0x20  u32       unknown (0x00070000 on GP-150 V1.0.5)
0x24  u32       uncompressed payload size = sum of all region lengths
0x38  region table, 16-byte records, terminated by FF FF FF FF:
        [0:2]   CRC-16/MODBUS of the region, stored BIG-ENDIAN
        [2]     0x00
        [3]     region id, ASCII 'b'..'h'
        [4:8]   destination address in flash
        [8:12]  offset of the region inside the payload
        [12:16] region length
```

The version string `V1xx` sits at region-`b` offset 8, right after the `FF FF FF FF`
sentinel that the first region swallows.

### Checksum

**CRC-16/MODBUS**, stored big-endian in the region record.

```
poly = 0x8005   init = 0xFFFF   refin = true   refout = true   xorout = 0x0000
```

Verified 7/7 on GP-150 V1.0.5 and 7/7 on the decompressed V1.1.1 payload.

### Packing

V1.0.5 stores the payload raw. **V1.1.1 packs it:**

```
after the region table:
  u32   uncompressed length, little endian
  ...   LZO1X stream
```

This is the same miniLZO that Valeton Suite ships as `minilzo_plugin.dll`
(exports `initLizo`, `startCompress`, `startDeCompress`). On GP-150 V1.1.1 the
prefix at `0xA8` reads `0x007A8EB0` = 8 031 920, matching header `0x24` exactly.

`tools/lzo1x.py` is a dependency-free decompressor. `tools/lzodll.py` calls the
DLL through `ctypes` when you need to compress; the recovered signatures are

```c
int startCompress  (const void *src, size_t src_len, void *dst, size_t *dst_len);
int startDeCompress(const void *src, size_t src_len, void *dst, size_t *dst_len);
```

Unpack + repack of an untouched V1.1.1 reproduces the original file **byte for
byte**, same SHA-256 — so the DLL's compressor settings match Valeton's own.

---

## Tools

### `tools/htfw_tool.py`

```
htfw_tool.py info    <fw.bin>              header + region table
htfw_tool.py verify  <fw.bin>              recompute and check every region CRC
htfw_tool.py unpack  <fw.bin> <dir>        header.bin + region_?.bin
htfw_tool.py repack  <orig> <dir> <out>    rebuild, fixing CRCs, offsets and sizes
```

Handles both raw and LZO-packed images. Repacking a packed image needs
`minilzo_plugin.dll`, i.e. a Valeton Suite install on the same machine.

### `tools/gfx_tool.py`

Firmware graphics are **RGB565 + 8-bit alpha, 3 bytes per pixel**, uncompressed,
rows top to bottom, no per-image header.

```
gfx_tool.py slots
gfx_tool.py extract <fw.bin> <addr> <w> <h> <out.png>
gfx_tool.py inject  <fw.bin> <addr> <w> <h> <in.png> <out.bin>
```

`inject` writes exactly as many bytes as it replaces, so nothing shifts and the
region table stays valid; it recomputes the affected region's CRC afterwards.
Slot geometry was recovered by row-stride analysis — heights are the least certain
value, so extract and look before you inject.

### `tools/rt_analyze.py`

Sets Ghidra up for the GP-150's SoC. Needs PyGhidra and `GHIDRA_INSTALL_DIR`.

Build a flat flash image with each region at its own flash address, import it as
`ARM:LE:32:Cortex` based at `0x60000000` (FlexSPI XIP), then add the rest of the
i.MX RT1064 map as uninitialised blocks — ITCM `0x0`, DTCM `0x20000000`,
OCRAM `0x20200000`, SDRAM `0x80000000`, AIPS `0x40000000` — disassemble the code
regions as Thumb and re-analyse. That yields ~1730 functions where a flat import
yields none.

---

## Hardware

The GP-150 runs an **NXP i.MX RT1064** (Cortex-M7) on a shielded module marked
`CC25A145`, with a separate JieLi BT-audio SoC for Bluetooth/BLE. Confirmed
against the image three ways: initial SP `0x20008000` in DTCM, globals at
`0x2021xxxx` in OCRAM, code addresses `0x8000xxxx` in SEMC-attached SDRAM.

Flash layout follows the family convention — the force-update bootloader lives
below the first region base (`0x38000` on GP-150) and the update protocol has no
command that reaches it, so a bad application image is recoverable.

---

## What is still open

- **Where the SDRAM-resident application lives in the file.** The flash-resident
  code is a bootstrap that calls into `0x8000xxxx` through a `MOVW/MOVT/BX` veneer
  table. No linear mapping of any region to `0x80000000` was found; tested per
  region, by free delta sweep over recovered function entries, and by an aligned
  full-file sweep (best 8/91 veneer targets against 0.35 expected — noise).
- Region `g` — 631 KB, entropy 7.97, byte-identical across firmware versions, so
  it is static data rather than code. Not unpacked, and not needed for anything
  reached so far.
- Header field `0x04`. Left untouched by these tools.

`FINDINGS.md` carries the full working notes, including the approaches that failed
and two corrections to earlier conclusions.

---

## Cautions

- Model string and version label **are** validated by newer boot software; a
  changed version label is refused silently. These tools leave both alone.
- Same-length edits only. A length change to a region is a different problem.
- Nothing here has been flashed to hardware by this project. Firmware modification
  voids your warranty and is entirely at your own risk.
- Do not redistribute Valeton's firmware images, their `module*_data.json`
  catalogs, or artwork extracted from them.

## Credits

- [drewmerc302/valeton-gp50](https://github.com/drewmerc302/valeton-gp50) — independent
  decode of the same container, GP-150 research notes, editor SysEx protocol.
- [tntexplosivesltd/gp200-patcher](https://github.com/tntexplosivesltd/gp200-patcher)
  and [gp200-reversing.hashnode.dev](https://gp200-reversing.hashnode.dev) — GP-200
  work on the i.MX RT1060 sibling, flash dump and updater protocol.
- [youlsaion/valeton-gp5-english-patch](https://github.com/youlsaion/valeton-gp5-english-patch)
  — in-place string patching for GP-5 / GP-50 / GP-100.
