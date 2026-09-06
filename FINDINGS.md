# Valeton GP-150 firmware — reverse engineering notes

Based on `GP-150 Firmware V1.0.5.bin` (8 371 564 B) and `V1.1.1.bin` (5 001 052 B).

---

## 1. Container format `HTFW` — SOLVED

```
0x00  char[4]   "HTFW"
0x04  uint32    build id; high 16 bits = 0x0001. NOT content-derived.
                V1.0.5 = 0x00015A3A, V1.1.1 = 0x00018AE2
0x08  uint32    total file size
0x0C  char[16]  model name, NUL padded — "GP-150"
0x1C  'V', major, minor, patch      (56 01 00 05 = V1.0.5)
0x20  uint32    unknown
0x24  uint32    size of the image = sum of all section lengths
0x38  section table, 16-byte records, terminated by FF FF FF FF:
        [0:2]   CRC-16/MODBUS of section data, stored BIG-ENDIAN
        [2]     0x00
        [3]     section tag, ASCII 'b'..'h'
        [4:8]   destination address in flash
        [8:12]  offset of the section inside the image
        [12:16] section length

payload starts at:  filesize - header[0x24]        (0xA8 for V1.0.5)
```

### Checksum — SOLVED

**CRC-16/MODBUS**, stored big-endian.
`poly=0x8005  init=0xFFFF  refin=true  refout=true  xorout=0x0000`

Verified on all 7 sections of V1.0.5 — 7/7 exact.

### Section table, V1.0.5

| tag | flash      | image off  | length     | contents |
|-----|-----------|-----------|-----------|----------|
| b | `0x00038000` | `0x00000000` | `0x004EA810` | 80 KB code at the start, then data + UI strings |
| c | `0x00740000` | `0x004EA810` | `0x000C0000` | data |
| d | `0x00800000` | `0x005AA810` | `0x00126578` | **main code**, Thumb-2 + VFP (DSP) |
| e | `0x009C0000` | `0x006D0D88` | `0x00049000` | cabinet / IR names + data |
| f | `0x00A80000` | `0x00719D88` | `0x00040000` | data |
| g | `0x00000000` | `0x00759D88` | `0x0009DF7C` | data |
| h | `0x00000000` | `0x007F7D04` | `0x00003FC0` | data |

Sections `e`, `f`, `g`, `h` are **byte-identical between V1.0.5 and V1.1.1** — same lengths and
same stored CRCs. This also proves the CRC is computed over *uncompressed* section data.

### Packing

- **V1.0.5 — raw.** Sections sum exactly to `filesize - 0xA8`. Unpack/repack round-trips
  byte-identically (verified).
- **V1.1.1 — packed.** Sections sum to 8 031 920 but the file is 5 001 052. Scheme not
  identified; no zlib/LZMA/LZ4/XZ/zstd stream header found. Likely a custom LZ.
  **Therefore V1.0.5 is the only practical target for patching today.**

---

## 2. Code layout

Determined by `BX LR` (`0x4770`) density — random rate is 1/65536, so blocks with dozens of
hits are code and blocks with zero are not.

```
file 0x000200 .. 0x014000    (~80 KB)   section b   general/control code
file 0x5AC000 .. 0x6D4000    (~1.2 MB)  section d   main code, float/DSP heavy
```

Everything else in the image is data.

- Architecture: **ARM Thumb-2 with VFP**. Confirmed by disassembly, e.g. at file `0x00C000`:
  `sdiv r2,r0,r1` / `mls r0,r1,r2,r0` / `bl #0x818` / `it ne` / `cmpne r0,#0` — unmistakably
  compiled C. Section `d` is full of `vldr` / `vstr` / `vmov.f32`.
- 421 116 instructions decoded across both regions with a restart-on-fault linear sweep.
- **Globals live in SRAM at `0x2021xxxx`**, loaded via `movw`/`movt` pairs
  (e.g. `movw r1,#0x241c` + `movt r1,#0x2021` → `0x2021241C`).
- Intra-section calls resolve directly in **file-offset space** — the mapping is linear, so
  patching does not require knowing the absolute base.

### Vector table

At file `0xD0`: `SP = 0x20008000`, reset = `0x80000159`, then fault handlers 2 bytes apart
(`b .` loops), 256 entries total, followed at file `0x4D0` by a `MOVW r12 / MOVT r12 / BX r12`
long-branch veneer table targeting `0x8000xxxx`.

### UNSOLVED: absolute base address

No mapping was found that makes absolute addresses resolve. Tested and rejected:

- `CPU = flash`, `0x80000000 + flash`, `0x60000000/0x08000000/0x90000000 + flash`,
  section-relative bases — all give **0 %** pointer resolution.
- Statistical correlation of 5 282 `movw`/`movt` constants and 1 647 LDR-literal values
  against 794 string offsets — no spike above background.
- Literal pools turned out to hold mostly float constants (`0x3F800000`, `0x46490E49`, …),
  not addresses.

**No absolute pointers to functions or to strings exist anywhere in the image.** The most
likely explanation is position-independent code using a static base register. Resolving this
needs data-flow analysis in the Ghidra GUI, not pattern matching.

---

## 3. UI string table (section b, file `0x27D400`..`0x27E200`)

Plain packed NUL-terminated strings, variable length. Relevant entries:

```
0x27DBC9  'Footswitch'      <- the setting
0x27DC71  'Stomp'           <- its values
0x27DBB9  'Patch'

0x27DD01  'EXP Settings'    0x27DB01  'EXP Calibrate'
0x27DA01  'Knob/EXP'        0x27DA51  'EXP/FS'
0x27D9A1  'EXP1 A/B'        0x27D989  'EXP 1-A'      0x27D999  'EXP 1-B'
0x27D829  'EXP 1'           0x27D855  'EXP 2'
0x27D831  'EXT FS 1'        0x27D85D  'EXT FS 2'
0x27DA3D  'Single FS'       0x27DA49  'Dual FS'
0x27D6D5  'Press the pedal\nfully down\ntowards toe.'
0x27D715  'Lift the pedal fully\nup towards heel.'
```

### Practical implication

`EXP1 A/B` together with `EXP 1-A` / `EXP 1-B` strongly suggests the firmware **already**
splits expression pedal travel into two zones with separate assignments. Before attempting
any binary patch, check on the device: **EXP Settings → EXP1 A/B**. If that mechanism can be
pointed at the footswitch mode, the desired behaviour may be reachable from the stock menu.

---

## 4. Tooling produced

`htfw_tool.py` — verified working:

```
htfw_tool.py info    <fw.bin>          parse and print the header + section table
htfw_tool.py verify  <fw.bin>          recompute and check every section CRC
htfw_tool.py unpack  <fw.bin> <dir>    split into header.bin + section_?.bin
htfw_tool.py repack  <orig> <dir> <out>  rebuild, recomputing CRCs and offsets
```

Round-trip on V1.0.5 produces a **byte-identical** file. `verify` reports 7/7 OK.
`repack` leaves header field `0x04` untouched, since its meaning is unknown — if the
bootloader validates it, a patched image may be rejected. Untested against hardware.

---

## 5. State of the feature request

Goal: expression pedal position selects footswitch mode — below 50 % = Stomp, above = Patch,
toggleable in settings.

| step | state |
|------|-------|
| unpack / repack container | done, verified |
| CRC recomputation | done, verified |
| locate code regions | done |
| absolute base address | **unsolved** |
| find the Footswitch=Stomp/Patch handler | not reached |
| find expression pedal ADC path | not reached |
| find a code cave, write the hook | not reached |
| flash and test | not attempted — brick risk is real |

The remaining steps need interactive reverse engineering and hardware to test against.

---

## 6. Bootloader does NOT validate the image

Established from https://github.com/youlsaion/valeton-gp5-english-patch — PowerShell scripts
that translate GP-5 / GP-50 / GP-100 firmware by overwriting Chinese strings in place.

The scripts contain **no checksum, CRC, hash or verification logic of any kind** (grepped),
they simply `WriteAllBytes` the modified buffer. The GP-50 V1.0.5 patch is reported as tested
and working on real hardware.

Conclusions:

- The bootloader ignores the section CRC, the header, and field `0x04`.
- A modified image flashes and boots. `htfw_tool.py` recomputes CRCs anyway, which is
  strictly safer but apparently not required.
- The bootloader lives in flash `0x00000000..0x00038000`, below section `b`, and is never
  written by an application update — hence the `Firmware update/restore` recovery screen
  survives a bad application image. Brick risk for a data-only patch is low.

Cross-validation of the container format: that project checks for `"V106"` at offset `0x90`
on the GP-5. GP-150 has `"V105"` at `0xB0`. The difference is exactly `0x20` = two extra
16-byte section records (GP-5 has 5 sections, GP-150 has 7). The format description above
therefore holds across the whole GP family.

---

## 7. Additional dead ends (second pass)

All of these were tried and produced nothing:

| approach | result |
|---|---|
| prior art search (Valeton / Hotone firmware RE) | nothing exists beyond the string patcher above |
| string offset table, found by difference signature `[8,4,12,20,8,8,12,8,8]` (base independent) | 0 matches as uint16 or uint32 |
| string IDs by counting NUL terminators, then looking for IDs clustered in a menu descriptor | only u8 noise |
| ARM-mode (32-bit) code — `BX LR` = `0xE12FFF1E` | **0 occurrences in the entire file**; everything is Thumb |
| any dword pointing into the UI blob's flash window | 5 hits vs 5.2 expected by chance — pure noise |
| Cortex-M system registers as anchors (`CPACR 0xE000ED88`, `VTOR 0xE000ED08`, `NVIC 0xE000E100`) | each matches once, but all land inside repeating data patterns, not code — false positives |

The image contains **no absolute pointer to any string and no absolute pointer to any
function**. Combined with the absence of an offset table, the string base must be computed at
runtime. Recovering it requires data-flow analysis (Ghidra GUI) or hardware experimentation —
static pattern matching cannot get there.

---

## 8. THE CHIP — identified from board photos

Main board carries a shielded **system-on-module**, silkscreen `CC25A145`, label
`CC25122 / 62669YB / 1.5.0`. Under the shield:

```
nxp
MRT1064D          ->  NXP i.MX RT1064   (Arm Cortex-M7, up to 600 MHz)
1N08X
CTUZC8
```

Alongside on the mainboard: a **JieLi ("JL")** Bluetooth-audio SoC with its own crystal and
a U.FL antenna connector (this is the BT/BLE path the mobile app uses, not the main CPU),
an IP2312-class charger, and NE5532/4580-class op-amps in the analogue path.

### i.MX RT1064 memory map vs. what the firmware actually does

| region | address | evidence from the image |
|---|---|---|
| ITCM | `0x00000000` | — |
| **DTCM** | `0x20000000` | initial SP = `0x20008000` ✔ |
| **OCRAM** | `0x20200000` | globals at `0x2021xxxx`, **9584** movw/movt references ✔ |
| FlexSPI1 (external QSPI XIP) | `0x60000000` | 0 references |
| FlexSPI2 (internal 4 MB flash) | `0x70000000` | 0 references |
| **SEMC / external SDRAM** | `0x80000000` | code addresses `0x8000xxxx`, 275 distinct refs ✔ |
| AIPS peripherals | `0x40000000` | GPIO1, GPIO2, SAI1, LPSPI1 base addresses each referenced at `+0x0` |

Three independent matches (stack in DTCM, globals in OCRAM, code in SDRAM) confirm the part.

### Why every static approach failed

**The application executes from external SDRAM at `0x80000000`, copied there at boot.**
The addresses it uses at run time are not the addresses anything has inside the flash image,
so absolute pointers to strings or functions simply do not exist in the file. That single fact
explains sections 2 and 7 in their entirety.

### What this unblocks for whoever continues

- The i.MX RT1064 reference manual and the MCUXpresso SDK are public. Peripheral addresses,
  boot flow (FlexSPI XIP → SDRAM), and the ROM bootloader are all documented.
- **The expression pedal ADC is ADC1 `0x400C4000` or ADC2 `0x400C8000`** — the original
  feature request now has a concrete place to look.
- Ghidra should be configured as Cortex-M7 with separate blocks for ITCM/DTCM/OCRAM/SDRAM
  rather than as one flat binary.
- Still open: the exact SDRAM load address of the code. The 275 SDRAM constants reach
  `0x81E00000` (30 MB in) and look like frame/audio buffers, not code pointers. No section
  mapped at `0x80000000` yields a sane function-prologue rate (best 1.3 %).

---

## 9. Ghidra, configured for the real chip — and what it settled

Setup that works (PyGhidra 3.1, Ghidra 12.1.3, JDK 21):

1. Rebuild a flat flash image, each section placed at its own flash address
   (`b`→`0x38000`, `c`→`0x740000`, `d`→`0x800000`, `e`→`0x9C0000`, `f`→`0xA80000`;
   `g` and `h` have no flash address and are left out). 10.8 MB, `0xFF` filled.
2. Import as `ARM:LE:32:Cortex`, BinaryLoader, base **`0x60000000`** (FlexSPI1 XIP view).
3. Add uninitialised blocks: ITCM `0x0`, DTCM `0x20000000`, OCRAM `0x20200000`,
   SDRAM `0x80000000` (32 MB), AIPS `0x40000000`.
4. Disassemble the byte-statistics code regions as Thumb, then re-run auto analysis.

Result: **1730 functions, 349 562 instructions, 42 105 defined data items** — a real analysis.

References by target region:

```
ITCM/small   54715      flash-XIP  40121      OCRAM  19292
SDRAM         1906      other       1398      AIPS     254      DTCM  4
```

Peripherals actually touched by the flash-resident code: `GPIO1` (6), `SAI1` (2, the audio
codec), `GPIO2` (2), `LPSPI1` (1), `GPIO3` (1). **No ADC references at all.**

References into the UI string blob: **0**. Into the graphics blob: **0**.

---

## 10. The structural answer

```
flash 0x000000..0x038000   bootloader — NOT in the firmware file, cannot be touched
section b  @ 0x038000      startup, vector table, veneer table into SDRAM,
                           low-level init (GPIO / SAI1 / LPSPI1)
section c  @ 0x740000      data
section d  @ 0x800000      DSP / audio code, runs XIP from flash, float heavy
section e  @ 0x9C0000      cabinet and IR names + data
section f  @ 0xA80000      font glyphs
section g  (no flash addr) 631 KB, entropy 7.97, no known compression header
section h  (no flash addr) 15 KB, looks like an index / relocation table
```

**The application — menus, settings, footswitch and expression handling — is section `g`,
loaded into SDRAM at `0x80000000` at boot.** The chain of evidence:

- `g` and `h` are the only sections with no flash destination, so they are loaded, not flashed.
- The flash code reaches SDRAM only through a 91-entry veneer table (`MOVW/MOVT/BX r12`)
  targeting `0x80000345..0x8004AF45`.
- Ghidra finds zero references from flash code to the UI strings or the graphics.
- Ghidra finds no ADC access in flash code, so the expression pedal is not read there.

Everything this project set out to change lives inside section `g`.

`zlib`, raw deflate, `gzip`, `lzma`, `lzma_alone` and `bzip2` were all tried at offsets
0/4/8/12/16 — none decompress it. Either a custom LZ or an encrypted blob (entropy 7.97 fits
both). One tension worth noting: 631 KB of "compressed" data against roughly 300 KB of SDRAM
code that the veneers reach, which would be back to front for compression — so encryption, or
a much larger SDRAM image than the veneers cover, are the likelier readings.

**This is the wall.** It is now a specific, well-defined one: unpack section `g`.

---

## 11. Cross-validation against two independent projects

### 11.1 `drewmerc302/valeton-gp50` — `re/HTFW_FORMAT.md`

An independent decode of the same container, cracked 2026-07-22 against GP-5, GP-50
and GP-150 firmware. **It matches the format derived here field for field**: `HTFW`
magic, u32 total size at `0x08`, 16-byte model string at `0x0C`, payload total at
`0x24`, 16-byte TOC records from `0x38` terminated by `FF FF FF FF`, record layout
`u16 checksum / 0x00 / ASCII id / load addr / offset / length`, and
`payload_base = filesize - payload_total` = `0xA8` on GP-150. They also note the
first region swallows the sentinel and the `V1xx` string — matching the finding here
that `V105` sits at section-`b` offset 8.

Two things this project has that theirs does not:

- **the checksum algorithm.** They record only "u16 checksum of the region".
  Here it is identified as **CRC-16/MODBUS stored big-endian**, verified 7/7.
- a decode of the graphics format (RGB565 + 8-bit alpha) and the image map.

Their GP-150 notes list region `g` as *"compressed (entropy 7.99) — unexamined"*
and, separately, *"GP-150 firmware region `g` is compressed — unexplored lead"*.

### 11.2 `tntexplosivesltd/gp200-patcher` + gp200-reversing.hashnode.dev

GP-200 runs an **NXP i.MX RT1060** — same family as the GP-150's RT1064. Independent
confirmations of conclusions reached here:

- flash is memory-mapped at **`0x60000000`** (FlexSPI);
- *"Flash acts as a loader stage only. The real application gets copied into RAM and
  executes there; the functions Ghidra found sitting in flash are the bootstrap and
  relocator."*
- the force-update bootloader lives **below the first partition base** and the update
  protocol has no command that reaches it — by design, on every model in the family;
- HAB is open, images are unsigned (`csf = 0`), `SEC_CONFIG` bit clear;
- their flash dump was taken with **OpenOCD + ST-LINK over SWD**,
  `dump_image` of `0x60000000` for `0x800000`.

Partition bases line up exactly with the GP-150's: GP-200 uses `0x20000`, `0x4E0000`,
`0x500000`, `0x700000`; GP-150 uses `0x38000`, `0x740000`, `0x800000`, `0x9C0000`,
`0xA80000`. The version tag convention matches too — GP-200 keeps `"V180"` at
partition-0 offset 8, GP-150 keeps `"V105"` at section-`b` offset 8. USB identity
follows the same +1 rule: GP-200 `84EF:002A` normal / `84EF:002B` update,
GP-150 `84EF:0186` / `84EF:0187`.

Difference worth recording: GP-200 has **no whole-image checksum at all** ("nothing in
the image matches a byte-sum over any candidate range"), while GP-150 carries a
per-region CRC-16/MODBUS. The GP-150 container is the newer generation.

Also relevant: that author's mods are **string-table edits only** — *"two string-table
edits, proven and repeatable, not custom code yet."* Nobody in either project has
patched code, and nobody has unpacked a compressed region.

### 11.3 Editor SysEx protocol (from the GP-50 project)

Frames are `F0 <nibble stream> F7`; each pair of 4-bit nibbles reassembles one byte.
The decoded buffer's byte 0 is a **CRC-8/0x07, init 0**, computed over the whole
decoded buffer with byte 0 zeroed. Read selectors `0x40` (patch names) and `0x41`
(active patch body); bulk write is `0x1D`. Their standing warning: *"sending guessed
traffic wedged the pedal once."*

The device was probed live here in **normal** mode (PID `0186`, MIDI ports
"Valeton GP-150 Subdevice 0/1"): MIDI Identity Request, and the GP-200 updater frames
`F0 7E 48 7F F7` / `F0 7E 48 01 F7`, all read-only. **No replies.** Expected — the
updater protocol only answers in update mode (PID `0187`).

### 11.4 Parameter-type cross-check — negative

`module150_data.json` (2.0 MB, shipped inside Valeton Suite) parses cleanly:
12 modules (PRE, WAH, DST, N->S, AMP, NR, CAB, EQ, MOD, DLY, RVB, VOL), 348 effects,
including 100 SnapTone slots, 20 "A2 Lite" and 20 "User IR" — which independently
confirms the effect-icon set and the `User IR 1..20` strings found in the image.

Its parameter records carry `code: "ValToStr_NNN"` (31 distinct, suffixes 0..192) and
`widgetType` (0..3). Cross-referenced against the constants in `FUN_6004afe8`
(`0x20 0x22 0x30 0x33 0x34 0x36 0x44 0x47 0x55 0x57 0x62 0x67 0x68`):
**3 of 13 overlap (34, 52, 85) — chance level for 31 codes over a 0..192 range.**
The firmware constants are not catalog ids.

---

## 12. Corrections to earlier sections

- **§7's premise stands, but one intermediate result in this session was wrong.**
  A numpy sweep looking for the SDRAM load base initially reported 32/91 veneer
  targets landing on function prologues at file `0x13A3D` — against a chance
  expectation of 0.3. It was an artifact: the prologue mask had been built from
  **unaligned** halfwords, so the hits fell on an odd offset. Disassembling there
  showed noise. Rebuilt with correct halfword alignment, the best candidate over the
  whole file is **8/91** against 0.35 expected, in a flat tail (8,7,7,7,7,7,…) —
  a noise distribution, not a signal.
- **There is no linear mapping of any part of the file to SDRAM `0x80000000`.**
  Confirmed three ways: per-section tests, a free delta sweep over Ghidra's function
  entries, and the aligned full-file sweep above.
- **No IVT in the update image.** A scan for the i.MX RT IVT tag (`D1 00 20 4x`)
  returns zero hits, as expected: the IVT belongs to the bootloader region, which the
  update file never carries.
- **Section `b` is exhausted.** All 399 functions decompiled (19,248 lines) and scored
  twice — once for bitstream/mask/loop shape, once for LZ back-reference shape. The
  top candidates are an audio sample-format converter (`FUN_6003a2c0`, a 512-sample
  ring buffer with 16/24/32-bit branches) and a parameter interpolation routine
  (`FUN_6004afe8`, `min + ((max-min) * v) >> 8` over a 0..255 control value — this is
  the expression/modulation scaler). **No decompressor.**

## 13. Where the wall now sits, precisely

The section-`g` decompressor is **not in the firmware update file**. Per the GP-200
evidence it lives in the bootloader below the first partition base, which the update
protocol cannot address by design on any model in this family.

Reaching it needs a flash dump over **SWD** (OpenOCD + ST-LINK, `dump_image
0x60000000 0x800000`), exactly as the GP-200 author did. That is a hardware step:
locating the SWD pads on the GP-150's RT1064 module and attaching a probe. No amount
of analysis of the update file substitutes for it.

### 12.1 Correction to §6 — the bootloader is not entirely blind

§6 concluded "the bootloader ignores the section CRC, the header, and field `0x04`",
from the GP-5 English-patch scripts recomputing nothing. That is right about the CRC
but too broad. The GP-200 patcher's README documents a real, enforced check:

> "Earlier releases changed a version label inside the firmware file, and units with
> newer boot software refuse an update when that label has been changed. They refuse
> it silently."

Confirmed on units reporting Boot `V0.0.5` and `V0.0.6`. The editor also reads the
model string out of the file and refuses a mismatch against the connected unit.

So: **model string and version label are validated; the region CRC apparently is
not.** Leaving both untouched — which `htfw_tool.py` and `gfx_tool.py` already do —
is the correct behaviour, and recomputing the CRC anyway costs nothing.

The GP-200 also exposes a factory QC screen (hold BACK+SAVE while powering on) that
reports the `Boot:` version. A GP-150 equivalent, if it exists, would be worth
knowing before flashing anything.

---

## 14. PACKING SOLVED — V1.1.1 is LZO1X

The lead came from the Valeton Suite install itself: `minilzo_plugin.dll` sits next to
the executable, exporting `initLizo`, `startCompress`, `startDeCompress`.

**Packed layout** (V1.1.1 and, presumably, everything after it):

```
0x00        HTFW header + TOC, exactly as in §1
table_end   u32  uncompressed payload length, little endian
table_end+4 LZO1X stream
```

For V1.1.1: prefix at `0xA8` = `0x007A8EB0` = 8 031 920, matching header `0x24`
exactly; the stream runs from `0xAC` to EOF.

### Proof

A pure-Python LZO1X decompressor (`lzo1x.py`) unpacks the stream to 8 031 920 bytes,
and **all seven section CRC-16/MODBUS values verify against the decompressed payload**:

```
b 0xEFA4  c 0x5137  d 0xAE63  e 0xA367  f 0x0FB6  g 0x0D22  h 0x6F93   -> 7/7 OK
```

Cross-checked against Valeton's own DLL through `ctypes` (`lzodll.py`): the DLL's
`startDeCompress` produces byte-identical output to the Python implementation, and the
Python implementation correctly decodes streams produced by the DLL's `startCompress`.

Export signatures recovered by disassembling the DLL (x64, 4 register args, the
work memory is supplied internally):

```c
int startCompress  (const void *src, size_t src_len, void *dst, size_t *dst_len);
int startDeCompress(const void *src, size_t src_len, void *dst, size_t *dst_len);
```

### Round-trip

`htfw_tool.py unpack` then `repack` on V1.1.1 reproduces the original file
**byte for byte** — same 5 001 052 bytes, same SHA-256
`6f1d4357086aa869c4856afa0279feb892ff72124a094d7d40a417fe641236d3`. The DLL's
compressor settings match Valeton's own, so a rebuilt image is indistinguishable from
the shipped one.

**This means V1.1.1 — the version with NAM/SnapTone — is now fully editable:**
unpack, patch a section, repack, and the container is valid. Neither reference project
had this; both list the compressed region as unexamined.

## 15. Section `g` is NOT the application

Settled by a version diff. Sections `e`, `f`, `g`, `h` are **byte-identical between
V1.0.5 and V1.1.1** (same lengths, same stored CRCs), while `b`, `c` and `d` all
changed. V1.1.1 added NAM A2 support, so the application code necessarily changed —
therefore it cannot live in `g`. §10's reading was wrong.

`BX LR` density per section settles where the ARM code actually is:

| section | 1.0.5 | 1.1.1 | reading |
|---|---|---|---|
| b | 0.02 /KB | 0.11 /KB | data, plus the ~80 KB bootstrap at the start |
| c | 0.00 /KB | 0.00 /KB | data (shrank 786 KB -> 340 KB between versions) |
| **d** | **1.43 /KB** | **1.41 /KB** | **the application — 1.2 MB of Thumb-2 + VFP** |
| e, f, g, h | ~0.00 /KB | ~0.00 /KB | data |

So `g` is 631 KB of static, high-entropy data that never changes between firmware
versions — model or sample data, not code. It does not need unpacking to reach the
footswitch logic.

The veneer table was re-verified with capstone rather than hand bit-twiddling —
`movw ip,#0xdeb / movt ip,#0x8000 / bx ip` — so the `0x8000xxxx` targets are real. How
section `d` comes to be addressed at `0x80000000` at run time is still open, but it is
now a relocation question about a section already in hand, not a decompression one.

---

## 16. Confirmed on hardware

A GP-150 V1.1.1 image rebuilt by `htfw_tool.py` — unpacked, one region of graphics
replaced, repacked with LZO — **was accepted by Valeton's own updater and flashed
successfully**. The unit rebooted and works normally afterwards.

Two things this settles:

- The whole pipeline is correct end to end, not just self-consistent on disk.
- **A larger file is accepted.** The patched image was 5 051 932 bytes against the
  stock 5 001 052 (+50 KB, photographic content compresses worse than the stock
  vector-style artwork). The updater read the size from the header and proceeded.
  What must stay untouched is the model string and the version label.

### Regions `g` and `h` identified — by watching the updater

The update runs in two phases. The second is captioned **"BT And PD Updating"**,
with its own progress bar, after the main firmware phase completes.

That names the two regions that never fit the RT1064 memory map:

| region | size | what it is |
|---|---|---|
| `g` | 631 KB | **firmware for the JieLi Bluetooth/BLE SoC** |
| `h` | 15 KB | **firmware/config for the PD (USB power delivery) controller** |

Everything now fits:

- neither contains ARM Thumb code (`BX LR` density 0.00–0.01 /KB) because neither
  targets the Cortex-M7;
- both carry flash address `0x00000000` because they are not written into the
  RT1064's flash map at all — they are forwarded to other chips;
- both are byte-identical between V1.0.5 and V1.1.1 because neither peripheral's
  firmware changed;
- `g`'s entropy of 7.97 is JieLi's own packaging, not something the RT1064 unpacks —
  which is why no decompressor for it exists anywhere in the image, and why looking
  for one in region `b` was always going to fail.

§10 and §13 chased region `g` as the missing application. It never was. The JieLi
part is the chip visible next to the shield can in the board photographs, with its
own crystal and U.FL antenna connector.

---

## 17. The images index themselves — and the pixel order was backwards

Every stored image is preceded by a **12-byte descriptor**:

```
u32 desc;   /* [7:0]   0x05, format tag: RGB565 + alpha, 3 bytes/pixel
               [19:8]  width  * 4
               [31:20] height * 2                                        */
u32 size;   /* width * height * 3, always                                */
u32 addr;   /* SDRAM address of this descriptor                          */
            /* the pixels follow immediately                             */
```

Found by measuring drift. A sheet of pedal icons recovered a width of 80 with no
ambiguity (row-difference score 5.1 against 11.4 for 79 and 81, everywhere in the
region), yet each image down the sheet came out rolled **exactly four pixels**
further right than the one above it. A constant per-image roll can only mean the
stride is not `w*h`: the true step was 80·102 + 4 pixels, so twelve bytes sit
between images. Those twelve bytes carry the geometry.

The predicate is self-checking — `size` must equal `width * height * 3` with the
width and height taken from two other fields of a different word, about thirty
bits of agreement — so it can be swept over the whole payload without producing
junk. On GP-150 V1.1.1 it finds **132 images**, 1.60 MB of pixels; 112 of them
decode as artwork and the rest are blocks the loader allocated but never filled.

### The pixel order

**Colour first, then alpha:**

```
[0:2]  uint16 RGB565, little endian
[2]    uint8  alpha
```

§ earlier notes and `gfx_tool.py`'s header said alpha-first, argued from colour
statistics. That was wrong, and wrong in the way that is hardest to catch: reading
the same bytes one position over still yields a recognisable icon, because the
shape survives — it just wears the neighbouring pixel's alpha and comes out olive.
The statistics could not settle it because they compared two readings of a
*window* whose true first pixel was unknown. A descriptor gives the exact first
pixel, and then the question is decided by looking once: the DST pedal is red, the
AMP tile orange, VOL green, NAM purple. Under alpha-first every one of them is
the same olive.

This is also why the hand-checked offsets in the old curated list all sat one byte
early — each was the alpha byte of the pixel before the image's real first pixel.

### These are allocator headers, not a resource table

Consecutive blocks chain: `hdr + 12 + size` is the next `hdr`. `addr` is an SDRAM
address, and along a run of chained blocks `addr - file_offset` is **constant**:

```
+0x7FFC4C4F   16 blocks   file 0x12EE4D..0x18E90D
+0x7FFC8A2F   16 blocks   file 0x1AA74D..0x1CC40D
+0x7FFC9FEF    8 blocks   file 0x0B7BA5..0x0BDC05
+0x7FFC9E63    8 blocks   file 0x1E5CE5..0x1EC9A5
```

So this part of section `b` is a **heap image copied to SDRAM verbatim** — which
is the first linear file→`0x80000000` mapping anyone here has been able to
demonstrate (§2 and the "what is still open" list record the failed searches).
It is not one mapping for the whole section: the delta changes between runs, as
it would for a heap whose blocks were allocated in several passes. Free or
never-filled blocks are in the image too, which is why a handful of descriptors
point at noise.

`tools/gfx_index.py` implements the scan, the decode and the encode; Studio's
Graphics tab is driven by it, and no width has to be nudged for an indexed image.

---

## 18. The NAM path, end to end - and the pedal really does run NAM

`.nam` never reaches the pedal. Valeton Suite converts it to **`.namb`**, magic
`BMAN`, and that is what is uploaded. The converter is in Suite's own
`assets/5868USB.dll` and is exported as plain C, so it can be driven from a
script (`tools/nam2namb.py`):

```c
const char *convertNamToNambAtPath(const char *in, const char *out, double slim);
const char *convertNamToNambWithSlim(const char *in, double slim);
const char *convertNamToNamb(const char *in);
const char *getLastNamToNambError(void);
```

The wrappers are three instructions each - `convertNamToNamb` is
`xorps xmm2,xmm2; xor edx,edx; jmp common`, so slim defaults to 0 and the output
path to one derived from the input - and they all reach
`convertNamFileToNambFile(std::string const&, std::string const&, bool, double)`.
The library also carries the strings of a `nam2namb [--slim <factor>] input.nam
[output.namb]` command line, so this was a standalone tool before it was a DLL.

**The magic is in the firmware.** `BMAN` appears once in section `b`, at
`0x00E818`, sitting in a literal pool between Thumb functions. The pedal parses
NAMB itself; the RT1064 is running the capture's own WaveNet, not a proprietary
model fitted to it. (That is the A2 generation. The A1 devices - GP-5, GP-50 -
get a *refit* instead: `namConvertClo*` in the same library runs the NAM to
generate reference audio and fits a much smaller model to it. Two different
paths in one library, and only one of them applies here.)

### What a capture actually is now

Captures from TONE3000 are NAM 0.7.0 **SlimmableContainers**: one file holding
the same amp trained at two widths.

| submodel | channels | weights | MAC/sample | .namb | share of a 600 MHz M7 at 48 kHz |
|---|---|---|---|---|---|
| `max_value` 0.5 | 3 | 1871 | 1 731 | 7 980 B | ~14% |
| `max_value` 1 | 8 | 12 146 | 11 776 | 49 080 B | ~94% |

`slim` picks one of them and nothing else: the weights in the `.namb` are the
JSON's own float32 values, byte for byte. So the wide submodel is not a setting
anyone can afford - it would need most of the core on its own - and slim 0 is
the only real option on this hardware.

What that costs is measurable, and `nam2namb.py check` measures it by running
both models: 0.0026 ESR on a clean amp, 0.0115 on a high-gain lead - the
expected shape, since distortion is what compresses badly.

### The weight layout, confirmed by reconstruction

The forward pass in `nam2namb.py` is written from the config, and the layout is
not assumed: per layer array a 1x1 rechannel `(channels, input_size)`, then for
each layer the dilated conv `(out, in, tap)` and its bias, the condition mixin,
the 1x1 and its bias; then the array's head conv `(1, channels, 16)` and bias;
then `head_scale`, which appears both as a config field and as the last weight.
That accounts for **1871 weights exactly** at 3 channels and **12 146 exactly**
at 8, and the two independently trained submodels of one capture come out
correlated at **0.9963** - neither of which happens if the layout is wrong.

### The `.namb` container

```
0x00  char[4]  "BMAN"
0x04  u32      format version, 1
0x08  u32      total file size
0x0C  u32      offset of the weights, always 496
0x10  u32      number of weights
0x14  u32      length of the config block at 0x50
0x18  u32      checksum (not a byte sum; not needed to read one)
0x20  u8[3]    NAM version, 0 7 0
0x23  u8       architecture id, 1 = WaveNet
0x24  double   sample rate
0x2C  double   loudness, LUFS
0x50  ...      config block, then float32 weights at 0x1F0
```

## 19. Ghidra on the Windows library

The GP-50 project's notes came from the macOS `5868USB.dylib`. The Windows DLL
is the better target: it exports **61** symbols against the dylib's handful,
including the whole NAMB converter, and it is what a Windows install has on
disk anyway. `tools/ghidra/DecompileExports.java` drives a headless run -
import, analyse, decompile the named exports and everything they call to a given
depth, one `.c` per function.

Analysis of the 2.8 MB DLL takes about a minute; six exports at depth 2 come to
137 functions.

`checkCrc` decompiles to exactly what §1 and §12.1 describe, which is the first
independent confirmation of the container's checksum rules from Valeton's own
code rather than from measurement:

```c
if (file_length != *(u32 *)(header + 8))    return -2;   /* truncated      */
crc = 0xFFFF; for (p = data + 6; p < end; p++) crc = table_step(crc, *p);
if (be16(crc) != *(u16 *)(header + 4))      return -1;   /* checksum wrong */
return 0;
```

Two byte tables at `0x180190700` and `0x180190800` - the split high/low form of
one CRC-16 table - and the comparison assembles the result big-endian, matching
"stored big-endian" in §1.

The decompiled listings are Valeton's code however it is spelled, so they are
not in this repository; `work/` is gitignored for them.

---

## 20. The wire format, out of the library rather than guessed

Every host-to-device message is one SysEx frame around a four-byte header:

```
BUF  = [ crc8 ][ command ][ index ][ length ][ length payload bytes ]
wire = F0, then for each byte of BUF: (b >> 4), (b & 0x0F), then F7
```

`crc8` is CRC-8, polynomial `0x07`, init 0, no reflection, no final xor, over the
whole of BUF with its own slot held at zero. The nibble split is what keeps every
byte under `0x80`, as SysEx requires.

The builder is one function in `5868USB.dll` — a 4-byte header, the payload
appended, the table stepped over the lot, the checksum written back into byte 0,
then optionally the nibble split, then `0xF0 … 0xF7` in a two-line helper. Its
CRC table sits at `0x180195910`, and `tools/ht_packet.py verify` checks the table
it generates against those 256 bytes: **256 of 256 match**.

This is the same format `drewmerc302/valeton-gp50` recovered from the macOS
dylib and verified against 298 captured packets, so the two independent reads
agree — theirs from a capture, this one from the Windows library's own code.

### The firmware update, specifically

`deviceStartUpdate` does not stream the file. It:

1. parses the container and, if the header says packed, **LZO-decompresses the
   payload in memory** — the vendor's loader does exactly what `htfw_tool.py`
   does, which is another confirmation of §14;
2. walks the section table and **recomputes each section's CRC-16/MODBUS**,
   comparing it big-endian against the stored value, refusing the file on the
   first mismatch — the same rule as §1, in Valeton's own code;
3. builds one message per section whose payload is `0x11, <section id>` followed
   by the whole section;
4. splits that into blocks of **42 bytes** (`0x2A`), or **19** (`0x13`) when the
   device has been put in the compressed mode `setDeviceCompress` selects, and
   records `ceil(len / block)` as the section's block count.

For GP-150 V1.1.1 that is 191 240 frames of 94 bytes — 17.6 MB on the wire for a
5 MB file, which is what a nibble-split protocol costs.

`tools/ht_packet.py plan` prints the whole schedule and the first frame of each
section without opening a MIDI port. What the code does *not* settle is the
width of the block counter: `index` is one byte and a section runs to six figures
of blocks, so it must wrap, and where is a guess until someone captures a real
update. Nothing here has been sent to a device; the GP-50 project's warning that
guessed traffic wedged a pedal once stands.

---

## 21. The boot animation is a GIF, and it says where it came from

Section `b` carries one 448 KB run that no image descriptor covers and that
reads as noise at every width — the only window in the whole payload with
entropy above 7.9 outside region `g`. It is not compressed code and it is not
audio. It is a **GIF**: `0x207AE5`, 474 509 bytes, 320x240 — the screen's own
resolution — 57 frames at 40 ms. It is the splash: "GP-150 / HD MODELING TECH
II" resolving into "VALETON" over a drifting grid.

Its comment extension was left in:

```
GIF compressed with https://ezgif.com/optimize
```

so the animation went through a web optimiser on its way into the firmware.

Nothing indexes it — no descriptor, no table, no length field anywhere in the
format — so `tools/gif_tool.py` finds it by its own magic and walks the block
structure (extension, image descriptor, sub-block chains) to the trailer. That
matters here: the bytes immediately after it are more artwork, so guessing the
end would overwrite a picture.

It is replaceable. The slot cannot grow, but a GIF reader stops at the trailer,
so a smaller animation padded with zeros is valid — `gif_tool.py inject`, or
Studio's Graphics tab, which shows it animated at the top of the index and takes
a new one on a click. This also explains the largest of the four areas the region
scanner reported as graphics and could never make sense of.

---

## 22. The image descriptors are load-bearing

They are not documentation the firmware ignores. A build that painted a texture
over whole regions - and so wrote through the twelve header bytes in front of 90
of the 132 images - **booted, ran, played, and drew colour static where every
icon should be**. Photographs of the pedal show it: the menus, the labels and the
panels draw correctly, and each icon is a rectangle of noise.

That settles what these blocks are for. The heap image is copied to SDRAM and
something walks it by those headers; corrupt them and the walk goes off the
rails, so the draw calls read pixels from wherever the broken chain points.

Two consequences, both now enforced:

- **No write path may touch a descriptor.** `Project._check_span()` refuses any
  write that overlaps one, so replacing an image, drawing text, laying a texture
  or swapping the animation cannot do this by accident, whatever offset is typed.
- **A region write has to be cut around the images inside it.** The old bulk
  edit skipped a region only when the *region's start* fell inside an indexed
  block, and region 18 of V1.1.1 starts before twenty-three of them and runs
  straight over the lot. Regions are now split into the gaps between blocks, in
  whole rows so the pixel phase survives.

`gfx_index.py check <fw.bin> <stock.bin>` reports damaged descriptors against a
stock image of the same build, and `repair` copies the twelve bytes back without
touching a pixel - the artwork edits, whatever they were, survive. The build in
the photographs was repaired that way: 90 descriptors restored, vendor
`checkCrc()` accepted, the blue theme intact.

---

## 23. Where the interface is drawn from - and where it is not

The photographs of the pedal settled what the interface is made of. Its icons are
the indexed images (they came back recoloured after a Studio edit), its labels
are the strings in region `b`, and its panels, bars, highlights and the blue
behind everything are rectangles the code fills. So the question for an editor
is where that code lives, and this section is the answer, including the part
that is still missing.

### Region `d` is the DSP, and it runs from flash

Measured, not assumed. Count the 4-aligned words in a region that point back
inside that region, for each candidate load address:

| base | words pointing inside region `d` |
|---|---|
| **0x60800000** — its own flash address through FlexSPI | **798** |
| 0x00800000 | 364 |
| 0x00838000 | 250 |
| 0x80000000 | 239 |
| 0x70800000 | 41 |

So the application is **executed in place from flash**, not copied to SDRAM, and
`tools/flat_image.py` can hand a disassembler the whole firmware at the addresses
the chip sees. Region `b`'s bootstrap does the same at 0x60038000 (1066 words).

Decompiled, region `d` turns out to be the **audio** application: VFP throughout,
float tables in SDRAM, `*(float *)(0x81600000 + (int)(x * k) * 4)` - a waveshaper
lookup, not a framebuffer. Its 1.2 MB is the effects engine.

### The interface code is at 0x80000000, and it is not in the file

Region `b`'s bootstrap holds 73 veneers, and they decompile to exactly what they
look like:

```c
void FUN_6003ab36(void) { (*(code *)&LAB_8002dd74)(); return; }
```

so there is code at `0x80000000..0x8002F760` - 192 KB - that the flash-resident
bootstrap calls into. It is not in the firmware image. Three independent tests
say so:

- a Thumb-prologue sweep over **every** possible base in the payload: best 8 of
  73 veneer targets against 4.4 expected by chance;
- the 31 heap deltas recovered from the image descriptors, tried one at a time:
  best 2 of 73;
- no scatter-load table - no place where a flash address sits beside an SDRAM
  destination in that range.

And nothing in the whole 11 MB image contains the address of any UI string:
"Global Settings", "TAP Settings", "Input Level" are all there as text, and
**zero** words point at them.

What does point at them is an array of ~350 **SDRAM** pointers at payload
`0x290BC1`, next to the strings themselves - `0x8025A538`, `0x8025A714`, one per
label. That array is part of the heap image, so the string resources and their
table are both in the file and both editable; the code that walks them is not.

The likeliest explanation is the flash below `0x38000`, which no firmware image
covers: the update protocol writes regions `b`..`h` at their own addresses and
never touches the bootloader area (§6). A GUI framework living there would be
present on the device, absent from every update, and reachable only by reading
the flash off the chip.

### What that means for editing

Everything the interface is *made of* is editable: the 132 images, the boot
animation, the strings, and the string pointer table. What is not is the
geometry and the colours of the parts that are drawn rather than blitted -
panel fills, the blue background, the selection highlight - because the code
that holds those constants is not in the file. `tools/thumb_patch.py` can
rewrite a MOVW immediate anywhere it *is* in the file, which covers region `d`
and the bootstrap, and is the tool for the day the rest turns up.

---

## 24. The editor protocol, off the wire

The firmware could not be made to give it up (§23), and the vendor library turned
out not to carry it either: Suite loads `5868USB.dll` and then, for everything
except firmware updates and NAM conversion, never calls it. The MIDI goes
straight from Dart to **winmm** - `flutter_midi_command_windows` is FFI, and
there is no plugin DLL in the install to stand in front of. So the capture rig
moved a layer down (`tools/spy/build_midi_spy.py`), and 876 frames later:

### The frame

```
F0 7F <crc> [len16] [off16] [id_a] [id_b] <payload, nibble-encoded> F7
```

* **`crc` is CRC-8, polynomial 0x31, init 0x00, masked to seven bits.** It fits
  in a SysEx data byte, it verifies on **876 of 876** captured frames, and the
  table for that polynomial is in the firmware at payload `0x0331A8` - so this is
  the device's own checksum, not a guess that happened to fit. (The *updater*
  uses CRC-8/0x07 over a nibble-encoded buffer - a different protocol in the same
  box, §20.)
* `len16` and `off16` are 14-bit, two seven-bit halves, low first. In a reply
  `len16` is the **whole object's size** and `off16` is where the chunk goes; in
  a request both are zero and the arguments are in the payload.
* `id_a`/`id_b` pair a reply to its request.
* the payload is **nibble-encoded**, two wire bytes per byte, high nibble first.
  A full chunk carries **119 bytes**, which is why offsets step by 119.

A read request looks like this, and the five that follow it differ only in the
offset and the sequence number:

```
00 00  03 06  02 05   01 00  5C 03  77  00 00 00
 len    ?     id      ?      offset len
                             = 476   = 119
```

### What comes back

Reassembled, the transfers are the device's own data structures:

| size | what it is |
|---|---|
| 1136 | a patch - the name sits at offset 0x34, `It's GP-150` |
| 4012 | the largest object read on connect |
| 2032 | another table |
| 412 | the **User IR list** - twelve-byte name slots, `User IR 1`, `User IR 2`, … |
| 408 | firmware version `V1.1.1` followed by floats |
| 92 | a patch header with its name |
| 16-48 | the small objects Suite reads to draw a list |

Inside each payload there is a second layer, which the Dart side calls a data
package: `01 <check> <len16 LE> 03 <type> <a a> <b b> <len16 LE> …`, where the
repeated 16-bit values (`0x3011`, `0x3020`, `0x1042`, `0x2000`, `0x1010`) look
like the addresses of the object and of whoever asked for it. That layer is only
half read.

### What it does not have

Nothing in the capture reads **memory**. Every request names an object by id and
an offset *within that object*; there is no command that says "give me the bytes
at this address". So this route does not, by itself, reach the interface code in
SDRAM. What it does give is the pedal's data: patches, names, IR lists, version -
readable and, with the same frame format, writable.

`tools/ht_sysex.py` decodes and builds these frames, reassembles a capture into
objects, and writes them out. It opens no MIDI port.

## 25. The editor protocol, finished

§24 stopped half way: the inner "data package" was only guessed at, and the
parser silently dropped 22 frames. Both are now settled, and the second one
explains the first.

### The dropped frames

`decode()` un-nibbled every payload. Twenty-two frames are not nibble-encoded -
their bytes run up to 0x77 - so `unnibble` produced values above 255 and the
frame was thrown away by the `except ValueError` that was meant to catch
non-frames. Those twenty-two are exactly the interesting ones: they are the
host asking for a chunk that went missing.

```
F0 7F 7B  00 00  03 06  02 05   01 00  5C 03  77  00 00 00  F7
                        seq=2 chunk=5   id=1   off=476 len=119
```

`5C 03` is 476 and `38 07` is 952 - the same 14-bit low-first pair as the
envelope, stepping by 119, the chunk size. So a resend request is plain
seven-bit values, and only bulk data is nibbled. The parser now decides per
frame and keeps both.

### The data package

Every nibble payload, in both directions, is one package:

```
01 <crc8> <len16 LE> | <cmd> <type> <dst16> <src16> <size16> <data[size]>
```

* `crc8` is the same CRC-8/0x31 as the envelope, but over eight whole bits
  rather than seven, computed from `cmd` onward. Verified on every package in
  the capture.
* `len16` counts the body; `size16` counts `data`. A reply to a patch read has
  `len16 = 1132`, `size16 = 1124`, and the frame's own `len16 = 1136 = 4 + 1132`.
* `cmd` is `0x03` to read - and on every reply - and `0x00` to write.
* `dst` and `src` are equal on a read. The one write in the capture, a rename,
  has `dst=0x1091 src=0x1051` and carries `"123"` in ASCII.

### The objects

| id | what it is | size |
|----|------------|------|
| `0x1010` | patch name list, the browser | 4012 |
| `0x1042` | User IR names | 412 |
| `0x1052` | cab / IR model names | 2032 |
| `0x1070` | session handshake | 16 |
| `0x1080` | device state blob | 144 |
| `0x1092` | amp model names | 2032 |
| `0x2000` | device info, `V1.1.1` | 408 |
| `0x2050` | input meter, pushed | 36 |
| `0x2060` | tuner / level, pushed | 20 |
| `0x3011` | the current patch | 1136 |
| `0x3020` | current patch header and name | 92 |
| `0x3031`/`0x3032`/`0x3033`/`0x3070`/`0x3080` | live state, pushed on every edit | 16-48 |

`ht_sysex.py read <id>` rebuilds the request for any of the eight objects the
capture actually asked for, and all eight come out **byte-identical** to what
Suite sent. That is the whole basis for a read-only client: no invented frames,
only shapes the device has already been asked for in front of us.

## 26. The GP-200 project, and what it tells us about this one

There is a public reverse-engineering effort on the GP-200, the GP-150's bigger
sibling: a blog at `gp200-reversing.hashnode.dev` and an editor at
`github.com/phash/gp200editor` whose `docs/sysex-protocol.md` documents that
device's protocol in full. The GP-200 is a different envelope
(`F0 21 25 7E "GP-2" <cmd> <sub>`), so none of it transfers directly - but three
things line up hard enough to be worth writing down.

**The patch is the same idea, and probably close to the same layout.** Their
preset reads back as 1176 bytes; ours is 1136. Theirs holds a 16-byte name at
decoded[28] and eleven 72-byte effect blocks (`14 00 44 00`, slot, active flag,
`00 0F`, `u32` effect id, fifteen `float32`). Our 1136-byte object carries the
factory name `It's GP-150` at offset 53 - theirs carries `It's GP-200`. The
72-byte block marker is *not* present in ours, so the block layout differs, but
the shape of the thing (header, name, author, routing order, per-slot blocks,
controller assignments at the tail) is the family's and is the right thing to
test our bytes against.

**Their A2 answer contradicts the assumption behind §18.** They report that the
GP-200 does not run neural inference at all: it runs FFT convolution of a fixed
impulse response plus biquads, at 44.1 kHz, and Valeton's A2 support is a
*desktop-side fit* - the editor turns the capture into that convolution and
never runs a network on the pedal. If the GP-150 works the same way, then
"compressing a `.nam` to fit" is the wrong frame entirely: the question is how
well an IR-plus-biquads fit reproduces the model, not how few MACs the WaveNet
can be pruned to. Our `nam2namb.py` measures the network honestly, but what the
`.namb` actually contains needs checking against this before any more work goes
into shrinking weights.

**SWD is open, and that is the way into SDRAM.** They read `SEC_CONFIG @
0x401F4460 = 0x00000008`, i.e. HAB open, no signature block, and dumped the
whole 8 MB of FlexSPI over a five-pad header (`J24`: SWCLK, SWDIO, nRST, VREF,
GND) with an ST-LINK and OpenOCD `dump_image` at `0x60000000` for `0x800000`.
The GP-150 is the same silicon family. §23 established that the interface code
lives at SDRAM `0x80000000..0x8002F760` and is *not* in the update image; §25
establishes that the editor protocol reads objects, never addresses. A debug
probe on the equivalent header is the one route that reads that memory directly -
and it is read-only until we choose otherwise.

Their updater notes are worth one line too: their command set has `0x01 = read
region`, which is the first evidence any of these boxes will read flash back
over MIDI. Ours (§20) is a different variant with a different CRC, so this is a
hint about where to look, not a command we can send.

## 27. The interface code is in the file after all - the bootloader moves it

§23 concluded that the UI code at SDRAM `0x80000000..0x8002F760` is not in the
update image: a prologue sweep over every base found nothing, no scatter table
turned up, and no absolute reference to a UI string existed anywhere. That
conclusion was wrong in its second half, and the GP-200 series says why.

On the GP-200 the application is **not one flat image loaded at one address**.
The bootloader copies two separate blocks out of flash at boot - one into the
M7's tightly-coupled instruction memory (ITCM), one into external SDRAM - and
then starts executing from ITCM. Their dialog renderer and LED driver had
refused to disassemble for exactly the reason ours does: the bytes are in the
file, at a flash offset, but every address inside them is written for where they
will *be*, not where they *are*. Disassemble at the file's own base and it is
noise. Once the real segment map was known, all of it decoded cleanly.

That reframes the search here completely. We have been looking for code that
carries `0x80000000`-shaped addresses inside a region that is executed in place.
What we should be looking for is the **copy loop in the bootstrap** - region b at
flash `0x38000` - and the source/destination/length triples it works from. Find
those, and the SDRAM block is a slice of the file we already have, disassemblable
at the right base, with the UI in it.

Two more of their findings are worth having in front of us when that lands:

* **The screen registry.** The GP-200 registers 20 screens, ids `0x00`-`0x14`:
  boot splash, home, edit menu, signal chain, global settings, footswitch
  assign, save, drum, tuner (`0x09`), looper, global EQ, CTRL, EXP, EXP
  calibration, factory reset, bank select, overload warning, MIDI, a factory QC
  screen (`0x13`, reachable on stock firmware by holding BACK+SAVE during the
  boot splash) and an on-screen debug log (`0x14`, patch-only). If the GP-150
  has the same structure, a screen id table is a small, findable thing, and it
  is the index into the native GUI that this project has been trying to reach.
* **The LED frame.** Six bytes written out one bit per indicator, with a
  separate table for blink rates; each footswitch LED has three bits (red,
  green, blue), so eight colours.

Their method for confirming a screen id is worth recording too, because it needs
no disassembly at all: patch the boot sequence to jump straight into screen *N*,
reflash, power on, photograph the display. We have `thumb_patch.py` and a working
flash path, so the same trick is available here - at the cost of a flash cycle
per screen, and only with the user's say-so.

None of this is confirmed on a GP-150 yet. It is a map of where to dig, from
someone who dug in the same rock.

## 28. Where the interface actually lives: below 0x38000, where updates never reach

§27 took the GP-200's boot copy chain and expected the SDRAM block to be a
slice of the update image, written for `0x80000000` rather than for where it
sits. It is not. Here is the test and the result.

**The veneers, enumerated.** Scanning section b for MOVW/MOVT pairs that build a
constant in `0x80000000..0x8003FFFF` finds **73 distinct targets**, every one of
them odd - Thumb function pointers - spanning `0x80000CCD` to `0x8002F761`. They
sit in one dense run starting at section-b offset `0x002B36`, ten bytes apart:
`MOVW r12,#lo; MOVT r12,#hi; BX r12`, over and over. That is an import table
into the SDRAM module, and it gives us 73 known function entry points.

**The sweep.** If the module were in the file, then at the right offset *F* the
bytes at `F + (target - 0x80000000)` would be function prologues - `push {…}` or
`push.w`. Sweeping every 2-byte alignment of all six sections against all 73
targets:

| section | best match |
|---------|-----------|
| b | 7 / 73 |
| c | 5 / 73 |
| d | 5 / 73 |
| e | 4 / 73 |
| f | 1 / 73 |
| g | 7 / 73 |

Seven out of seventy-three is what chance gives. The module is not in any
section, at any alignment.

**It is not hiding compressed, either.** The payload is already LZO-unpacked; a
second compression layer would show up as a high-entropy block. There is exactly
one in section b, `0x208000..0x278000`, and it is the boot GIF, whose header sits
at `0x207AE5`. Nothing else in 5.2 MB looks compressed.

**So where is it?** The section table says where each section is flashed: b at
`0x38000`, c at `0x740000`, d at `0x800000`, e at `0x9C0000`, f at `0xA80000`.
Everything below `0x38000` - 229,376 bytes - is never written by an update. The
SDRAM module is 0x2F760 = 194,400 bytes. **It fits, with 35 KB to spare for the
boot code itself.**

That is consistent with everything: the GP-200's bootloader copies blocks out of
flash at boot and lives below the lowest partition the updater can address; ours
would be doing the same, out of a region no Valeton update has ever rewritten.
It also explains why the interface has looked identical across firmware versions
while everything else moved, and why no scatter table was ever going to turn up
in the image - the copier is not in the image either.

**What this costs us, precisely.** The native GUI cannot be edited by patching an
update file, because the code that draws it is not in the update file. Reading
it needs the flash below `0x38000`, and there are exactly two ways to that:

1. a debug probe on the SWD header, as the GP-200 work did - reads all 8 MB,
   read-only, and needs the case open;
2. a read command in the resident updater, if ours has one. The GP-200's has
   `0x01 = read a fixed-size region back`. Ours (§20) is a different variant, and
   whether it has the same command is a question for the vendor library's
   disassembly, not for the device.

Until one of those happens, Studio edits artwork - which *is* in the image, and
is indexed, guarded and reversible - and the native layout stays out of reach.

## 29. A capture at a width the pedal can afford

The A2 question, settled by measurement rather than by argument.

### What the choice costs today

An A2 capture is a SlimmableContainer holding two independently trained
submodels - three channels and eight - and Suite always takes the three. Running
both over the DI the vendor's own converter uses and comparing them, gain matched,
over sixteen captures:

| capture | ESR | dB |
|---------|-----|----|
| Soldano, Spiraling Clean | 0.0012 | -29.4 |
| Soldano, Lazy Boy / 30 Days / Drop Anchor / Another Day | 0.0016-0.0027 | -28 to -26 |
| Jcm800 | 0.0074 | -21.3 |
| Soldano, High / Web Of The Dog / BYOS Drive | 0.012-0.016 | -19 to -18 |
| Randall X2 Dimezone, all five | 0.020-0.029 | -17 to -15 |

Clean captures lose nothing at three channels. High-gain ones lose real detail.
So the vendor's choice is not wrong, it is just the only one they offer.

### Why there is a third option

The submodels are **not** nested - the three-channel one is not a slice of the
eight-channel one, and their weights differ by more than a unit - so no
intermediate width comes for free. But nothing forces three or eight either.

The `.namb` the pedal reads carries a **binary description of the architecture**,
not the source JSON: channel count, per-layer kernel sizes, dilations and the
LeakyReLU slope, laid out from offset 0x50. A three-channel file and an
eight-channel file of the same capture differ in **exactly two bytes**:
`channels` at 0x5E and `bottleneck` at 0x60. The width is read from the file.

And the vendor's own converter will emit any width: hand
`convertNamToNambAtPath` a five-channel `.nam` and it returns a well-formed
20124-byte `.namb` with its own checksum - which is what makes the checksum at
0x18 a non-problem. It never had to be cracked.

### What each width costs

| channels | weights | MAC/sample | `.namb` | M7 at 48 kHz |
|----------|---------|-----------|---------|--------------|
| 3 | 1871 | 1731 | 7.8 KB | 14% (Suite ships this) |
| 4 | 3210 | 3024 | 13.0 KB | 24% |
| 5 | 4907 | 4675 | 19.7 KB | 37% |
| 6 | 6962 | 6684 | 27.7 KB | 53% |
| 8 | 12146 | 11776 | 47.9 KB | 94% |

Four channels lands at 24%, within a point of the 22% the GP-200 project
*measured* for that pedal's own amp engine. That is the width to aim at.

### Training one

`tools/nam_distill.py` distils the eight-channel submodel into a wider-than-stock
student. The student is **widened out of the three-channel submodel**, with the
new channels wired so they cannot reach the output yet - the widened model's
output is bit-identical to the narrow one's, checked at 1.4e-16 - so training
starts from exactly what Suite would have shipped and can only improve on it.
Adam over random DI windows, the loss taken past the 6347-sample receptive field,
the best checkpoint kept rather than the last.

The forward pass is `nam2namb.WaveNet`'s; the gradients are hand-written and
checked against finite differences (worst relative error 1.1e-4). `selftest`
runs all of that.

On `x2mysettings`, the worst capture in the set, twenty-five minutes:

```
Suite, 3 channels     ESR 0.02233   (-16.5 dB)     14% of the M7
distilled, 4 channels ESR 0.00592   (-22.3 dB)     24% of the M7
```

The error is a quarter of what it was, at a cost the pedal is already known to
carry for its own amp block. `gp150_re/x2mysettings-4ch.namb` is that model,
13336 bytes, converted by the vendor library.

**The honest caveat:** 24% is arithmetic - MAC/sample against 600 MHz - not a
measurement on the device. Whether a four-channel model actually fits alongside
the rest of a chain is something only loading it into a GP-150 will settle.

Studio has a tab for all of this ("Оптимизировать намы"): pick a capture, see
what each width would cost, measure what the stock choice loses, train, and
convert - the training runs as a background job with a live log and can be
stopped, keeping the best checkpoint.

## 30. The system font: searched again, still not in the file

The menus - `Gain`, `Global EQ`, `Tuner`, `USB Settings`, `Band 1 Gain` - are
drawn by the pedal itself, and re-typefacing them means finding the glyphs. §23
said they are not in the payload. Now that §28 explains *why* code can be
missing from an update image, the search was worth running again, properly.

**What was looked for, and what came back:**

* **An outline font.** TrueType/OpenType/WOFF/TTC signatures across all seven
  sections, and the table tags a real font must carry - `glyf`, `cmap`, `head`,
  `hhea`, `hmtx`, `maxp`, `name`, `OS/2`, `post`, `loca`, `CFF `. One accidental
  `loca` in 8 MB and no coincident tags. The `00 01 00 00` hits are what that
  byte pattern always is in a binary: noise.
* **A glyph descriptor table**, which is how an embedded UI stores a bitmap
  font: a record per glyph holding an index into a bitmap blob plus the box.
  Scanned for runs of 8-, 10-, 12- and 16-byte records whose index only ever
  grows and whose box is a plausible glyph size. The longest run in the whole
  image is 59 records - an ASCII set needs 95 - its index steps by 512 to 1800
  at a time, far too much for a 4x6 box, and the data in front of it does not
  render as letters.
* **Every section identified**, so nothing is left over to hide a font in:
  `b` the application with the strings and the boot GIF, `c` the cab/IR
  catalog, `d` the DSP, `e` cab names, `f` the patch bank, and `g`/`h`.

That is consistent with §28: the interface code lives at SDRAM `0x80000000` and
comes from the flash below `0x38000` that no update image contains. The font is
almost certainly down there with the code that uses it.

**The honest gap.** Section `g` is 647,036 bytes at maximum entropy (7.996 bits
per byte), its destination field reads `0x00000000`, it is not LZO, it has no
repeating key - and the updater *does* send it, 15,406 frames of it. It is not
identified. If it is an encrypted image of something, this search cannot see
inside it and the font could be in there. Against that: 647,036 bytes does not
fit in the 229,376 below `0x38000`, so whatever it is, it is not simply the
boot region. Section `h`, 16,320 bytes, is a table of repeated `0x2ECC` u32s
and is not identified either.

**What is editable today.** The *words* are in the file - `Gain`, `Global EQ`,
`Tuner`, `MIC Monitor`, `Reset factory patches`, `Band 1 Gain` and the rest sit
in the string chains in section b around `0x030000` and `0x290000`, and Studio's
Text tab edits them. The lettering in the artwork - the AMP/DLY/VOL block tiles -
can be re-typefaced (§ the Font tab). The menu type cannot, yet.

**What would change that.** The flash below `0x38000`. Either a debug probe on
the SWD header, as the GP-200 work did, or a read command in the resident
updater if ours has one - the GP-200's is `0x01`, and ours is a different
variant whose command set can be read out of the vendor library without going
near the device.

## 31. The screen registry is in the file, and its pointers are editable

Everything in §23, §28 and §30 was found by measuring bytes. Ghidra had only
ever been pointed at the Windows library, not at the firmware, and that was a
mistake: the first real pass over the flat image turned up the thing all of
those sections had been circling.

**How it was found.** Import the flat image `flat_image.py` writes at
`0x60038000`, add the chip's RAM windows, disassemble Thumb, then ask a question
a byte-grep cannot: *what references this range*. Two new scripts do that -
`Refs.java` for an address, `RangeRefs.java` for a range - and the answers were
immediately worth having:

| range | what it is | references |
|-------|-----------|-----------|
| `0x602C8000-0x602C9000` | the menu strings | **0** |
| `0x6006C000-0x6006D000` | parameter names | 44 |
| `0x80000000-0x80030000` | the SDRAM module | 182 |
| `0x6003AB00-0x6003B000` | the veneer table | 160 |

Zero references to the menu strings confirms what §30 assumed: they are reached
by index through a table, never by address, which is why no search for a
reference to one ever found anything.

**The registry.** `FUN_6004fec8`, an init routine, calls `FUN_600628b8` fifteen
times:

```c
void FUN_600628b8(uint id, void *a, void *b, void *c) {
  if (0x1f < id) return;                       /* 32 slots */
  int e = DAT_600628dc + id * 0xc;             /* 12 bytes each */
  *(void **)(e)     = a;
  *(void **)(e + 4) = b;
  *(void **)(e + 8) = c;
}
```

A **32-slot table of three function pointers each**, filled with ids `0x00`,
`0x01`, `0x02`, `0x03`, `0x04`, `0x05`, `0x06`, `0x08`, `0x09`, `0x0A`, `0x0B`,
`0x0C`, `0x0E`, `0x0F`, `0x12` - fifteen screens, with gaps at `0x07`, `0x0D`,
`0x10`, `0x11`. The GP-200 registers twenty screens with gaps in the same style,
`0x00`-`0x14`, and there `0x08` is a registered-but-blank slot; ours has the same
shape, and the same trick would name them: patch the boot to enter screen *N*,
reflash, photograph the display.

**And every one of those pointers is in the update file.** They are literals in
section b, at payload `0x018064` through `0x0180E4`:

| id | handlers (SDRAM) |
|----|------------------|
| `0x00` | `0x8000ED41` `0x8000EDD5` `0x8000EE4B` |
| `0x01` | `0x8000C50D` `0x8000D871` `0x8000E1E9` |
| `0x02` | `0x8000231D` `0x80003381` `0x80004261` |
| `0x03` | `0x8000EE65` `0x8000F381` `0x8000F911` |
| `0x04` | `0x800054E5` `0x80005BA9` `0x800064DD` |
| `0x05` | `0x80003C05` `0x80003F21` `0x80003FC5` |
| `0x06` | `0x80006CC9` `0x80007065` `0x80009FB5` |
| `0x08` | `0x80010B21` `0x80011195` `0x80011D11` |
| `0x09` | `0x80001C0D` `0x80001C61` `0x80001FCD` |
| `0x0A` | `0x80014C75` `0x80015475` `0x80015A35` |
| `0x0B` | `0x8000AC8D` `0x8000B1C5` `0x8000BE65` |
| `0x0C` | `0x80007071` `0x80007B3D` `0x80007FCD` |
| `0x0E` | `0x80004E3D` `0x80005239` `0x80005389` |
| `0x0F` | `0x8000FC21` `0x80010751` `0x80010899` |
| `0x12` | `0x80011F71` `0x80013E2D` `0x80014885` |

This is the first handle on the native interface that does not need a debug
probe. The code being pointed at is out of reach, but **the pointers are not**:
they are four bytes each in a file we can already rebuild and flash. Point one
at code of our own, placed in flash where nothing else uses it, and that screen
runs our code instead - which is how the GP-200 project's tuner mod works, one
retargeted call into a code cave.

**Two blocks are copied at boot, not one.** The same literal pool holds ITCM
pointers - `0x00014F65`, `0x0002093D`, `0x00020CCD`, `0x00022D53`, `0x00022DAD`,
`0x00029BE5`, `0x00029F1D`, and a data pointer `0x000302BC` - alongside the SDRAM
ones. So the GP-150 does exactly what the GP-200 does: one block into ITCM, one
into SDRAM. Neither is in the image, and together they are larger than the
229,376 bytes below `0x38000` that §28 proposed as their home.

Which puts **section g** back in the frame: 647,036 bytes, destination field
`0x00000000` - which is the ITCM base - transmitted during an update, entropy
7.996 bits per byte, no 16- or 32-byte block ever repeating (so not ECB), not
LZO, and not zlib, raw deflate, gzip, LZMA or bzip2 at any offset in the first
64 bytes. Big enough to hold both modules. If g is the ITCM+SDRAM image under a
stream cipher or an unidentified packer, then the interface *is* in the update
file after all, and §28's conclusion needs replacing rather than extending.
That is the thread to pull next, and it is pure offline work.

## 32. Section b is copied, not executed — and everything follows from that

This overturns §23, §28, §30 and §31. All four were built on the same wrong
premise, which came from `flat_image.py`: that every section runs in place from
flash at `0x60000000 + its flash address`. For section b that is false, and it
is false in a way that made the interface, its layout and its font all
invisible.

**The load table.** Section b does not begin with code. It begins with a
40-byte header:

```
0x08  "V111"                    the version tag
0x10  u32 0x00038028  flash address   0x14  u32 0x000353E9  size
0x18  u32 0x00000000  destination     <- ITCM
0x1C  u32 0x0006D411  flash address   0x20  u32 0x004C7771  size
0x24  u32 0x80000000  destination     <- SDRAM
```

The two runs are consecutive - the first ends exactly where the second begins -
and the second ends two bytes short of the section's own end. So at boot:

* **payload `0x000028`, 218,089 bytes → ITCM `0x00000000`** - the application;
* **payload `0x035411`, 5,011,313 bytes → SDRAM `0x80000000`** - the interface,
  its artwork, its strings and its fonts.

**Confirmed four ways, not assumed.** Counting aligned words that point into
each candidate range: the ITCM half holds 2,571 pointers into ITCM against 267
into the flash view, ten to one. Checking the 73 veneer targets against a base
of `0x35411` puts 33 of them on Thumb prologues where every neighbouring base
scores 0 to 6. `flat_image.py map` now reports 4,613 self-references for the
ITCM half where the old flash base gave 1,037. And Ghidra, given the corrected
map, finds **459 references to the menu strings** where the flash base found
zero - which is what §30 read as "the strings are addressed by index" when the
truth was simply that we were looking at the wrong addresses.

So: the interface is in the update file, it always was, and §28's "below
`0x38000`, where updates never reach" was wrong. §31's speculation that the
modules might be hiding in section g was also wrong, and contradicted this
project's own earlier and better-evidenced finding that `g` and `h` are the
JieLi Bluetooth SoC's and the USB-PD controller's firmware - which is also why
they are byte-identical between V1.0.5 and V1.1.1.

### The interface is LVGL v8

The screen handlers call style setters by property number, and the numbers are
LVGL's own: `1` width, `4` height, `7` x, `8` y. The global settings screen
reads, in the file:

```c
FUN_8002da98(obj, 0x140, 0xf0);      /* set_size(320, 240)  - the screen */
FUN_8002d9d2(obj, 0, 0x2c);          /* set_pos (0, 44)                  */
FUN_8002da98(obj, 0x140, 0x2c);      /* set_size(320, 44)   - a bar      */
FUN_8002d9d2(obj, 10, 0xc);          /* set_pos (10, 12)                 */
FUN_8002da98(obj, 200, 0x1e);        /* set_size(200, 30)                */
```

Every widget's position and size on every screen is an immediate constant in
code we hold. So is its colour: `FUN_80015eac` builds a box with
`set_pos, set_size, set_bg_color, set_opacity(0xff), set_border_color,
set_border_width(1)`.

### The system font, found

LVGL stores a bitmap font as `lv_font_fmt_txt`, and the GP-150's are exactly
that. Fourteen of them:

| # | descriptor | glyphs | bpp | height | bitmap blob |
|---|-----------|--------|-----|--------|-------------|
| 0 | `0x80035410` | 98 | 2 | 14 px | 1,790 B |
| 1 | `0x800361D0` | 96 | 2 | 18 px | 2,652 B |
| 2 | `0x80037F70` | 95 | 2 | 29 px | 6,060 B |
| 3 | `0x8003AE20` | 95 | 2 | 38 px | 10,427 B |
| 4 | `0x8003D418` | 95 | 2 | 7 px | 388 B |
| 5 | `0x8003DA80` | 95 | 2 | 10 px | 800 B |
| 6 | `0x8003E340` | 96 | 2 | 13 px | 1,372 B |
| 7 | `0x8003EE84` | 96 | 2 | 17 px | 2,016 B |
| 8 | `0x80042EF8` | 312 | 2 | 16 px | 13,449 B |
| 9 | `0x80049610` | 314 | 2 | 21 px | 23,322 B |
| 10 | `0x8004CEC8` | 313 | 2 | 15 px | 11,479 B |
| 11 | `0x80051B70` | 313 | 2 | 18 px | 16,584 B |
| 12 | `0x80059728` | 74 | 2 | 63 px | 24,649 B |
| 13 | `0x80259E08` | 157 | 4 | 15 px | 8,832 B |

The depth is **measured, not read**: for each candidate bpp, check that
consecutive `bitmap_index` values differ by exactly `ceil(box_w*box_h*bpp/8)`.
On every one of the fourteen a single value scores 38 out of 38 with no
disagreement, which is why `lv_font.py` trusts the arithmetic over the header
bitfield it could have read instead.

`tools/lv_font.py` lists them, renders a specimen sheet, and **replaces one
from any TrueType or OpenType face** - re-rendering the ASCII range into new
boxes, advances and bitmaps, repacked into the byte span the original held,
refusing rather than overflowing, and restamping every section CRC and the
whole-file CRC. Verified end to end: font 9 replaced with Georgia Bold reads
back as Georgia Bold, and `htfw_tool verify` passes on all seven sections.

**So the menu type can be changed after all.** §30 said it could not, and gave
the searches that had failed; every one of those searches was run against the
wrong addresses.

## 33. The layout is numbers in the code, and the numbers can be changed

§32 found that the interface is LVGL and that it is in the file. This is what
that is worth: **the position and size of every widget on every screen is an
immediate in the instruction stream**, and an immediate can be rewritten.

### The setters name themselves

Nothing here is hard-coded to one build. `thumb_imm.py` walks the interface code
halfword by halfword, decoding the four instructions that put a constant in a
register - `MOVS Rd,#imm8`, `MOV.W Rd,#imm12`, `MOVW Rd,#imm16`, `MVN` - and
remembering them until a `BL` consumes them. On V1.1.1 that finds **9,327 call
sites**, and ranking the targets by how often they are reached with two constant
arguments settles the question by itself:

| target | calls with two constants | sample arguments | |
|--------|-------------------------|------------------|-|
| `0x8002DA98` | 267 | (166,167) (166,38) (162,127) | **set_size** |
| `0x8002B880` | 239 | (0,50) (0,18) (0,19) | |
| `0x8002D9D2` | 182 | (0,9) (0,45) (286,43) | **set_pos** |
| `0x8002DDAA` | 77 | (255,0) always | opacity |
| `0x8002DE88` | 52 | (4,0) always | |

The top two are told apart by which is handed the larger numbers - a size setter
gets widths and heights, a position setter gets coordinates that are often zero.
Both then match exactly what the decompiler shows: LVGL style properties 1 and 4,
and 7 and 8.

### What a screen looks like

Fifteen screens are registered, and their handlers lay out 177 widgets between
them. The global settings screen reads, straight out of the file:

```
  #   x, y      w, h        where each constant lives
  0   0, 0      320, 240    w 0x800055A4  h 0x800055A2      the screen
  1   0, 0      320, 44     w 0x800055F0  h 0x800055EE      the header
  2   0, 44     320, 133    w 0x80005616  h 0x80005614      the body
  3   0, 177    320, 63     w 0x8000563C  h 0x8000563A      the footer
  5   10, 12    200, 30     w 0x800056A6  h 0x800056A2      the title
  6   242, 4    68, 36      w 0x80005710  h 0x8000570C
  7   0, 5      106, 24     w 0x80005764  h 0x80005760   \
  8   107, 5    106, 24     w 0x80005788  h 0x80005784    > three tabs
  9   214, 5    106, 24     w 0x800057AC  h 0x800057A8   /
```

Three 106-wide tabs at x = 0, 107 and 214 is a tab bar, and it is in there as
nine numbers.

### Changing one

`lv_layout.py set --at 0x800056A6 --value 240` widened that title from 200 to
240: **one byte of the payload changed**, the value reads back, and every
section CRC and the whole-file CRC verify. That is the whole edit.

The limit is honest and worth stating: an instruction cannot change length in
place, so a new value has to fit the encoding that is already there. A `MOVS`
holds 0 to 255, a `MOVW` holds 0 to 65535, a `MOV.W` holds whatever
ThumbExpandImm can spell. Ask for 260 where a `MOVS` sits and the tool refuses
*that* edit and applies the rest, rather than writing four bytes into a
two-byte hole.

Studio's **Раскладка** tab draws the screen as boxes on a 320x240 canvas -
drag to move, drag the corner to resize, or type the numbers - and writes the
constants back. Positions in LVGL are relative to a widget's parent, so the
canvas is a schematic and not a render of the screen; that is said on the tab
rather than glossed over.

## 34. The descriptor comes after its image, not before

Every image in the payload has a 12-byte record beside it, and §17 read that
record as a header sitting in front of the pixels. It sits behind them. The
index has therefore been pairing each descriptor with the **next** image's
pixels since the day it was written, and that is where the noise came from.

**The descriptors say so themselves.** The third word is a pointer, and mapped
back through the load table it lands, on **124 of the 132 blocks** in V1.1.1,
at exactly `hdr - size` - the bytes immediately *before* the record. The other
eight point outside the SDRAM block altogether. Not one lands at `hdr + 12`,
which is where the index was reading.

```
hdr 0x090A55  14x26  size 1092   its pointer -> 0x090611   hdr-size = 0x090611
hdr 0x090EA5  14x26  size 1092                -> 0x090A61   hdr-size = 0x090A61
hdr 0x091C3D  34x34  size 3468                -> 0x090EB1   hdr-size = 0x090EB1
```

So the layout is `[pixels][descriptor][pixels][descriptor]`, and reading
forwards shifts every image by one place in the run.

**Why it went unnoticed for so long.** The artwork is stored in pairs - a grey
icon and a coloured one, the same size - so an off-by-one inside a pair swaps
two pictures that look interchangeable and keeps the geometry. It only shows
when consecutive blocks differ in size, and then it shows as static. Rendering
fourteen blocks both ways settles it in one look: read backwards they are a
battery, two amp icons, a lightning bolt, two drum icons, a cassette, a
document, a face, two arrows, a pedal and a drum kit; read forwards half of
them are noise.

**What it fixes.** Grading the same image both ways: 125 of 132 blocks come
back as artwork now, against a much thinner majority before, and the "doubtful"
pile that Studio hides behind a toggle largely evaporates. This is the noise
the Graphics tab has been apologising for since §16.

`Blob.off` is `hdr - size` now and `Blob.end` is `hdr`; the scan requires room
*before* a candidate rather than after it. The descriptor guard is unchanged -
it protects `[hdr, hdr + 12)`, which was always right.

## 35. The screen, as the pedal assembles it

§33 read the layout as numbers and drew it as boxes. Boxes are enough to move
something and not enough to recognise it, and the reason is that the three
things that make a screen a screen - which object a call is about, who its
parent is, and what was put inside it - travel through registers and struct
slots rather than through immediates.

`lv_trace.py` follows them. The builders are stereotyped:

```
    bl   lv_obj_create      ; r0 = parent
    str  r0,[r4,#0x2c]      ; the handle goes into a slot of the screen struct
    ldr  r0,[r4,#0x2c]      ; and comes back out for each setter
    movs r1,#0
    movs r2,#44
    bl   set_pos
```

so a tracker that knows four kinds of value - a constant, a word from the
literal pool, what a call returned, and what a struct slot holds - can follow a
widget from its birth to its contents. Two details make it work rather than
nearly work:

* **r4 to r11 survive a call.** A builder with several widgets in flight parks
  their handles in the high registers precisely because a call cannot disturb
  them, and a tracker that clears everything at each `bl` loses every one.
* **the literal pool is data.** A picture and a caption both arrive as
  `ldr rN,[pc,#imm]`, and the pool is in the file, so both can be read.

Everything else names itself, on this image or any other:

| role | how it is recognised | here |
|------|---------------------|------|
| `lv_obj_create` | its result is what gets stored into the struct slots | `0x8002A09C` |
| `set_pos` / `set_size` | pass LVGL properties 7/8 and 1/4 to the property helper | `0x8002D9D2`, `0x8002DA98` |
| `lv_img_set_src` | handed a pointer that lands exactly on an image descriptor | `0x80027918` |
| `lv_obj_align` | handed an alignment in LVGL's own range with two offsets | `0x80029670` |

A handler that delegates is followed two levels down - a helper is one whose
own body calls the constructor or the setters - and each invocation is tagged
by its call site so the second row of a list does not land on top of the first.
That took the tuner screen from one widget to fifty-four and the home screen
from nine to eighty-three.

With the tree in hand the coordinates finally compose: LVGL's are relative to a
parent, and an aligned widget needs the parent's box before it has one of its
own, so placement walks down from the screen rather than treating each widget
alone. Then the artwork goes on, at the picture's own size when the widget was
given none - which is how an `lv_img` normally works.

The result is the home screen with its amp badge, its OFF plate, its pedal, its
battery and its two indicator lamps where the device puts them. Studio's
Раскладка tab draws that under the editable boxes, so the thing being dragged is
the thing on the screen.

**What it gets right, and what it does not.** The frame is sound: the home
screen reads as a 320x240 root holding a 7-pixel meter strip, a 43-pixel
header, a 62-pixel band, three 59-pixel bands stacked at the same y - which is
one area with three alternative views - and a 55-pixel footer, with a 195x87
panel over the middle. Those numbers are the ones the tab edits, and they are
read straight out of the instructions.

Where each *picture* lands is another matter, and a first attempt overstated
it. Three things defeat static reconstruction here:

* widgets made in a loop come from one call site, so a row of ten tiles reads
  as one;
* a screen keeps several alternative views in the same place and shows one, and
  nothing in the code says which;
* captions are `set_text(obj, "%s")` with the string built at run time from the
  tables, so almost none resolve.

There was also a plain bug worth recording: an early version made an object for
every call whose first argument it could name, which put seventy-three phantom
widgets on the home screen's fifty. Only the constructor and the four
recognised setters bring a widget into being now.

So the preview is a **structural sketch** and is labelled as one in Studio,
off by default. A true picture of a screen needs the device: patch the boot to
enter screen *N*, flash, photograph - the method the GP-200 project used - at
the cost of a flash cycle per screen.

## 36. The layout, checked against the pedal

Twenty photographs of the real screens settle what static reading could only
claim. `tools/screen_photo.py` finds the display in each - the largest bright
region, then the box stretched to the screen's own 4:3, because the dark bands
inside the interface break the lit area into pieces and a run-of-bright-rows
test collapsed to a sliver on half of them - and Studio keeps one per screen
under the editable boxes.

Laying the extracted geometry over the photograph of the home screen:

* the top strip sits on the thin band above the header;
* the header band's lower edge lands exactly on the line under
  `104  It's GP-150`;
* the footer band's upper edge lands exactly on the top of the
  `P-VOL | BPM | NAM MODE` panel - `y = 185` read from the code against about
  182 measured off the photograph, inside the error of a hand-held crop;
* the 195x87 panel covers the patch tiles.

So the numbers the Layout tab edits are the device's own. That is worth having
said out loud, because the rest of this section is about what is *not*.

**Ten of forty-four.** Only ten of the home screen's boxes have a parent chain
that reaches the screen. The other thirty-four are built by helpers whose
parent could not be worked out, so their coordinates are relative to a
container nobody identified - their *sizes* are right and their *positions* are
unknown. They are drawn dashed and hidden by default rather than placed
somewhere plausible and wrong. The settings screen anchors five of fourteen;
the tuner, whose widgets are all built two levels down, anchors none.

Two bugs came out of the checking, both the kind that only a real comparison
finds:

* `Layout` keeps a snapshot of the code because the scan walks it thousands of
  times, and nothing refreshed that snapshot after an edit - so a write
  succeeded, reported success, and read back the old number. It refreshes now.
* a pairing that was never a widget produced a box 8292 pixels square at
  minus four thousand, and it was being drawn. Sizes beyond twice the screen
  are dropped.

The editor reads the tree now rather than the flat pairing, so a box is drawn
where it lands and the number an edit changes is still the parent-relative one
the instruction holds. Both come back from the API: `x`/`y` are what is
written, `ax`/`ay` are where it shows.
