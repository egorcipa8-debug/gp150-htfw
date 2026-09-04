# gp150-htfw

Tools and notes for Valeton's **HTFW** firmware container, worked out from the
GP-150 images. The container is shared across the GP-5 / GP-50 / GP-150 family.

Three things here are, as far as we can tell, not published anywhere else:

- **the region checksum algorithm** — CRC-16/MODBUS, stored big-endian;
- **the payload packing** — LZO1X with a 4-byte length prefix, which is what makes
  GP-150 **V1.1.1 and later editable at all**;
- **the image descriptors** — a 12-byte header before every stored image, carrying
  its width and height, so the artwork does not have to be found by guessing at
  row strides. It also settles the pixel order, which these notes had backwards.

Both are verified byte-exactly, not inferred. Prior work by
[drewmerc302/valeton-gp50](https://github.com/drewmerc302/valeton-gp50) documents
the same container but records the checksum only as "u16 checksum of the region"
and lists the compressed region as unexamined.

No firmware is distributed here. Download images from valeton.net yourself.

---

## Container format

```
0x00  char[4]   "HTFW"
0x04  u16       CRC-16/MODBUS of the whole file from offset 6, BIG-ENDIAN
0x06  u16       format version, 1
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

### Checksums

There are two levels, and both use the same algorithm.

**Per region**, stored big-endian in the region record. **Whole file**, stored
big-endian at header offset `0x04`, covering everything from offset `6` — so it
has to be stamped last, after the region CRCs, the size fields and the packing.

The whole-file one is easy to miss, and missing it is silent: the region CRCs all
verify, the image unpacks, and the device accepts it. Valeton Suite's own
`checkCrc()` is what catches it. Earlier notes here described `0x04` as a build id
not derived from content; that was wrong.

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

## GP-150 Studio

A desktop tool for building modified firmware — browse every image in the file,
replace any of them, edit the on-screen text, and write a flashable file. The
interface is a local web page only because that is a convenient way to draw one;
it is not a service, it listens on loopback only, and nothing leaves the machine.

```
cd studio
python server.py "GP-150 Firmware V1.1.1.bin"
```

It opens the UI in your browser. Loopback only — there is nothing to expose and
no network access of any kind.

- **Graphics** — opens on **images (from the firmware index)**. Every stored image
  is preceded by a 12-byte descriptor carrying its width and height, so the list
  is *read out of the file*, not guessed: 132 images on GP-150 V1.1.1, each one
  framed correctly with nothing to nudge. Blocks the loader allocated but never
  filled decode as noise; they are marked *unfilled* rather than hidden. Click a
  picture to replace it, shift+click to pick from Valeton Suite's own artwork.
  *index + everything the scan finds* adds the artwork that carries no
  descriptor, recovered the old way — per-region width estimation, which is what
  the offset/width/height controls and the strip and tiles views are still there
  for. *Keep alpha byte* copies the alpha byte of every pixel from the original,
  so icon shapes survive a recolour.
- **Text** — the string tables, recovered as *chains*: NUL-terminated printable runs
  packed one after another with only a few bytes of padding between them. That shape
  is what a table looks like and an isolated printable run inside code never has it,
  which is why per-string heuristics let noise through and mangled real entries.
  Search, step through matches, replace one or replace all; a replacement that no
  longer fits its slot is refused and reported, never truncated.
- **Font** — the glyph region rendered as a grid, so you can look before you touch it.
- **Device** — validates a built image with the vendor's own `checkCrc()`, lists the
  MIDI ports its library reports, streams that library's log, and flashes. The flash
  refuses unless the whole-file CRC is current, the vendor library accepts the image,
  a device is actually reported, and you confirm.
- **Build** — recomputes every region CRC, stamps the whole-file CRC, re-packs with
  LZO when the source was packed, and leaves the model string and version label alone.
- **Build and Deploy** — one button: build, stamp, hand the result to the vendor's
  `checkCrc()`, and write it to the device. It reports each step and stops at the
  first one that fails, so a build that is fine but has nowhere to go says exactly
  that and leaves the file on disk.

Studio wears Valeton Suite's own palette and typeface — greys `#181818` / `#242424`
with a `#2478FC` accent, sampled from Suite's shipped artwork, and its
`Source-regular.OTF` served straight from the install.

Only Pillow is required. Rebuilding a packed image also needs Valeton Suite
installed, for its `minilzo_plugin.dll`.

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

### `tools/gp150.py`

Inspect, validate and flash, driving Valeton Suite's own device library rather
than guessing its protocol. `assets/5868USB.dll` exports plain C — `scanInDevice`,
`scanOutDevice`, `connectDevice`, `deviceStartUpdate`, `sendMidiMessage`,
`checkCrc`, `isRealFirmware` — and updates travel over MIDI.

```
gp150.py info    <fw.bin>            header, regions, both checksum levels
gp150.py check   <fw.bin>            our verification plus the vendor's checkCrc()
gp150.py seal    <fw.bin> [-o out]   recompute the whole-file CRC in place
gp150.py devices                     MIDI ports the library reports
gp150.py probe                       raw dump of what it reports
gp150.py log [--follow] [--all]      the library's own log
gp150.py flash   <fw.bin> --yes      update the device
```

`check` is the useful one: it runs the vendor's `checkCrc()`, which is what
catches a stale whole-file CRC. `0` means accepted, `-1` a checksum mismatch,
`-2` a truncated file. `seal` repairs an image that already exists without
rebuilding or touching its content.

The library keeps a log at `%TEMP%\HTCache\logfile.txt` — this is where update
progress appears. It truncates the file on startup, and over 99% of what it
writes is `scanInDevice` polling, so `log` hides that unless you pass `--all`.

`flash` refuses to write unless the whole-file CRC is correct, the vendor library
accepts the image, a device is actually reported, and `--yes` is given. Note that
`deviceStartBoot` is a stub in this build — it is literally `mov eax, -1; ret` —
so there is no vendor call that puts the device into its bootloader.

### `tools/suite_link.py`

Puts Studio one click away *inside* Valeton Suite, without rebuilding it.

Suite's UI is AOT-compiled Dart in `data/app.so` — an ELF holding a Dart snapshot,
magic `F5F5DCDC` at `0x200`, class names like `_DrumPageState` still intact. Adding
a screen there would mean emitting code objects with valid GC stack maps,
registering classes in the snapshot's class table and matching its version hash:
that is writing a Dart AOT backend, not patching bytes. What *is* available is the
link Suite already has.

`https://www.valeton.net/` is a Dart `OneByteString`, laid out as

```
[8-byte header][8-byte length as a Smi][characters][NUL padding]
```

and the Smi eight bytes ahead of the text reads `0x30` = 48 = 24 << 1, exactly the
string's length. Swapping in a URL of the **same** length leaves the length field,
the object size and every reference to it untouched:

```
https://www.valeton.net/    24 characters
http://127.0.0.1:8765/gp    24 characters
```

```
suite_link.py status     where the link is and what it points at
suite_link.py patch      repoint it at Studio (backs app.so up first)
suite_link.py restore    put the stock app.so back
```

Writing into Program Files needs an elevated shell. A replacement of any other
length is refused rather than fudged.

### `tools/gfx_index.py`

The firmware's own image index. Every stored image is preceded by a 12-byte
descriptor:

```
u32 desc;   /* [7:0]   0x05, format tag: RGB565 + alpha, 3 bytes/pixel
               [19:8]  width  * 4
               [31:20] height * 2                                        */
u32 size;   /* width * height * 3, always                                */
u32 addr;   /* SDRAM address of this descriptor; pixels follow it        */
```

`size` has to equal `width * height * 3` with the width and the height read from
two other fields of a different word, so the test is about thirty bits of
agreement and can be swept over the whole payload: **132 images on GP-150
V1.1.1**, 1.60 MB of pixels, no false positives to sift.

```
gfx_index.py list <fw.bin> [--all]     the index, one line per image
gfx_index.py dump <fw.bin> <dir>       write every image as a PNG
```

The pixel format is **3 bytes per pixel, colour first**: little-endian RGB565,
then the alpha byte. Earlier revisions of these notes said alpha-first; that
reads the same bytes one position over, which still shows the icon's shape but
paints every one of them olive and gives each pixel its neighbour's alpha. With
a descriptor fixing the exact first pixel the question is settled by looking:
DST is red, the AMP tile orange, VOL green, NAM purple.

The descriptors are the allocator's, not a resource table's — blocks chain
(`hdr + 12 + size` is the next `hdr`), and along a run `addr - file offset` is
constant, so this part of section `b` is a heap image copied to SDRAM verbatim.
That also means blocks that were allocated and never filled sit in the file:
`looks_like_picture()` marks them *unfilled* instead of hiding them.

### `tools/gfx_tool.py`

Extract and inject at an explicit offset, for artwork that carries no descriptor.

```
gfx_tool.py index   <fw.bin>              the index (same as gfx_index list)
gfx_tool.py slots
gfx_tool.py extract <fw.bin> <addr> <w> <h> <out.png>
gfx_tool.py inject  <fw.bin> <addr> <w> <h> <in.png> <out.bin>
```

`inject` writes exactly as many bytes as it replaces, so nothing shifts and the
region table stays valid; it recomputes the affected region's CRC afterwards.

For the unindexed artwork the geometry still has to be recovered, and two things
make that hard. **Widths vary inside one region** — the big artwork region holds
runs of 112, 80 and 48 pixels wide, packed with no separator, and one width
imposed on all of them tears the picture; the width is recovered per window from
the alpha plane, because alpha is the silhouette and the colour bytes are noise
for this purpose. **Not everything that passes the alpha test is a picture** —
section `b` also holds 16-bit PCM, and quiet audio is full of 0x00/0xFF
sign-extension bytes, so it scores as an alpha channel and gets offered as an
image; painting over it destroys sound with no other symptom. Audio has that
structure at a period of two bytes, a picture at three, and whichever period
explains the data better settles it.

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

- **Where the SDRAM-resident application lives in the file.** Still open for the
  code, but no longer for everything: the image descriptors (`tools/gfx_index.py`)
  carry SDRAM addresses, and along each run of chained blocks `addr - file offset`
  is constant, so those parts of section `b` are a heap image copied to SDRAM
  verbatim. The delta changes between runs, so it is not one mapping for the whole
  section, and none of the recovered deltas places the `0x8000xxxx` veneer targets
  on real code. The flash-resident bootstrap still calls into `0x8000xxxx` through
  a `MOVW/MOVT/BX` table whose destinations are unaccounted for.
- Region `g` is **the JieLi Bluetooth SoC's firmware** and region `h` is the PD
  controller's — confirmed by the updater itself, which runs a second
  "BT And PD Updating" phase after the main firmware phase. Neither targets the
  Cortex-M7, which is why both carry flash address `0x00000000`, contain no ARM
  code, and never change between firmware versions.


`FINDINGS.md` carries the full working notes, including the approaches that failed
and two corrections to earlier conclusions.

---

## Cautions

- Model string and version label **are** validated by newer boot software; a
  changed version label is refused silently. These tools leave both alone.
- Same-length edits only. A length change to a region is a different problem.
- A rebuilt image **has** been flashed to a real GP-150 and booted normally, so the
  pipeline is verified end to end. That is not a promise about your own edits.
  Firmware modification voids your warranty and is entirely at your own risk.
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
