# gp150-htfw

Tools and notes for Valeton's **HTFW** firmware container, worked out from the
GP-150 images. The container is shared across the GP-5 / GP-50 / GP-150 family.

Several things here are, as far as we can tell, not published anywhere else:

- **the region checksum algorithm** — CRC-16/MODBUS, stored big-endian;
- **the payload packing** — LZO1X with a 4-byte length prefix, which is what makes
  GP-150 **V1.1.1 and later editable at all**;
- **the image descriptors** — a 12-byte header before every stored image, carrying
  its width and height, so the artwork does not have to be found by guessing at
  row strides. It also settles the pixel order, which these notes had backwards;
- **the NAM path** — the pedal reads `.namb`, not `.nam`, and its magic is in the
  firmware, so the RT1064 runs the capture's own WaveNet;
- **the boot animation** — 448 KB of what read as noise is a 320x240 GIF.

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
  framed correctly with nothing to nudge. The descriptors are the allocator's,
  so blocks it never filled are in the file too, with perfectly good geometry
  and leftovers inside; they are graded — 94 artwork, 3 doubtful, 35 never
  filled — and the view opens on the artwork, with **show doubtful** for the
  rest. Click a picture to replace it, shift+click to pick from Valeton Suite's
  own artwork.
  *index + everything the scan finds* adds the artwork that carries no
  descriptor, recovered the old way — per-region width estimation, which is what
  the offset/width/height controls and the strip and tiles views are still there
  for. The byte phase of those regions is settled on the alpha plane rather than
  on colour: only at the right phase does the third byte of every pixel read as
  a silhouette, 0 or 255 nearly everywhere, and on the pedal sheet the three
  phases score 0.21, 0.21 and 0.95. The colour test that used to decide it reads
  a photograph as colourful at every phase, which is what left four regions two
  bytes short and wearing a magenta rim. *Keep alpha byte* copies the alpha byte of every pixel from the original,
  so icon shapes survive a recolour.
- **Texture** — lay an image over the colour of every asset at once. Applied
  *per image*: each entry in the index gets the whole texture fitted to its own
  frame, so a sheet of icons comes out looking like a set rather than like a
  strip cut at random — which is what the old per-region version produced, and
  it missed every image the region scan does not cover. *Opacity* mixes the
  result back into the colour that was there, so 30% recolours without erasing
  the drawing, *multiply* keeps the shading, and *keep alpha* leaves every
  silhouette intact.
- **Font** — draw text into any image slot with **any TrueType or OpenType font
  on your machine**, or one you add: pick a slot from the index, type, choose
  size (0 = as large as fits), colour, outline and alignment, and write it in.
  *Draw over* composites onto the picture; with it off the slot is cleared and
  only the lettering remains. The pedal's own UI font is **not** in the file —
  not as 1-bit glyphs, not as an anti-aliased sheet, not behind a glyph
  descriptor table; every 32 KB of the payload was rendered as a bitmap and
  looked at, and the structural searches came back empty. So the menus cannot be
  re-typefaced yet, and this tab does the thing that is possible instead.
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

### `tools/selftest.py`

Everything in here that can be checked without a device, checked against a real
image:

```
selftest.py <fw.bin> [capture.nam]
```

```
container        header, every region CRC, the whole-file CRC, re-sealing
round trip       unpack then repack reproduces the file's SHA-256
image index      132 descriptors, geometry consistent, decode/encode byte-exact
boot animation   found by its own block structure, put back byte-exact
packets          CRC-8 table against the DLL's, a frame round-tripped, a
                 corrupted one rejected
NAM capture      every weight accounted for, submodels agree (ESR 0.0038)
```

23 checks on GP-150 V1.1.1, all passing; 17 on a V1.0.5 image that had been
edited and never re-sealed, also all passing — a stale checksum is a fact about
the input, so the test is that sealing repairs it and changes nothing else, and
the round trip then reproduces the file except those two bytes. The index reads
V1.0.5 as well: 120 images, and the same boot animation to the byte.

Nothing in it writes to the firmware, opens a MIDI port or touches a device.

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

### `tools/ht_packet.py`

The wire format, built rather than sent. Every host-to-device message is one
SysEx frame around a four-byte header:

```
BUF  = [ crc8 ][ command ][ index ][ length ][ length payload bytes ]
wire = F0, then for each byte of BUF: (b >> 4), (b & 0x0F), then F7
```

`crc8` is CRC-8/0x07, init 0, over the whole of BUF with its own slot zeroed;
the nibble split is what keeps every byte under `0x80`. Read out of
`5868USB.dll`'s own packet builder, and `verify` checks the table this file
generates against the 256 bytes in the DLL — they match exactly.

The firmware update turns out not to stream the file at all. `deviceStartUpdate`
parses the container, LZO-decompresses the payload when the header says packed,
recomputes every section's CRC-16/MODBUS and compares it big-endian against the
stored value, then sends one message per section: payload `0x11, <section id>`
followed by the whole section, split into blocks of **42 bytes** (19 in the
compressed mode `setDeviceCompress` selects).

```
ht_packet.py verify                     table against the DLL's own
ht_packet.py frame <cmd> <index> <hex>  build one frame
ht_packet.py parse <hex>                take one apart
ht_packet.py plan <fw.bin>              what an update would send
```

`plan` prints the schedule — for GP-150 V1.1.1, 191 240 frames of 94 bytes,
17.6 MB on the wire for a 5 MB file — and stops there. **Nothing in this module
opens a MIDI port.** Every field is read out of the vendor's code rather than
invented, and none of it has been checked against a capture here; the one thing
the code does not settle is where the one-byte block index wraps. The GP-50
project's warning that guessed traffic wedged a pedal once stands.

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

### `tools/suite_map.py`

What is legible in Suite's Dart snapshot. `data/app.so` is an ELF whose
`.dynsym` names the snapshot blobs — `_kDartIsolateSnapshotData` is 4.4 MB of
objects and `_kDartIsolateSnapshotInstructions` 6.3 MB of AOT x86-64. Reading
the objects properly means implementing that Dart version's cluster
deserialiser, which is what blutter does by compiling the matching SDK, and is
not what this is.

It does not have to be. **The snapshot was not built obfuscated**, so every
library URI, class name and member name is in it as an ordinary string, and that
maps the application:

```
package:qme10_pc                 223 source files — Suite itself
package:ht_midi_data_protocol     28 source files — the device protocol
package:flutter                  389, and 90 more packages
```

The protocol package is the interesting half: `src/core/protocol/` holds
`ht_protocol_handler`, `receive_assembler`, an `ack_dispatcher`, a `negotiator`
and `constants`; `src/core/utils/` holds `crc_utils`, `midi_codec`,
`data_wrap_codec`, `ht_firmware_parser` and `ht_firmware_update`; `src/device/`
has separate USB, BLE and MIDI device managers behind a `unified_device`. Suite
itself is a Flutter app of 223 files under `Views/`, `model150/` and `utils/`,
and `model150/` — 39 files — is where the GP-150's own data model lives.

The FFI seam is exact: 18 of `5868USB.dll`'s 61 exports are named in the
snapshot, and they are the ones this repo's own tools call — `checkCrc`,
`connectDevice`, `deviceStartUpdate`, `sendMidiMessage`, `scanInDevice`,
`isRealFirmware`, plus `convertNamToNambAtPath` and the SnapTone conversion
entry points.

```
suite_map.py map                  packages, files, FFI surface
suite_map.py files [pkg]          source files, one per line
suite_map.py classes [--like RE]  class-shaped names
suite_map.py ffi                  which exports the Dart side binds
suite_map.py strings [--like RE]
suite_map.py keys [--key N]       private names grouped by library key
```

Names are canonicalised into one unordered table, so they cannot be grouped back
into their classes by position: what comes out is an inventory, not source.
Private members do carry Dart's per-library key (`_bind@637311317`), which
groups them by library — 5398 names in 614 groups — even though the key itself
does not say which library it belongs to.

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
That also means blocks that were allocated and never filled sit in the file with
perfectly good geometry and leftover bytes inside. `grade()` sorts them, on two
signals that take both to be useful: **noise does not compress** (artwork goes
under a tenth through deflate, leftovers stay near a quarter) and **stale data
is streaky** (its rows are long runs and each row is unrelated to the one above,
so the vertical difference dwarfs the horizontal one, where artwork is coherent
both ways). On V1.1.1 that is 94 artwork, 3 doubtful, 35 never filled, with two
stragglers in the artwork bucket — good enough for the default view to be clean
and for nothing to be thrown away.

### `tools/gif_tool.py`

The boot animation, which is an ordinary GIF. Section `b` carries a 448 KB run
that no descriptor covers and that reads as noise at every width — the only
high-entropy window in the payload outside the Bluetooth SoC's firmware. It is
`0x207AE5`, 474 509 bytes, **320x240 — the screen's own resolution — 57 frames
at 40 ms**: the "GP-150 / HD MODELING TECH II" splash resolving into VALETON.
Whoever built it left the comment extension in place, so the file says
`GIF compressed with https://ezgif.com/optimize`.

Nothing indexes it, and the format has no length field, so it is found by its own
magic and walked block by block to its trailer — which matters, because the bytes
straight after it are more artwork.

```
gif_tool.py list    <fw.bin>
gif_tool.py extract <fw.bin> <out.gif> [n]
gif_tool.py inject  <fw.bin> <in.gif> <out.bin> [n]
```

The slot cannot grow, but a GIF reader stops at its trailer, so a smaller
animation padded with zeros is a valid replacement. Studio shows it animated at
the top of the Graphics tab and takes a new one on a click.

### `tools/gif_fit.py`

Squeezing an animation into that slot. It is fixed at 474 509 bytes and 320x240,
so an 18 MB clip has to lose 97% of itself, and there are only three places to
take it from - frames, palette, picture size. This tries the first two against
the budget and says what it gave up.

```
gif_fit.py fit <in.gif> <out.gif> --slot <fw.bin>
                   [--size 320x240] [--fit letterbox|crop|stretch]
                   [--colors N] [--frames N] [--fps N] [--clip a:b]
                   [--quant octree|maxcov|medcut] [--dither]
```

```
slot in deploy-test.bin: 474509 bytes, 320x240
  128 colours ->  42 frames,  461889 bytes (97% of the slot)
   64 colours ->  50 frames,  459377 bytes (97% of the slot)
   32 colours -> 124 frames,  468859 bytes (99% of the slot)
   16 colours -> 141 frames,  469198 bytes (99% of the slot)
```

Two things decide the result, and neither is obvious. **The quantiser matters
more than the palette size**: median cut - what Pillow's `convert('P', ADAPTIVE)`
does, and what most scripts therefore use - spends its palette where the pixels
are, so a clip with a dark background gets thirty shades of near-black and
nothing left for the gold and pink the picture is actually about. The result is
recognisable and completely desaturated. Octree keeps the hues, and on this clip
it also gave **124 frames instead of 41** at the same 32 colours, because
flatter areas compress better. **Dithering is off by default** for the same
reason: its noise is exactly what LZW cannot compress, and it costs a third of
the file - a third that buys frames.

It writes the shape of GIF the firmware already carries: full-size frames, one
global palette, no local colour tables, no transparency, no disposal tricks. The
stock animation is exactly that, so it is the shape known to play.

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

### `tools/nam2namb.py`

The GP-150 does not read `.nam`. Valeton Suite converts a capture into a
**`.namb`** — a binary NAM, magic `BMAN` — and that is what reaches the pedal.
The conversion is exported from Suite's own `assets/5868USB.dll` as plain C, so
it can be driven directly:

```c
const char *convertNamToNambAtPath(const char *in, const char *out, double slim);
const char *convertNamToNambWithSlim(const char *in, double slim);
const char *convertNamToNamb(const char *in);
const char *getLastNamToNambError(void);
```

Captures people download today (TONE3000, NAM 0.7.0) are **SlimmableContainers**:
one file holding the same amp trained at several widths, each submodel tagged
with a `max_value`. `slim` only picks one of them. That is the whole of the
vendor's optimisation, and it says nothing about what the choice costs — which
is the part this adds.

```
nam2namb.py info    <file.nam>                  submodels, cost, sizes
nam2namb.py check   <file.nam> [--wav di.wav]   ESR of each submodel
nam2namb.py convert <file.nam> [-o out.namb] [--slim F]
nam2namb.py batch   <dir> [-o outdir] [--slim F]
nam2namb.py namb    <file.namb>                 header of a converted file
```

A typical TONE3000 capture holds a 3-channel and an 8-channel submodel of the
same amp:

```
slim   channels MAC/samp  namb     M7 load   ESR vs best
<=0.5  3        1731      7.8 KB   14%       0.0026  (-25.9 dB)
<=1    8        11776     47.9 KB  94%       reference
```

`M7 load` is the model's multiply-accumulates per sample against a 600 MHz
Cortex-M7 retiring roughly one per cycle at 48 kHz — an estimate, but a decisive
one: the wide submodel would need most of the core on its own, so `slim 0` and
the narrow submodel is not a compromise the tool invents, it is the only one
that runs. `check` says what that costs: measured over Suite's own DI, a clean
amp loses 0.0026 ESR and a high-gain lead patch 0.0115, which is the expected
shape — the more distortion, the harder it compresses.

ESR is measured by **running both models**. The WaveNet forward pass is
implemented here in numpy, and it is not a guess: the weight layout it assumes
reproduces the exact weight count of every submodel in a file (1871 for a
3-channel model, 12146 for an 8-channel one, to the weight), and the two
independently trained submodels of one capture come out correlated at 0.996 —
which only happens if both are being read correctly.

The `.namb` container itself:

```
0x00  char[4]  "BMAN"
0x04  u32      format version, 1
0x08  u32      total file size
0x0C  u32      offset of the weights, 496
0x10  u32      number of weights
0x14  u32      length of the config block at 0x50
0x18  u32      checksum
0x20  u8[3]    NAM version, 0.7.0
0x23  u8       architecture id, 1 = WaveNet
0x24  double   sample rate
0x2C  double   loudness, LUFS
0x50  ...      config block, then float32 weights at 0x1F0
```

The weights are the capture's own, float32, byte-identical to the JSON they came
from — the conversion is a repack plus a submodel choice, not a refit. And the
magic is in the firmware: `BMAN` appears once in section `b`, at `0x00E818`, in
a literal pool between Thumb functions, so the pedal parses NAMB itself and the
RT1064 is running the capture's own WaveNet. (The *SnapTone* path in the same
library — `namConvertClo*` — is a refit onto a much smaller proprietary model,
and that is what the A1 devices, GP-5 and GP-50, get instead.)

### `tools/ghidra/DecompileExports.java`

Decompile named exports of a DLL, and everything they call to a given depth, to
C. Written for `5868USB.dll`, which is the better of the two vendor libraries to
read: 61 exports against the macOS dylib's handful, and it carries the whole NAM
to NAMB converter.

```
analyzeHeadless <proj-dir> <proj-name> -import 5868USB.dll     -scriptPath tools/ghidra -postScript DecompileExports.java     work/decomp 2 checkCrc deviceStartUpdate sendMidiMessage -deleteProject
```

Analysis of the 2.8 MB library takes about a minute; six exports at depth 2 come
to 137 functions. `checkCrc` decompiles to exactly the rules this repo worked
out by measurement — length against header `0x08`, CRC-16/MODBUS from offset 6,
compared big-endian against header `0x04`, `-2` and `-1` for the two failures —
which is the first confirmation of them from Valeton's own code.

Keep the output out of the repository: it is Valeton's code however it is
spelled. `work/` is gitignored for it.

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
  verbatim — the first linear file→`0x80000000` mapping demonstrated here. The
  delta changes between runs, so it is not one mapping for the whole section.
  The 73 `0x8000xxxx` veneer targets in the bootstrap were swept again against
  every possible base with a Thumb-prologue test, independently of the earlier
  attempt: best 8 of 73 against 4.4 expected by chance, which is noise. So that
  half stands where it did.
- **Where the update protocol's block index wraps.** `index` is one byte and a
  section runs to six figures of blocks (`tools/ht_packet.py plan`), so the
  counter must wrap; nothing in the library's code says where, and it would take
  one captured update to settle.
- **About 13% of the artwork carries no descriptor** — four areas, the largest
  76 KB. They decode correctly once the byte phase is right, so they are real
  pictures; they simply sit outside the heap runs the descriptors cover, and
  nothing has been found that indexes them.
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
