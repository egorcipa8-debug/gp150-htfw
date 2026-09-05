# Credits

This project is about the Valeton GP-150. Some of what it knows was not worked
out here, and this file says whose it is.

## The GP-200 reverse-engineering series

**tntexplosivesltd** — <https://gp200-reversing.hashnode.dev/>

A public series on the GP-200, the GP-150's bigger sibling: the teardown, the
flash dump over SWD, the updater protocol, a firmware patcher, the front panel
and a tuner mod that runs on real hardware.

What this project took from it, all of it credited in `FINDINGS.md` §26 and §27:

* **The boot copy chain.** The application is not one flat image at one address:
  the bootloader copies one block into ITCM and another into SDRAM before it
  starts executing. That is what §23 here had run into and could not name — the
  interface code that appeared to be "missing" from the update image.
* **The screen registry** as a concept, and the method of finding it: patch the
  boot sequence to jump straight to screen *N*, reflash, look at the display.
* **SWD is open.** `SEC_CONFIG @ 0x401F4460 = 0x00000008` on their unit — HAB
  open, no signature block — and an 8 MB dump off a five-pad header with
  OpenOCD. The GP-150 is the same silicon family.
* **The A2 / NAM answer.** Their measurement that the pedal runs FFT convolution
  of a fixed impulse response plus biquads, not neural inference, and that
  Valeton's A2 support is an offline fit done by the desktop editor.
* The LED frame format and the tuner subsystem, as documented findings.

Their `gp200fw` toolchain is not public; the tuner mod is released as a
browser-side patcher. Nothing from it is vendored here.

## The GP-200 editor

**phash** — <https://github.com/phash/gp200editor>

A web editor for the GP-200 with `docs/sysex-protocol.md`, a full write-up of
that device's SysEx protocol: message envelope, sub-commands, nibble encoding,
the 1176-byte preset layout, block ids, effect id structure, the `.prst` file
format.

The GP-150 speaks a *different* protocol — a different envelope, a different
checksum, objects addressed by id rather than commands with sub-codes — so
nothing was copied. What their document gave us is the shape to test against:
the family's preset layout (header, name, author, routing order, per-slot effect
blocks, controller assignments in the tail) and the confirmation that these
boxes read presets back in nibble-encoded chunks. Our `It's GP-150` sitting
where their `It's GP-200` sits is how we knew our 1136-byte object was a patch.

## Everything else

The GP-150 firmware container, the image descriptors and pixel order, the
graphics index, the boot animation, the NAM tooling, the updater wire format,
the editor protocol in `tools/ht_sysex.py`, the capture rigs in `tools/spy/`
and Studio were worked out here, against a GP-150 and its own firmware images.

Valeton firmware images, the vendor's model catalogs and any artwork extracted
from them are **not** redistributed by this project, and neither is any vendor
library or a decompilation of one.
