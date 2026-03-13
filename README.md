# Peeled 🔍

![python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)
![platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)
![zero deps](https://img.shields.io/badge/dependencies-none-orange?style=flat-square)

a lightweight PE analysis tool that detects and extracts embedded payloads from windows executables. it inspects the file overlay and resource section, deep-classifies every blob it finds (exe, dll, sys, efi, png, wav, zip and more), and dumps anything suspicious to disk with the correct file extension.
i wrote this because i needed a quick static analysis pass to decide if a file was even worth my time before going deeper and this thing makes that call fast. not like other tools that make you wait around. you get an immediate read on what's hiding inside a binary, so you're not burning time reversing something that turns out to be nothing.
no third-party libraries. just python 3.10 and the standard library.

---

## what it does

- Detects embedded files hiding in the pe overlay (data appended after the last section)
- Walks the full resource directory tree and flags anything that shouldn't be there
- Deep-classifies every blob it finds using magic bytes and pe header fields, not just the file extension
- Tells you exactly what kind of pe file something is: exe, dll, kernel driver (.sys), or efi binary
- Sub-classifies riff containers into wav, avi, webp, animated cursors, etc
- Extracts and saves flagged payloads to a `.extracted` folder next to the target file
- Colored terminal output that works on windows (cmd, powershell), linux and macos
- Falls back to plain text automatically when piping output to a file

---

## what it can identify

| category | formats |
|----------|---------|
| pe binaries | .exe (gui / cui), .dll, .sys (kernel driver), .efi (all 4 subtypes), pe32 vs pe32+ |
| images | png, jpeg, gif (87a / 89a), bmp, tiff, ico, cur, webp |
| archives | zip, 7z, rar (v4 / v5), gzip, bzip2, xz, ms cabinet |
| documents | pdf (with version), ooxml (docx / xlsx / pptx), legacy ole2 office |
| audio / video | wav, avi, mp3, mp4 / mov, mkv / webm, midi |
| unix binaries | elf (32 / 64-bit), mach-o (32 / 64-bit, all endians) |
| other | sqlite databases, shell scripts, animated cursors |

---

## usage

```
python peeled.py target.exe
```
or download the latest release from [here](https://github.com/xidenlz/Peeled/releases/tag/v1.0.0) 
```
peeled.exe target.exe
```
That's it. No flags, no config files. Point it at any pe file and it figures out the rest.

The extracted payloads (if any) go into a folder called `target.exe.extracted` right next to the file you scanned.

---

## example output

```
  ██████╗ ███████╗███████╗██╗     ███████╗██████╗
  ██╔══██╗██╔════╝██╔════╝██║     ██╔════╝██╔══██╗
  ██████╔╝█████╗  █████╗  ██║     █████╗  ██║  ██║
  ██╔═══╝ ██╔══╝  ██╔══╝  ██║     ██╔══╝  ██║  ██║
  ██║     ███████╗███████╗███████╗███████╗██████╔╝
  ╚═╝     ╚══════╝╚══════╝╚══════╝╚══════╝╚═════╝

  PE Embedded Payload Detector & Extractor
  github.com/xdenlz  ·  MIT License

────────────────────────────────────────────────────────────────
  TARGET
────────────────────────────────────────────────────────────────
  File: file.dll
  Path: C:\Users\CurrentUser\Desktop\Analysis\file.dll
  Size: 15,872 bytes
  Type: .dll  DLL — Windows GUI [PE32+]

────────────────────────────────────────────────────────────────
  OVERLAY
────────────────────────────────────────────────────────────────
  No overlay present.

────────────────────────────────────────────────────────────────
  RESOURCES
────────────────────────────────────────────────────────────────
  No resource section / empty.

────────────────────────────────────────────────────────────────
  VERDICT
────────────────────────────────────────────────────────────────
  [=] Embedded payload: NOT CONFIRMED
      No overlay-with-magic / resource-with-magic / large RCDATA.

  [=] No extractable payloads found to dump.

────────────────────────────────────────────────────────────────
```

---

## how pe type detection works

When it finds an mz/pe blob it doesn't guess based on the file name or extension. it reads two fields directly out of the pe headers:

**coff characteristics** (2 bytes at `coff+18`)

```
IMAGE_FILE_DLL    0x2000  →  it's a dll
IMAGE_FILE_SYSTEM 0x1000  →  it's a kernel driver (.sys)
```

**optional header subsystem** (2 bytes at `opt_off+68`)

```
1   native               →  kernel driver (.sys)
2   windows gui          →  regular exe
3   windows cui          →  console exe
10  efi application      →  .efi
11  efi boot svc driver  →  .efi
12  efi runtime driver   →  .efi
13  efi rom image        →  .efi
```

These two checks together pin down exactly what kind of pe file you're looking at. The architecture (pe32 vs pe32+) comes from the optional header magic at `opt_off`.

---

## how riff sub-classification works

All riff containers share the same `RIFF` magic at offset 0, so you can't tell them apart from the first 4 bytes alone. The tool reads the 4-byte form-type field at offset 8:

```
WAVE  →  .wav
AVI   →  .avi
WEBP  →  .webp
ACON  →  .ani  (animated cursor)
RMID  →  .mid
```

---

## adding more signatures

Open `MAGICS` at the top of the file and add a tuple:

```python
MAGICS = [
    ...
    (b"\x52\x61\x72\x21", "RAR"),   # example
]
```

If you also want the tool to extract that type on detection, add the name to `EXTRACT_NAMES`:

```python
EXTRACT_NAMES = {"PNG", "JPEG", "PE/MZ", "ReplaceMeWithNewType"}
```

---

## requirements

- Python 3.10 or newer
- No pip installs needed, everything is stdlib

Tested on windows 10/11 (cmd and powershell), ubuntu 22.04, and macos 14.

---

