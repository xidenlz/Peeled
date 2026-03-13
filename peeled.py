# MIT License
# Copyright (c) 2026 xdenlz
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import annotations
import sys
import os
import struct
from pathlib import Path


def _supports_color() -> bool:
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32         
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

USE_COLOR = _supports_color()

class C:
    RESET   = "\033[0m"  if USE_COLOR else ""
    BOLD    = "\033[1m"  if USE_COLOR else ""
    DIM     = "\033[2m"  if USE_COLOR else ""
    RED     = "\033[91m" if USE_COLOR else ""
    GREEN   = "\033[92m" if USE_COLOR else ""
    YELLOW  = "\033[93m" if USE_COLOR else ""
    BLUE    = "\033[94m" if USE_COLOR else ""
    MAGENTA = "\033[95m" if USE_COLOR else ""
    CYAN    = "\033[96m" if USE_COLOR else ""
    WHITE   = "\033[97m" if USE_COLOR else ""
    ORANGE  = "\033[38;5;214m" if USE_COLOR else ""

def color(text: str, *codes: str) -> str:
    if not codes:
        return text
    return "".join(codes) + text + C.RESET

def sep(char: str = "─", width: int = 64) -> str:
    return color(char * width, C.DIM)

def banner() -> None:
    print(color(r"""
  ██████╗ ███████╗███████╗██╗     ███████╗██████╗
  ██╔══██╗██╔════╝██╔════╝██║     ██╔════╝██╔══██╗
  ██████╔╝█████╗  █████╗  ██║     █████╗  ██║  ██║
  ██╔═══╝ ██╔══╝  ██╔══╝  ██║     ██╔══╝  ██║  ██║
  ██║     ███████╗███████╗███████╗███████╗██████╔╝
  ╚═╝     ╚══════╝╚══════╝╚══════╝╚══════╝╚═════╝
""", C.CYAN, C.BOLD))
    print(color("  PE Embedded Payload Detector & Extractor", C.WHITE, C.BOLD))
    print(color("  github.com/xdenlz  ·  MIT License\n", C.DIM))





MAGICS: list[tuple[bytes, str]] = [
    (b"MZ",                  "PE/MZ"),
    (b"PK\x03\x04",          "ZIP"),
    (b"7z\xBC\xAF\x27\x1C",  "7z"),
    (b"Rar!\x1A\x07",        "RAR"),
    (b"%PDF-",               "PDF"),
    (b"\x89PNG\r\n\x1a\n",   "PNG"),
    (b"\xFF\xD8\xFF",        "JPEG"),
    (b"GIF87a",              "GIF"),
    (b"GIF89a",              "GIF"),
    (b"BM",                  "BMP"),
    (b"II*\x00",             "TIFF"),
    (b"MM\x00*",             "TIFF"),
    (b"SQLite format 3\x00", "SQLite"),
    (b"\x1F\x8B\x08",        "GZIP"),
    (b"BZh",                 "BZIP2"),
    (b"\xFD7zXZ\x00",        "XZ"),
    (b"MSCF",                "CAB"),
    (b"RIFF",                "RIFF"),     
    (b"\x00\x00\x01\x00",    "ICO"),
    (b"MThd",                "MIDI"),
    (b"\x7fELF",             "ELF"),
    (b"\xCE\xFA\xED\xFE",    "Mach-O"), 
    (b"\xCF\xFA\xED\xFE",    "Mach-O"), 
    (b"\xFE\xED\xFA\xCE",    "Mach-O"), 
    (b"\xFE\xED\xFA\xCF",    "Mach-O"), 
]


EXTRACT_NAMES: set[str] = {"PNG", "JPEG", "GIF", "BMP", "TIFF", "PE/MZ"}


MAGIC_COLORS: dict[str, str] = {
    "PE/MZ":  C.RED,
    "ZIP":    C.YELLOW,
    "7z":     C.YELLOW,
    "RAR":    C.YELLOW,
    "PDF":    C.MAGENTA,
    "PNG":    C.CYAN,
    "JPEG":   C.CYAN,
    "GIF":    C.CYAN,
    "BMP":    C.CYAN,
    "TIFF":   C.CYAN,
    "SQLite": C.BLUE,
    "GZIP":   C.GREEN,
    "BZIP2":  C.GREEN,
    "XZ":     C.GREEN,
    "CAB":    C.YELLOW,
    "RIFF":   C.BLUE,
    "ICO":    C.CYAN,
    "MIDI":   C.BLUE,
    "ELF":    C.ORANGE,
    "Mach-O": C.ORANGE,
}

def fmt_magic(name: str) -> str:
    c = MAGIC_COLORS.get(name, C.WHITE)
    return color(f"[{name}]", c, C.BOLD)



RT_RCDATA                     = 10
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_FILE_DLL                = 0x2000
IMAGE_FILE_SYSTEM             = 0x1000   


_SUBSYSTEM: dict[int, tuple[str, str, str]] = {
    0:  ("Unknown",             "bin", ".bin"),
    1:  ("Native / Driver",     "sys", ".sys"),
    2:  ("Windows GUI",         "exe", ".exe"),
    3:  ("Windows CUI",         "exe", ".exe"),
    5:  ("OS/2 CUI",            "exe", ".exe"),
    7:  ("POSIX CUI",           "exe", ".exe"),
    8:  ("Native Win9x",        "exe", ".exe"),
    9:  ("Windows CE GUI",      "exe", ".exe"),
    10: ("EFI Application",     "efi", ".efi"),
    11: ("EFI Boot Svc Driver", "efi", ".efi"),
    12: ("EFI Runtime Driver",  "efi", ".efi"),
    13: ("EFI ROM Image",       "efi", ".efi"),
    14: ("Xbox",                "exe", ".exe"),
    16: ("Boot Application",    "exe", ".exe"),
}



def u16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]

def u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]



def classify_pe_blob(data: bytes) -> tuple[str, str, str]:
    """
    Parse PE COFF + Optional headers to determine the exact PE sub-type.
    Returns (human_label, short_tag, extension).
    Characteristics & IMAGE_FILE_SYSTEM    Kernel Driver  (.sys)
    Subsystem == 1  (Native)               Kernel Driver  (.sys)
    Subsystem in 10-13 (EFI)               EFI binary     (.efi)
    Characteristics & IMAGE_FILE_DLL       DLL            (.dll)
    else                                   EXE            (.exe)
    """
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return ("MZ (truncated/stub)", "bin", ".bin")

        pe_off = u32(data, 0x3C)
        if pe_off + 24 > len(data):
            return ("MZ (no PE offset)", "bin", ".bin")
        if data[pe_off:pe_off+4] != b"PE\x00\x00":
            return ("MZ (no PE sig)", "bin", ".bin")

        coff    = pe_off + 4
        chars   = u16(data, coff + 18)  
        opt_off = coff + 20


        if opt_off + 70 > len(data):

            if chars & IMAGE_FILE_SYSTEM:
                return ("Kernel Driver (sys)", "sys", ".sys")
            if chars & IMAGE_FILE_DLL:
                return ("Dynamic Link Library (dll)", "dll", ".dll")
            return ("Executable (exe)", "exe", ".exe")

        opt_magic = u16(data, opt_off)
        if opt_magic not in (0x10B, 0x20B):
            return ("PE (bad optional-header magic)", "bin", ".bin")

        arch       = "PE32+" if opt_magic == 0x20B else "PE32"
        subsystem  = u16(data, opt_off + 68)

        is_driver  = bool(chars & IMAGE_FILE_SYSTEM)
        is_dll     = bool(chars & IMAGE_FILE_DLL)
        is_efi     = subsystem in (10, 11, 12, 13)

        sub_info = _SUBSYSTEM.get(subsystem, ("?", "exe", ".exe"))

        if is_driver or subsystem == 1:
            return (f"Kernel Driver [{arch}]", "sys", ".sys")
        if is_efi:
            return (f"EFI Binary — {sub_info[0]} [{arch}]", "efi", ".efi")
        if is_dll:
            return (f"DLL — {sub_info[0]} [{arch}]", "dll", ".dll")
        return (f"EXE — {sub_info[0]} [{arch}]", "exe", ".exe")

    except Exception as exc:
        return (f"PE (parse error: {exc})", "bin", ".bin")


def classify_riff(data: bytes) -> tuple[str, str, str]:
    """Sub-classify a RIFF container using the 4-byte form-type field at offset 8."""
    if len(data) < 12:
        return ("RIFF (truncated)", "riff", ".riff")
    form = data[8:12]
    table = {
        b"WEBP": ("WebP Image",       "webp", ".webp"),
        b"WAVE": ("WAV Audio",        "wav",  ".wav"),
        b"AVI ": ("AVI Video",        "avi",  ".avi"),
        b"RMID": ("RIFF MIDI",        "mid",  ".mid"),
        b"ACON": ("Animated Cursor",  "ani",  ".ani"),
        b"CDDA": ("CD Audio",         "cda",  ".cda"),
    }
    if form in table:
        return table[form]
    tag = form.decode(errors="replace").strip()
    return (f"RIFF/{tag}", "riff", ".riff")


def classify_blob(data: bytes) -> tuple[str, str, str]:
    """
    Identify any blob by its magic bytes.
    Returns (human_label, short_tag, file_extension).
    """
    if len(data) < 2:
        return ("Empty / Too Small", "bin", ".bin")

    h = data[:16]


    if h[:2] == b"MZ":
        return classify_pe_blob(data)


    if h[:8] == b"\x89PNG\r\n\x1a\n":
        return ("PNG Image", "png", ".png")
    if h[:3] == b"\xFF\xD8\xFF":
        return ("JPEG Image", "jpg", ".jpg")
    if h[:6] in (b"GIF87a", b"GIF89a"):
        ver = h[3:6].decode()
        return (f"GIF Image ({ver})", "gif", ".gif")
    if h[:2] == b"BM":
        return ("BMP Image", "bmp", ".bmp")
    if h[:4] in (b"II*\x00", b"MM\x00*"):
        return ("TIFF Image", "tif", ".tif")
    if h[:4] == b"\x00\x00\x01\x00":
        return ("ICO Image", "ico", ".ico")
    if h[:4] == b"\x00\x00\x02\x00":
        return ("CUR Cursor", "cur", ".cur")


    if h[:4] == b"RIFF":
        return classify_riff(data)


    if h[:4] == b"PK\x03\x04":

        peek = data[:4096]
        if b"word/" in peek:
            return ("Word Document (OOXML/ZIP)", "docx", ".docx")
        if b"xl/" in peek and b"workbook" in peek:
            return ("Excel Workbook (OOXML/ZIP)", "xlsx", ".xlsx")
        if b"ppt/" in peek:
            return ("PowerPoint (OOXML/ZIP)", "pptx", ".pptx")
        return ("ZIP Archive", "zip", ".zip")
    if h[:6] == b"7z\xBC\xAF\x27\x1C":
        return ("7-Zip Archive", "7z", ".7z")
    if h[:7] in (b"Rar!\x1A\x07\x00", b"Rar!\x1A\x07\x01"):
        ver = "v5" if h[6] == 1 else "v4"
        return (f"RAR Archive ({ver})", "rar", ".rar")
    if h[:3] == b"\x1F\x8B\x08":
        return ("GZIP Archive", "gz", ".gz")
    if h[:3] == b"BZh":
        return ("BZIP2 Archive", "bz2", ".bz2")
    if h[:6] == b"\xFD7zXZ\x00":
        return ("XZ Archive", "xz", ".xz")
    if h[:4] == b"MSCF":
        return ("MS Cabinet", "cab", ".cab")


    if h[:5] == b"%PDF-":
        ver = data[5:8].decode(errors="replace") if len(data) > 8 else "?"
        return (f"PDF Document (v{ver})", "pdf", ".pdf")
    if h[:8] == b"\xD0\xCF\x11\xE0\xa1\xb1\x1a\xe1":
        return ("OLE2 / Legacy MS Office (.doc/.xls/.ppt)", "ole", ".doc")
    if h[:16] == b"SQLite format 3\x00":
        return ("SQLite Database", "db", ".db")


    if h[:4] == b"\x7fELF":
        ei_class = data[4] if len(data) > 4 else 0
        bits = {1: "32-bit", 2: "64-bit"}.get(ei_class, "?-bit")
        return (f"ELF Binary ({bits})", "elf", ".elf")
    if h[:4] in (b"\xCE\xFA\xED\xFE", b"\xCF\xFA\xED\xFE",
                 b"\xFE\xED\xFA\xCE", b"\xFE\xED\xFA\xCF"):
        bits = "64-bit" if h[3] in (0xCF, 0xFA) else "32-bit"
        return (f"Mach-O Binary ({bits})", "macho", "")


    if h[:4] == b"MThd":
        return ("MIDI Audio", "mid", ".mid")
    if h[:3] == b"ID3" or h[:2] == b"\xFF\xFB":
        return ("MP3 Audio", "mp3", ".mp3")
    if len(data) > 8 and data[4:8] == b"ftyp":
        return ("MP4 / MOV Video", "mp4", ".mp4")
    if h[:4] == b"\x1a\x45\xDF\xA3":
        return ("MKV / WebM Video", "mkv", ".mkv")


    if h[:2] == b"#!":
        return ("Shell Script", "sh", ".sh")

    return ("Unknown", "bin", ".bin")



_TYPE_COLOR: dict[str, str] = {
    "exe":   C.RED,
    "dll":   C.ORANGE,
    "sys":   C.MAGENTA,
    "efi":   C.MAGENTA,
    "png":   C.CYAN,
    "jpg":   C.CYAN,
    "gif":   C.CYAN,
    "bmp":   C.CYAN,
    "tif":   C.CYAN,
    "webp":  C.CYAN,
    "ico":   C.CYAN,
    "zip":   C.YELLOW,
    "7z":    C.YELLOW,
    "rar":   C.YELLOW,
    "gz":    C.GREEN,
    "bz2":   C.GREEN,
    "xz":    C.GREEN,
    "cab":   C.YELLOW,
    "pdf":   C.MAGENTA,
    "db":    C.BLUE,
    "elf":   C.ORANGE,
    "macho": C.ORANGE,
    "wav":   C.BLUE,
    "avi":   C.BLUE,
    "mp3":   C.BLUE,
    "mp4":   C.BLUE,
    "mkv":   C.BLUE,
    "mid":   C.BLUE,
}

def fmt_type(label: str, tag: str, ext: str) -> str:
    c       = _TYPE_COLOR.get(tag, C.WHITE)
    display = ext if ext else f"({tag})"
    return f"{color(display, c, C.BOLD)}  {color(label, C.DIM)}"



def parse_pe(buf: bytes):
    if len(buf) < 0x100 or buf[:2] != b"MZ":
        raise ValueError("Not an MZ/PE file")
    pe_off = u32(buf, 0x3C)
    if pe_off + 4 > len(buf) or buf[pe_off:pe_off+4] != b"PE\x00\x00":
        raise ValueError("Missing PE signature")

    coff     = pe_off + 4
    nsec     = u16(buf, coff + 2)
    opt_size = u16(buf, coff + 16)
    opt_off  = coff + 20

    magic = u16(buf, opt_off)
    if magic not in (0x10B, 0x20B):
        raise ValueError("Bad optional header magic")

    data_dir_off = opt_off + (96 if magic == 0x10B else 112)
    sec_table    = opt_off + opt_size
    sections = []
    for i in range(nsec):
        off = sec_table + i * 40
        if off + 40 > len(buf):
            break
        name  = buf[off:off+8].split(b"\x00", 1)[0].decode(errors="replace")
        vsize = u32(buf, off + 8)
        vaddr = u32(buf, off + 12)
        rsize = u32(buf, off + 16)
        rptr  = u32(buf, off + 20)
        sections.append((name, vaddr, vsize, rptr, rsize))

    return pe_off, opt_off, data_dir_off, sections


def get_data_dir(buf: bytes, data_dir_off: int, idx: int) -> tuple[int, int]:
    eoff = data_dir_off + idx * 8
    if eoff + 8 > len(buf):
        return (0, 0)
    return (u32(buf, eoff), u32(buf, eoff + 4))


def rva_to_file(buf: bytes, rva: int, sections) -> int | None:
    for (_name, vaddr, vsize, rptr, rsize) in sections:
        size = max(vsize, rsize)
        if vaddr <= rva < vaddr + size:
            return rptr + (rva - vaddr)
    return None



def find_magic_hits(blob: bytes) -> list[tuple[int, str, bytes]]:
    """First occurrence of every magic  list of (pos, category, sig)."""
    hits = []
    for sig, name in MAGICS:
        pos = blob.find(sig)
        if pos != -1:
            hits.append((pos, name, sig))
    return hits


def extract_hits_from_blob(blob: bytes) -> list[tuple[int, str]]:
    """All occurrences of extractable magics  sorted list of (pos, category)."""
    hits = []
    for sig, name in MAGICS:
        if name not in EXTRACT_NAMES:
            continue
        start = 0
        while True:
            pos = blob.find(sig, start)
            if pos == -1:
                break
            hits.append((pos, name))
            start = pos + 1
    hits.sort(key=lambda x: x[0])
    return hits



def walk_resources(buf: bytes, sections, rsrc_rva: int) -> list[tuple[int, int, int]]:
    base = rva_to_file(buf, rsrc_rva, sections)
    if base is None or base + 16 > len(buf):
        return []

    def read_dir(off: int):
        if off + 16 > len(buf):
            return None
        named = u16(buf, off + 12)
        ids   = u16(buf, off + 14)
        entries = []
        eoff = off + 16
        for i in range(named + ids):
            x = eoff + i * 8
            if x + 8 > len(buf):
                break
            name_or_id  = u32(buf, x)
            data_or_dir = u32(buf, x + 4)
            is_dir  = (data_or_dir & 0x80000000) != 0
            off_rel = data_or_dir & 0x7FFFFFFF
            is_name = (name_or_id & 0x80000000) != 0
            ident   = (name_or_id & 0x7FFFFFFF) if is_name else name_or_id
            entries.append((ident, is_dir, off_rel))
        return entries

    out: list[tuple[int, int, int]] = []
    lvl1 = read_dir(base)
    if not lvl1:
        return out

    for type_id, is_dir_t, off_t in lvl1:
        if not is_dir_t:
            continue
        lvl2 = read_dir(base + off_t)
        if not lvl2:
            continue
        for _nid, is_dir_n, off_n in lvl2:
            if not is_dir_n:
                continue
            lvl3 = read_dir(base + off_n)
            if not lvl3:
                continue
            for _lid, is_dir_l, off_l in lvl3:
                if is_dir_l:
                    continue
                data_entry_off = base + off_l
                if data_entry_off + 16 > len(buf):
                    continue
                data_rva = u32(buf, data_entry_off)
                size     = u32(buf, data_entry_off + 4)
                foff     = rva_to_file(buf, data_rva, sections)
                if foff is None:
                    continue
                out.append((type_id, size, foff))
    return out



def write_payload(out_dir: Path, base_name: str,
                  tag: str, idx: int,
                  data: bytes) -> tuple[Path, str, str, str]:
    """
    Deep-classify data, write to disk with the correct extension.
    Returns (out_path, label, short_tag, ext).
    """
    label, short_tag, ext = classify_blob(data)
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = short_tag.replace("/", "_")
    out_path = out_dir / f"{base_name}.{tag}.{idx:03d}.{safe}{ext}"
    out_path.write_bytes(data)
    return out_path, label, short_tag, ext



def main(path: str) -> int:
    banner()

    p = Path(path)
    if not p.exists():
        print(color(f"  [-] File not found: {p}", C.RED))
        return 2

    buf = p.read_bytes()


    tgt_label, tgt_tag, tgt_ext = classify_blob(buf)

    print(sep())
    print(color("  TARGET", C.BOLD, C.WHITE))
    print(sep())
    print(f"  {color('File:', C.DIM)} {color(p.name, C.CYAN, C.BOLD)}")
    print(f"  {color('Path:', C.DIM)} {color(str(p.resolve()), C.WHITE)}")
    print(f"  {color('Size:', C.DIM)} {color(f'{len(buf):,} bytes', C.WHITE)}")
    print(f"  {color('Type:', C.DIM)} {fmt_type(tgt_label, tgt_tag, tgt_ext)}")

    try:
        _pe_off, _opt_off, data_dir_off, sections = parse_pe(buf)
    except Exception as e:
        print(color(f"\n  [-] PE parse error: {e}", C.RED))
        return 3


    last_end = 0
    for (_, _, _, rptr, rsize) in sections:
        last_end = max(last_end, rptr + rsize)
    overlay_size = max(0, len(buf) - last_end)
    overlay = buf[last_end:] if overlay_size else b""


    rsrc_rva, rsrc_size = get_data_dir(buf, data_dir_off, IMAGE_DIRECTORY_ENTRY_RESOURCE)
    res_entries = walk_resources(buf, sections, rsrc_rva) if (rsrc_rva and rsrc_size) else []

    reasons:   list[str]  = []
    extracted: list[tuple[Path, str, str, str]] = []
    out_dir   = p.with_suffix(p.suffix + ".extracted")
    base_name = p.stem


    print(f"\n{sep()}")
    print(color("  OVERLAY", C.BOLD, C.WHITE))
    print(sep())

    if overlay_size:
        print(f"  {color('Size:', C.DIM)} {color(f'{overlay_size:,} bytes', C.YELLOW, C.BOLD)}")
        overlay_hits = find_magic_hits(overlay)
        if overlay_hits:
            seen: set[str] = set()
            for pos, cat, _sig in overlay_hits:
                if cat in seen:
                    continue
                seen.add(cat)

                slice_data = overlay[pos:] if cat == "PE/MZ" else overlay[pos:pos+128]
                ol, otag, oext = classify_blob(slice_data)
                reasons.append(f"overlay ({overlay_size:,} bytes) — {ol} at +{pos:#x}")
                print(
                    f"  {color(f'+{pos:#010x}', C.DIM)}  "
                    f"{fmt_magic(cat)}    {fmt_type(ol, otag, oext)}"
                )

            oh = extract_hits_from_blob(overlay)
            for i, (pos, _cat) in enumerate(oh, 1):
                result = write_payload(out_dir, base_name, "overlay", i, overlay[pos:])
                extracted.append(result)
        else:
            print(f"  {color('No recognized magic bytes in overlay.', C.DIM)}")
    else:
        print(f"  {color('No overlay present.', C.DIM)}")


    print(f"\n{sep()}")
    print(color("  RESOURCES", C.BOLD, C.WHITE))
    print(sep())

    if not res_entries:
        print(f"  {color('No resource section / empty.', C.DIM)}")
    else:
        print(f"  {color('Entries scanned:', C.DIM)} {color(str(len(res_entries)), C.WHITE)}")

    res_idx = 0
    for (type_id, size, foff) in res_entries:
        if size <= 0 or foff + size > len(buf):
            continue

        blob = buf[foff:foff+size]
        hits = find_magic_hits(blob)

        if hits:
            seen2: set[str] = set()
            for pos, cat, _sig in hits:
                if cat in seen2:
                    continue
                seen2.add(cat)
                slice_data = blob[pos:] if cat == "PE/MZ" else blob[pos:pos+128]
                rl, rtag, rext = classify_blob(slice_data)
                reasons.append(
                    f"resource type={type_id} size={size:,} — {rl} at blob+{pos:#x}"
                )
                print(
                    f"  {color(f'type={type_id}', C.DIM)} "
                    f"{color(f'size={size:,}', C.DIM)}  "
                    f"{fmt_magic(cat)}    {fmt_type(rl, rtag, rext)}"
                )

            rh = extract_hits_from_blob(blob)
            for (pos, _cat) in rh:
                res_idx += 1
                result = write_payload(out_dir, base_name, f"res{type_id}", res_idx, blob[pos:])
                extracted.append(result)

        elif type_id == RT_RCDATA and size >= 256 * 1024:
            reasons.append(f"large RCDATA resource type={type_id} size={size:,}")
            print(
                f"  {color(f'type={type_id} (RCDATA)', C.DIM)} "
                f"{color(f'size={size:,}', C.YELLOW)}  "
                f"{color('← large, possibly encrypted/packed payload', C.YELLOW)}"
            )


    embedded = bool(reasons)
    print(f"\n{sep()}")
    print(color("  VERDICT", C.BOLD, C.WHITE))
    print(sep())

    if embedded:
        print(color("  [!] Embedded payload: LIKELY", C.RED, C.BOLD))
        for r in reasons:
            print(f"      {color('·', C.RED)} {r}")
    else:
        print(color("  [=] Embedded payload: NOT CONFIRMED", C.GREEN, C.BOLD))
        print(color("      No overlay-with-magic / resource-with-magic / large RCDATA.", C.DIM))


    if extracted:
        print(f"\n{sep()}")
        print(color("  EXTRACTED", C.BOLD, C.WHITE))
        print(sep())
        print(f"  {color('Output dir:', C.DIM)} {color(str(out_dir), C.CYAN)}")
        for (xp, xl, xtag, xext) in extracted:
            c = _TYPE_COLOR.get(xtag, C.WHITE)
            print(
                f"  {color('+', C.GREEN, C.BOLD)}  "
                f"{color(xext or f'.{xtag}', c, C.BOLD):<10}  "
                f"{color(xl, C.DIM):<42}  {xp.name}"
            )
    else:
        print(f"\n  {color('[=] No extractable payloads found to dump.', C.DIM)}")

    print(f"\n{sep()}\n")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python peeled.py Program.exe or peeled.exe Program.exe")
        raise SystemExit(1)
    raise SystemExit(main(sys.argv[1]))