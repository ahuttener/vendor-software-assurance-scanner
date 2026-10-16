"""Artifact loading and feature extraction.

Supports PE (Windows .exe/.dll), ELF (Linux), Mach-O (macOS, basic) and
ZIP-based packages (APK/JAR). Everything here is read-only: we open the file,
parse headers and pull out strings, symbols, URLs and hardening metadata.
"""
from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from typing import Any

# Printable ASCII runs, and UTF-16LE runs (common in PE binaries).
_ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")

MAX_EMBEDDED_SCAN = 8 * 1024 * 1024  # cap per-entry scan inside archives


@dataclass
class Artifact:
    path: str
    size: int
    fmt: str                              # 'pe' | 'elf' | 'macho' | 'zip' | 'unknown'
    metadata: dict[str, Any] = field(default_factory=dict)
    strings: list[tuple[int, str]] = field(default_factory=list)   # (offset, text)
    symbols: list[str] = field(default_factory=list)
    hardening: dict[str, Any] = field(default_factory=dict)
    entries: list[str] = field(default_factory=list)               # archive members

    def all_text(self) -> str:
        """All extracted strings joined, for cheap substring scans."""
        return "\n".join(s for _, s in self.strings)


def _extract_strings(data: bytes) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for m in _ASCII_RE.finditer(data):
        out.append((m.start(), m.group().decode("ascii", "replace")))
    for m in _UTF16_RE.finditer(data):
        out.append((m.start(), m.group().decode("utf-16le", "replace")))
    return out


def _detect_format(data: bytes) -> str:
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                    b"\xca\xfe\xba\xbe"):
        return "macho"
    if data[:4] == b"PK\x03\x04":
        return "zip"
    return "unknown"


def _parse_elf(path: str, art: Artifact) -> None:
    """Hardening + symbols for ELF using pyelftools."""
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.dynamic import DynamicSection
        from elftools.elf.sections import SymbolTableSection
    except Exception as exc:                       # pragma: no cover
        art.hardening["error"] = f"pyelftools unavailable: {exc}"
        return

    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        etype = elf.header["e_type"]
        art.metadata["elf_type"] = etype
        art.metadata["machine"] = elf.header["e_machine"]
        pie = etype == "ET_DYN"

        nx = True          # NX on unless GNU_STACK is executable
        relro = False
        bind_now = False
        for seg in elf.iter_segments():
            t = seg["p_type"]
            if t == "PT_GNU_STACK":
                nx = not bool(seg["p_flags"] & 0x1)   # PF_X
            elif t == "PT_GNU_RELRO":
                relro = True

        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    if tag.entry.d_tag == "DT_BIND_NOW":
                        bind_now = True
                    if tag.entry.d_tag == "DT_FLAGS" and (tag.entry.d_val & 0x8):   # DF_BIND_NOW
                        bind_now = True
                    if tag.entry.d_tag == "DT_FLAGS_1" and (tag.entry.d_val & 0x1):  # DF_1_NOW
                        bind_now = True

        names: list[str] = []
        for sec in elf.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    if sym.name:
                        names.append(sym.name)
        art.symbols = sorted(set(names))

        canary = "__stack_chk_fail" in art.symbols
        art.hardening = {
            "platform": "elf",
            "pie": pie,
            "nx": nx,
            "relro": "full" if (relro and bind_now) else ("partial" if relro else "none"),
            "stack_canary": canary,
            "signed": False,     # ELF binaries are normally signed externally (package/repo)
            "signed_note": "ELF integrity is typically provided by package/repo signatures, not embedded.",
        }


def _parse_pe(path: str, art: Artifact) -> None:
    """Hardening + imports for PE using pefile."""
    try:
        import pefile
    except Exception as exc:                       # pragma: no cover
        art.hardening["error"] = f"pefile unavailable: {exc}"
        return

    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories()
    dc = pe.OPTIONAL_HEADER.DllCharacteristics
    aslr = bool(dc & 0x0040)        # DYNAMIC_BASE
    dep = bool(dc & 0x0100)         # NX_COMPAT
    cfg = bool(dc & 0x4000)         # GUARD_CF
    force_integrity = bool(dc & 0x0080)

    # Authenticode signature lives in the security directory (index 4).
    signed = False
    try:
        sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        signed = sec.VirtualAddress != 0 and sec.Size != 0
    except Exception:
        pass

    imports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for mod in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in mod.imports:
                if imp.name:
                    imports.append(imp.name.decode("ascii", "replace"))
    art.symbols = sorted(set(imports))
    art.metadata["machine"] = hex(pe.FILE_HEADER.Machine)
    art.hardening = {
        "platform": "pe",
        "aslr": aslr,
        "dep_nx": dep,
        "cfg": cfg,
        "force_integrity": force_integrity,
        "signed": signed,
    }
    pe.close()


def _parse_zip(path: str, art: Artifact) -> None:
    """APK/JAR/other ZIP: list members and pull strings from text-ish members."""
    with zipfile.ZipFile(path) as zf:
        art.entries = zf.namelist()
        art.metadata["archive_members"] = len(art.entries)
        art.metadata["is_apk"] = any(n == "AndroidManifest.xml" for n in art.entries)
        art.metadata["is_jar"] = any(n.startswith("META-INF/") and n.endswith(".MF")
                                     for n in art.entries)
        # APK/JAR signatures live under META-INF (*.RSA/*.DSA/*.EC or v2+ block).
        art.hardening = {
            "platform": "zip",
            "signed": any(n.startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))
                          for n in art.entries),
        }
        extra: list[tuple[int, str]] = []
        for name in art.entries:
            try:
                if zf.getinfo(name).file_size > MAX_EMBEDDED_SCAN:
                    continue
                blob = zf.read(name)
            except Exception:
                continue
            for off, s in _extract_strings(blob):
                extra.append((off, f"[{name}] {s}"))
        art.strings.extend(extra)


def load(path: str) -> Artifact:
    """Open an artifact and extract everything the detectors need."""
    with open(path, "rb") as fh:
        data = fh.read()
    fmt = _detect_format(data)
    art = Artifact(path=path, size=len(data), fmt=fmt)
    art.strings = _extract_strings(data)

    try:
        if fmt == "elf":
            _parse_elf(path, art)
        elif fmt == "pe":
            _parse_pe(path, art)
        elif fmt == "zip":
            _parse_zip(path, art)
        elif fmt == "macho":
            art.hardening = {"platform": "macho", "signed": False,
                             "note": "Mach-O parsing is basic; strings only."}
    except Exception as exc:                        # never let one parser abort the scan
        art.metadata["parse_error"] = f"{type(exc).__name__}: {exc}"

    return art
