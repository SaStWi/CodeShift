"""
Native AOT & Script-to-Native-C++ Transpiler Analyzers (IL2CPP-like Runtimes).

Supports games built with AOT compilers and script-to-native runtimes comparable to Unity IL2CPP:
  1. `.NET Single-File Bundle` (AppHost single-file `.exe` embedding managed `.dll`s & configs)
  2. `HashLink` (`hlboot.dat` `HLB` magic) & `HXCPP` (Haxe-to-C++ AOT — Dead Cells, Northgard, Wartales, etc.)
  3. `GameMaker YYC` (YoYo Compiler: GML-to-C++ AOT + `data.win` metadata without `CODE` VM bytecode)
  4. `LuaJIT` (`\x1bLJ`) & `Lua 5.1–5.4` (`\x1bLua`) compiled bytecode (Hades, Noita, Balatro, Factorio, etc.)
  5. `WebAssembly` (`.wasm` `\x00asm`) binary modules (LEB128 section & export/import/data parser)
  6. `Universal Native AOT PE Analyzer` (MSVC/Itanium C++ RTTI class recovery, PE Export/Import tables
     for .NET NativeAOT/ReadyToRun, Nuitka/Cython, HXCPP, GameMaker YYC, Unreal/Godot C++ binaries)
"""
from __future__ import annotations

import json
import os
import re
import struct
import zlib
from pathlib import Path
from typing import Callable

from . import AOTAnalysisResult, CancelToken

STREAM_CHUNK = 16 * 1024 * 1024


def _read_7bit_int(buf: bytes, pos: int) -> tuple[int, int]:
    """Reads a .NET BinaryReader 7-bit encoded unsigned integer (LEB128)."""
    result = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
        if shift > 63:
            break
    return result, pos


def _read_leb128_u(buf: bytes, pos: int) -> tuple[int, int]:
    return _read_7bit_int(buf, pos)


# =============================================================================
# 1. .NET SINGLE-FILE BUNDLED EXECUTABLE UNPACKER (`SingleFileHost`)
# =============================================================================


class DotNetSingleFileUnpacker:
    """
    Detects and natively unpacks .NET 5/6/7/8/9 Single-File executables (`SingleFileHost`),
    where the game's `.dll` assemblies and JSON configs are embedded inside one `.exe`.
    """

    # Official Microsoft .NET Core / .NET 5+ AppHost Single-File 32-byte signature
    BUNDLE_SIGNATURE = bytes([
        0x8B, 0x12, 0x02, 0xB9, 0x6A, 0x61, 0x20, 0x38,
        0x72, 0x7B, 0x93, 0x02, 0x14, 0xD7, 0xA0, 0x32,
        0x13, 0xF5, 0xB9, 0xE6, 0xEF, 0xAE, 0x33, 0x18,
        0xEE, 0x3B, 0x2D, 0xCE, 0x24, 0xB3, 0x6A, 0x3D,
    ])

    @classmethod
    def find_bundle_header_offset(cls, exe_path: Path) -> int | None:
        """Scans an executable in 4 MB overlapping chunks for the .NET Single-File bundle signature."""
        if not exe_path.is_file():
            return None
        try:
            file_size = exe_path.stat().st_size
            if file_size < 128:
                return None
            sig = cls.BUNDLE_SIGNATURE
            chunk_size = 4 * 1024 * 1024
            overlap = 64
            with open(exe_path, "rb") as f:
                offset = 0
                while offset < file_size:
                    f.seek(offset)
                    chunk = f.read(chunk_size + overlap)
                    if not chunk:
                        break
                    idx = chunk.find(sig)
                    if idx != -1 and idx >= 8:
                        # The 8 bytes IMMEDIATELY preceding the 32-byte signature hold the 64-bit header offset!
                        hdr_off = struct.unpack_from("<Q", chunk, idx - 8)[0]
                        if 0 < hdr_off < file_size - 16:
                            return hdr_off
                    offset += chunk_size
        except OSError:
            return None
        return None

    @classmethod
    def unpack(
        cls,
        exe_path: Path,
        out_dir: Path,
        log_callback: Callable[[str], None] | None = None,
        cancel_token: CancelToken | None = None,
    ) -> AOTAnalysisResult:
        log = log_callback or (lambda _m: None)
        hdr_off = cls.find_bundle_header_offset(exe_path)
        if hdr_off is None:
            return AOTAnalysisResult(False, ".NET Single-File Bundle", out_dir, "No .NET Single-File bundle signature found.")

        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            file_size = exe_path.stat().st_size
            with open(exe_path, "rb") as f:
                f.seek(hdr_off)
                manifest_buf = f.read(min(16 * 1024 * 1024, file_size - hdr_off))

                major, minor, file_count = struct.unpack_from("<III", manifest_buf, 0)
                pos = 12
                id_len, pos = _read_7bit_int(manifest_buf, pos)
                bundle_id = manifest_buf[pos : pos + id_len].decode("utf-8", errors="ignore")
                pos += id_len

                if major >= 2:
                    # .NET 5+ BundleHeader v2/v6 includes deps.json, runtimeconfig.json, and flags (5 * 8 = 40 bytes)
                    pos += 40

                entries: list[tuple[str, int, int, int, int]] = []
                for _ in range(min(file_count, 50000)):
                    if pos + 18 > len(manifest_buf):
                        break
                    if major >= 6:
                        entry_off, entry_sz, comp_sz, entry_type = struct.unpack_from("<QQQB", manifest_buf, pos)
                        pos += 25
                    else:
                        entry_off, entry_sz, entry_type = struct.unpack_from("<QQB", manifest_buf, pos)
                        comp_sz = 0
                        pos += 17
                    path_len, pos = _read_7bit_int(manifest_buf, pos)
                    rel_path = manifest_buf[pos : pos + path_len].decode("utf-8", errors="replace")
                    pos += path_len
                    entries.append((rel_path, entry_off, entry_sz, comp_sz, entry_type))

                log(f"[*] Unpacking .NET Single-File Bundle v{major}.{minor} (`{bundle_id}`): {len(entries):,} embedded files...")
                extracted = 0
                dll_count = 0
                for rel_path, entry_off, entry_sz, comp_sz, _etype in entries:
                    if cancel_token:
                        cancel_token.raise_if_cancelled()
                    safe_parts = [p for p in Path(rel_path).parts if p not in ("", ".", "..", "/", "\\")]
                    if not safe_parts:
                        continue
                    target = out_dir.joinpath(*safe_parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    f.seek(entry_off)
                    if comp_sz > 0:
                        raw = zlib.decompress(f.read(comp_sz))
                        target.write_bytes(raw)
                    else:
                        remaining = entry_sz
                        with open(target, "wb") as out:
                            while remaining > 0:
                                chunk = f.read(min(STREAM_CHUNK, remaining))
                                if not chunk:
                                    break
                                out.write(chunk)
                                remaining -= len(chunk)
                    extracted += 1
                    if target.suffix.lower() == ".dll":
                        dll_count += 1

            report = (
                f"# .NET Single-File Bundle Unpack Report\n"
                f"- **Executable**: `{exe_path.name}`\n"
                f"- **Bundle Format**: v{major}.{minor} (`{bundle_id}`)\n"
                f"- **Extracted Files**: {extracted:,} ({dll_count:,} `.dll` assemblies)\n"
            )
            (out_dir / "DOTNET_BUNDLE_REPORT.md").write_text(report, encoding="utf-8")
            return AOTAnalysisResult(
                True,
                f".NET Single-File Bundle v{major}.{minor}",
                out_dir,
                f"Unpacked {extracted:,} embedded files ({dll_count:,} `.dll` assemblies) from `{exe_path.name}`!",
                {"files": extracted, "dlls": dll_count},
            )
        except Exception as exc:
            return AOTAnalysisResult(False, ".NET Single-File Bundle", out_dir, f"Bundle unpack failed: {exc}")


# =============================================================================
# 2. HAXE / HASHLINK (`hlboot.dat` `HLB` MAGIC) DECOMPILER & METADATA PARSER
# =============================================================================


class HashLinkDecompiler:
    """
    Natively parses Haxe / HashLink bytecode binaries (`hlboot.dat` — `HLB` magic),
    used by Dead Cells, Northgard, Wartales, Dune: Spice Wars, and Evoland.
    """

    @staticmethod
    def _read_varuint(data: bytes, pos: int) -> tuple[int, int]:
        """Reads HashLink's big-endian-ish variable-length unsigned integer encoding."""
        if pos >= len(data):
            return 0, pos
        b = data[pos]
        pos += 1
        if (b & 0x80) == 0:
            return b & 0x7F, pos
        if (b & 0x40) == 0:
            if pos >= len(data):
                return 0, pos
            b2 = data[pos]
            pos += 1
            return ((b & 0x3F) << 8) | b2, pos
        # 30-bit / 4-byte encoded int
        if pos + 2 >= len(data):
            return 0, pos
        b2, b3, b4 = data[pos], data[pos + 1], data[pos + 2]
        pos += 3
        return ((b & 0x1F) << 24) | (b2 << 16) | (b3 << 8) | b4, pos

    @classmethod
    def decompile(
        cls,
        hlboot_path: Path,
        out_dir: Path,
        game_name: str,
        log_callback: Callable[[str], None] | None = None,
    ) -> AOTAnalysisResult:
        log = log_callback or (lambda _m: None)
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            data = hlboot_path.read_bytes()
            if len(data) < 16 or data[:3] != b"HLB":
                return AOTAnalysisResult(False, "HashLink", out_dir, "Invalid HLB magic header.")

            version = data[3]
            pos = 4
            flags, pos = cls._read_varuint(data, pos)
            nints, pos = cls._read_varuint(data, pos)
            nfloats, pos = cls._read_varuint(data, pos)
            nstrings, pos = cls._read_varuint(data, pos)
            nbytes_tbl = 0
            if version >= 5:
                nbytes_tbl, pos = cls._read_varuint(data, pos)
            ntypes, pos = cls._read_varuint(data, pos)
            nglobals, pos = cls._read_varuint(data, pos)
            nnatives, pos = cls._read_varuint(data, pos)
            nfunctions, pos = cls._read_varuint(data, pos)
            nconstants = 0
            if version >= 4:
                nconstants, pos = cls._read_varuint(data, pos)
            entrypoint, pos = cls._read_varuint(data, pos)

            log(
                f"[*] HashLink v{version} (`{hlboot_path.name}`): "
                f"{nstrings:,} strings, {ntypes:,} types, {nfunctions:,} functions, {nnatives:,} natives..."
            )

            # Skip ints (4 bytes each) and floats (8 bytes each)
            pos += nints * 4
            pos += nfloats * 8

            # Read HashLink string pool: total_size (4 bytes LE) + raw UTF-8/UTF-16 string data + lengths
            extracted_strings: list[str] = []
            if pos + 4 <= len(data):
                str_data_size = struct.unpack_from("<I", data, pos)[0]
                pos += 4
                if pos + str_data_size <= len(data):
                    str_blob = data[pos : pos + str_data_size]
                    pos += str_data_size
                    # Split null-terminated strings from blob
                    for chunk in str_blob.split(b"\x00"):
                        if chunk:
                            s = chunk.decode("utf-8", errors="ignore").strip()
                            if s:
                                extracted_strings.append(s)

            # Fallback regex extraction for any additional identifiers/paths
            if len(extracted_strings) < 5:
                extracted_strings = [
                    m.decode("utf-8", errors="ignore")
                    for m in re.findall(rb"[A-Za-z_][A-Za-z0-9_\./:]{3,120}", data)
                ]

            unique_strings = list(dict.fromkeys(extracted_strings))
            class_candidates = [
                s for s in unique_strings
                if re.match(r"^[a-z0-9_]+\.[A-Z][A-Za-z0-9_]+$", s) or re.match(r"^[A-Z][A-Za-z0-9_]{3,60}$", s)
            ]

            (out_dir / "hl_strings.json").write_text(
                json.dumps(unique_strings[:20000], indent=2, ensure_ascii=False), encoding="utf-8"
            )
            (out_dir / "hl_types_candidates.json").write_text(
                json.dumps(class_candidates[:5000], indent=2, ensure_ascii=False), encoding="utf-8"
            )

            # Generate browsable Haxe `.hx` stub overview
            hx_lines = [
                f"// Auto-generated Haxe / HashLink Stub Reference for {game_name}",
                f"// Source: {hlboot_path.name} (HashLink Bytecode v{version})",
                f"// Types: {ntypes:,} | Functions: {nfunctions:,} | Natives: {nnatives:,} | Globals: {nglobals:,}",
                "",
                "package recovered;",
                "",
                "class RecoveredHashLinkSymbols {",
                f"    public static inline var HL_VERSION = {version};",
                f"    public static inline var FUNCTION_COUNT = {nfunctions};",
                f"    public static inline var ENTRYPOINT_INDEX = {entrypoint};",
                "    // Key Haxe classes & symbols recovered from string pool:",
            ]
            for c in class_candidates[:300]:
                hx_lines.append(f"    //   class {c}")
            hx_lines.append("}")
            (out_dir / "RecoveredHashLinkSymbols.hx").write_text("\n".join(hx_lines), encoding="utf-8")

            report = (
                f"# Haxe / HashLink Decompilation Report: {game_name}\n"
                f"- **Bytecode File**: `{hlboot_path.name}` (HashLink v{version}, flags=`{flags:#x}`)\n"
                f"- **Types**: {ntypes:,}\n"
                f"- **Functions**: {nfunctions:,}\n"
                f"- **Native C Bindings**: {nnatives:,}\n"
                f"- **Globals**: {nglobals:,}\n"
                f"- **String Pool Entries Recovered**: {len(unique_strings):,}\n"
                f"- **Class/Module Symbols Recovered**: {len(class_candidates):,}\n\n"
                f"## Files Generated\n"
                f"- `hl_strings.json` — Full recovered string pool (dialogue, asset paths, config keys, identifiers)\n"
                f"- `hl_types_candidates.json` — Detected Haxe classes & packages\n"
                f"- `RecoveredHashLinkSymbols.hx` — Haxe stub reference\n"
            )
            (out_dir / "HL_METADATA_REPORT.md").write_text(report, encoding="utf-8")

            return AOTAnalysisResult(
                True,
                f"Haxe / HashLink v{version}",
                out_dir,
                f"Parsed HashLink v{version}: {nfunctions:,} functions, {ntypes:,} types, and {len(unique_strings):,} strings!",
                {"types": ntypes, "functions": nfunctions, "strings": len(unique_strings)},
            )
        except Exception as exc:
            return AOTAnalysisResult(False, "HashLink", out_dir, f"HashLink parse error: {exc}")


# =============================================================================
# 3. GAMEMAKER YYC (YOYO COMPILER — GML-TO-C++ AOT, LIKE IL2CPP) ANALYZER
# =============================================================================


class GameMakerYYCAnalyzer:
    """
    Detects and extracts metadata & C++ RTTI / GML stubs from GameMaker YYC (YoYo Compiler) games,
    where GML scripts are compiled ahead-of-time into native C++ inside the `.exe` (empty/missing `CODE` chunk in `data.win`).
    """

    @staticmethod
    def is_yyc_build(data_win: Path) -> bool:
        """Returns True if `data.win` is a YYC build (valid `FORM` IFF with no `CODE` chunk or empty `CODE` chunk)."""
        try:
            with open(data_win, "rb") as f:
                hdr = f.read(8)
                if len(hdr) < 8 or hdr[:4] != b"FORM":
                    return False
                total_size = struct.unpack("<I", hdr[4:8])[0]
                end_pos = 8 + total_size
                has_gen8 = False
                code_len = 0
                while f.tell() + 8 <= end_pos:
                    c_name, c_len = struct.unpack("<4sI", f.read(8))
                    if c_name == b"GEN8":
                        has_gen8 = True
                    elif c_name == b"CODE":
                        code_len = c_len
                    f.seek(c_len, os.SEEK_CUR)
                return has_gen8 and code_len <= 16
        except OSError:
            return False

    @classmethod
    def analyze_yyc(
        cls,
        data_win: Path,
        exe_path: Path | None,
        out_dir: Path,
        game_name: str,
        extracted_strings: list[str],
        log_callback: Callable[[str], None] | None = None,
    ) -> AOTAnalysisResult:
        log = log_callback or (lambda _m: None)
        out_dir.mkdir(parents=True, exist_ok=True)
        log(f"[*] Detected GameMaker YYC (YoYo Compiler GML->C++ AOT build, like IL2CPP) for {game_name}!")

        gml_scripts = [s for s in extracted_strings if s.startswith(("gml_Script_", "gml_Object_", "gml_GlobalScript_", "scr_"))]
        gml_objects = [s for s in extracted_strings if s.startswith(("obj_", "o_"))]
        gml_rooms = [s for s in extracted_strings if s.startswith(("rm_", "room_"))]

        pe_info = None
        if exe_path and exe_path.is_file():
            pe_info = NativeAOTPEAnalyzer.analyze_binary(exe_path, out_dir / "native_exe_aot", game_name, log_callback=log)

        stub_lines = [
            f"// GameMaker YYC (YoYo Compiler AOT) Recovered GML Script & Object Map for {game_name}",
            "// Note: YYC compiles GML directly into native C++ inside the game executable (similar to Unity IL2CPP).",
            f"// Recovered GML Script Symbols: {len(gml_scripts):,} | Objects: {len(gml_objects):,} | Rooms: {len(gml_rooms):,}",
            "",
        ]
        for s in gml_scripts[:500]:
            stub_lines.append(f"function {re.sub(r'[^A-Za-z0-9_]', '_', s)}() {{ /* Compiled to native C++ via YYC */ }}")
        (out_dir / "YYC_GML_STUBS.gml").write_text("\n".join(stub_lines), encoding="utf-8")

        report = [
            f"# GameMaker YYC (GML->C++ AOT) Report: {game_name}",
            f"- **Container**: `{data_win.name}` (YYC AOT — empty/absent VM `CODE` chunk)",
            f"- **Native Executable Analyzed**: `{exe_path.name if exe_path else 'None'}`",
            f"- **Total STRG Strings**: {len(extracted_strings):,}",
            f"- **Recovered GML Scripts (`gml_Script_*` / `scr_*`)**: {len(gml_scripts):,}",
            f"- **Recovered Objects (`obj_*`)**: {len(gml_objects):,}",
            f"- **Recovered Rooms (`rm_*`)**: {len(gml_rooms):,}",
        ]
        if pe_info and pe_info.success:
            report.append(f"- **Native PE AOT Analysis**: {pe_info.summary}")
        (out_dir / "YYC_AOT_REPORT.md").write_text("\n".join(report), encoding="utf-8")

        return AOTAnalysisResult(
            True,
            "GameMaker YYC (C++ AOT)",
            out_dir,
            f"YYC AOT analyzed: {len(gml_scripts):,} GML script symbols, {len(gml_objects):,} objects, {len(extracted_strings):,} strings!",
            {"scripts": len(gml_scripts), "objects": len(gml_objects), "strings": len(extracted_strings)},
        )


# =============================================================================
# 4. LUAJIT (`\x1bLJ`) & LUA 5.1-5.4 (`\x1bLua`) BYTECODE DECOMPILER
# =============================================================================


class LuaBytecodeDecompiler:
    """
    Natively parses compiled LuaJIT (`\x1bLJ`) and standard Lua 5.1–5.4 (`\x1bLua`) bytecode files
    (used in Hades, Noita, Balatro, Factorio, Don't Starve, Payday 2, etc.) to extract
    header info, function names, string constants, and source paths.
    """

    @classmethod
    def decompile_file(cls, lua_bin: Path, out_file: Path) -> bool:
        try:
            data = lua_bin.read_bytes()
            if len(data) < 8:
                return False

            if data.startswith(b"\x1bLJ"):
                ver = data[3]
                flags = data[4]
                flavor = f"LuaJIT Bytecode (v{ver}, flags={flags:#x})"
            elif data.startswith(b"\x1bLua"):
                ver_byte = data[4]
                major, minor = (ver_byte >> 4) & 0xF, ver_byte & 0xF
                flavor = f"Standard Lua {major}.{minor} Bytecode"
            else:
                return False

            # Extract readable UTF-8 string constants & identifiers from the bytecode constant pool
            raw_strs = re.findall(rb"[\x20-\x7e]{3,200}", data[5:])
            unique_strs = list(dict.fromkeys(s.decode("utf-8", errors="ignore").strip() for s in raw_strs if s.strip()))

            out_file.parent.mkdir(parents=True, exist_ok=True)
            lines = [
                f"-- Recovered Lua Bytecode Summary for `{lua_bin.name}`",
                f"-- Format: {flavor} ({len(data):,} bytes)",
                f"-- Recovered Constant Pool Strings & Symbols: {len(unique_strs):,}",
                "",
                "local RECOVERED_CONSTANTS = {",
            ]
            for s in unique_strs[:2000]:
                lines.append(f"    {json.dumps(s)},")
            lines.append("}")
            out_file.write_text("\n".join(lines), encoding="utf-8")
            return True
        except Exception:
            return False


# =============================================================================
# 5. WEBASSEMBLY (`.wasm` `\x00asm`) BINARY SECTION & SYMBOL PARSER
# =============================================================================


class WasmModuleDecompiler:
    """
    Natively parses WebAssembly (`.wasm` `\x00asm\x01\x00\x00\x00`) binary modules using LEB128
    section decoding to extract Imports, Exports, Custom Name sections, and Data Segment strings.
    """

    SECTION_NAMES = {
        0: "Custom", 1: "Type", 2: "Import", 3: "Function", 4: "Table",
        5: "Memory", 6: "Global", 7: "Export", 8: "Start", 9: "Element",
        10: "Code", 11: "Data", 12: "DataCount",
    }
    EXPORT_KINDS = {0: "func", 1: "table", 2: "memory", 3: "global"}

    @classmethod
    def decompile(cls, wasm_path: Path, out_dir: Path) -> AOTAnalysisResult:
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            data = wasm_path.read_bytes()
            if len(data) < 8 or data[:4] != b"\x00asm":
                return AOTAnalysisResult(False, "WebAssembly", out_dir, "Invalid WASM magic.")

            wasm_ver = struct.unpack_from("<I", data, 4)[0]
            pos = 8
            sections_summary: list[dict] = []
            exports: list[dict] = []
            imports: list[dict] = []
            data_strings: list[str] = []

            while pos < len(data):
                sec_id = data[pos]
                pos += 1
                sec_len, pos = _read_leb128_u(data, pos)
                sec_end = min(pos + sec_len, len(data))
                sec_slice = data[pos:sec_end]
                sections_summary.append({
                    "id": sec_id,
                    "name": cls.SECTION_NAMES.get(sec_id, f"Unknown({sec_id})"),
                    "size": sec_len,
                })

                # Parse Import Section (id=2)
                if sec_id == 2:
                    spos = 0
                    cnt, spos = _read_leb128_u(sec_slice, spos)
                    for _ in range(min(cnt, 10000)):
                        if spos >= len(sec_slice):
                            break
                        mlen, spos = _read_leb128_u(sec_slice, spos)
                        mod = sec_slice[spos : spos + mlen].decode("utf-8", errors="ignore")
                        spos += mlen
                        flen, spos = _read_leb128_u(sec_slice, spos)
                        field = sec_slice[spos : spos + flen].decode("utf-8", errors="ignore")
                        spos += flen
                        if spos >= len(sec_slice):
                            break
                        kind = sec_slice[spos]
                        spos += 1
                        # Advance past import descriptor
                        if kind == 0:
                            _, spos = _read_leb128_u(sec_slice, spos)
                        elif kind == 1:
                            spos += 1
                            lim_f = sec_slice[spos] if spos < len(sec_slice) else 0
                            spos += 1
                            _, spos = _read_leb128_u(sec_slice, spos)
                            if lim_f == 1:
                                _, spos = _read_leb128_u(sec_slice, spos)
                        elif kind == 2:
                            lim_f = sec_slice[spos] if spos < len(sec_slice) else 0
                            spos += 1
                            _, spos = _read_leb128_u(sec_slice, spos)
                            if lim_f == 1:
                                _, spos = _read_leb128_u(sec_slice, spos)
                        elif kind == 3:
                            spos += 2
                        imports.append({"module": mod, "name": field, "kind": cls.EXPORT_KINDS.get(kind, str(kind))})

                # Parse Export Section (id=7)
                elif sec_id == 7:
                    spos = 0
                    cnt, spos = _read_leb128_u(sec_slice, spos)
                    for _ in range(min(cnt, 20000)):
                        if spos >= len(sec_slice):
                            break
                        nlen, spos = _read_leb128_u(sec_slice, spos)
                        ename = sec_slice[spos : spos + nlen].decode("utf-8", errors="ignore")
                        spos += nlen
                        if spos >= len(sec_slice):
                            break
                        kind = sec_slice[spos]
                        spos += 1
                        idx, spos = _read_leb128_u(sec_slice, spos)
                        exports.append({"name": ename, "kind": cls.EXPORT_KINDS.get(kind, str(kind)), "index": idx})

                # Extract readable strings from Data Section (id=11) or Custom `name` Section (id=0)
                elif sec_id in (0, 11):
                    for m in re.findall(rb"[\x20-\x7e]{4,160}", sec_slice):
                        data_strings.append(m.decode("utf-8", errors="ignore"))

                pos = sec_end

            unique_strs = list(dict.fromkeys(data_strings))
            (out_dir / "wasm_exports.json").write_text(json.dumps(exports, indent=2), encoding="utf-8")
            (out_dir / "wasm_imports.json").write_text(json.dumps(imports, indent=2), encoding="utf-8")
            (out_dir / "wasm_strings.json").write_text(json.dumps(unique_strs[:10000], indent=2), encoding="utf-8")

            report = (
                f"# WebAssembly (`.wasm`) Binary Analysis Report: `{wasm_path.name}`\n"
                f"- **WASM Binary Version**: v{wasm_ver}\n"
                f"- **Sections**: {len(sections_summary)} ({', '.join(s['name'] for s in sections_summary)})\n"
                f"- **Exported Functions/Globals**: {len(exports):,}\n"
                f"- **Imported Host APIs**: {len(imports):,}\n"
                f"- **Recovered Data/Name Strings**: {len(unique_strs):,}\n"
            )
            (out_dir / "WASM_REPORT.md").write_text(report, encoding="utf-8")

            return AOTAnalysisResult(
                True,
                f"WebAssembly v{wasm_ver}",
                out_dir,
                f"Parsed `{wasm_path.name}`: {len(exports):,} exports, {len(imports):,} imports, {len(unique_strs):,} data strings!",
                {"exports": len(exports), "imports": len(imports), "strings": len(unique_strs)},
            )
        except Exception as exc:
            return AOTAnalysisResult(False, "WebAssembly", out_dir, f"WASM parse error: {exc}")


# =============================================================================
# 6. UNIVERSAL NATIVE AOT PE ANALYZER (RTTI CLASSES, PE EXPORTS, PE IMPORTS)
# =============================================================================


class NativeAOTPEAnalyzer:
    """
    Universal Windows PE32 / PE32+ Native AOT Introspection Engine.
    Extracts rich structural modding context from AOT-compiled native game executables & DLLs:
      - Haxe HXCPP (Haxe -> C++)
      - .NET NativeAOT / ReadyToRun (C# -> Native)
      - Nuitka / Cython (Python -> C++)
      - GameMaker YYC (GML -> C++)
      - Unity IL2CPP `GameAssembly.dll` (fallback when `global-metadata.dat` is obfuscated)
      - Unreal / Godot GDExtension / Custom C++ Games
    Recovers:
      1. Real PE Export Table functions (`pe_exports.json`)
      2. Real PE Import Table DLLs (`pe_imports.json`) + runtime fingerprinting
      3. MSVC C++ RTTI Class Hierarchy (`.?AVClassName@Namespace@@` -> `Namespace::ClassName`)
      4. GCC / Clang Itanium C++ RTTI (`_ZTI...`)
      5. C/C++ Header Stubs (`native_aot_stubs.h`) + `AOT_ANALYSIS_REPORT.md`
    """

    @staticmethod
    def _rva_to_offset(rva: int, sections: list[tuple[int, int, int, int]]) -> int | None:
        for vaddr, vsize, raw_ptr, raw_sz in sections:
            span = max(vsize, raw_sz)
            if vaddr <= rva < vaddr + span:
                return raw_ptr + (rva - vaddr)
        return None

    @staticmethod
    def _demangle_msvc_rtti(raw: str) -> str:
        """Converts `.?AVPlayerController@Game@@` -> `Game::PlayerController`."""
        # Strip leading `.?AV` / `.?AU` / `.?AW4` and trailing `@@`
        core = re.sub(r"^\.\?A[VUW]4?", "", raw).rstrip("@")
        parts = [p for p in core.split("@") if p]
        parts.reverse()
        return "::".join(parts) if parts else raw

    @classmethod
    def detect_aot_runtime_fingerprint(cls, binary_path: Path) -> str | None:
        """Quickly fingerprints whether a PE binary is NativeAOT, HXCPP, Nuitka, Cython, ReadyToRun, or MSVC C++."""
        if not binary_path.is_file():
            return None
        try:
            with open(binary_path, "rb") as f:
                # Inspect up to first 6 MB + last 2 MB for fast runtime markers
                size = binary_path.stat().st_size
                sample = f.read(min(size, 6 * 1024 * 1024))
                if size > 8 * 1024 * 1024:
                    f.seek(size - 2 * 1024 * 1024)
                    sample += f.read(2 * 1024 * 1024)
        except OSError:
            return None

        if b"hxcpp" in sample.lower() or b"hx::Object" in sample or b".?AVObject@hx@@" in sample:
            return "Haxe HXCPP (C++ AOT)"
        if b"__nuitka_version__" in sample or b"NUITKA_" in sample:
            return "Nuitka (Python->C++ AOT)"
        if b"__pyx_" in sample or b"PyInit_" in sample:
            return "Cython (Python->C AOT)"
        if b"RTR\x00" in sample or b"System.Private.CoreLib" in sample or b"NativeAOT" in sample:
            return ".NET NativeAOT / ReadyToRun (C#->Native AOT)"
        if b"libhl.dll" in sample.lower() or b"hl_module_init" in sample:
            return "Haxe HashLink/C (AOT)"
        if b"YYGML_" in sample or b"gml_Script_" in sample:
            return "GameMaker YYC (GML->C++ AOT)"
        if b"il2cpp_init" in sample or b"il2cpp_domain_get" in sample:
            return "Unity IL2CPP (C#->C++ AOT)"
        return None

    @classmethod
    def analyze_binary(
        cls,
        pe_path: Path,
        out_dir: Path,
        game_name: str,
        log_callback: Callable[[str], None] | None = None,
    ) -> AOTAnalysisResult:
        log = log_callback or (lambda _m: None)
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            file_size = pe_path.stat().st_size
            if file_size < 128:
                return AOTAnalysisResult(False, "Native PE", out_dir, "File too small to be a PE binary.")

            # Cap full-binary scan to 128 MB so even huge binaries stay fast & memory-safe
            read_limit = min(file_size, 128 * 1024 * 1024)
            with open(pe_path, "rb") as f:
                data = f.read(read_limit)

            if data[:2] != b"MZ":
                return AOTAnalysisResult(False, "Native PE", out_dir, "Not a valid Windows PE (MZ) binary.")

            pe_off = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_off + 24 > len(data) or data[pe_off : pe_off + 4] != b"PE\x00\x00":
                return AOTAnalysisResult(False, "Native PE", out_dir, "Invalid PE header offset.")

            machine, num_sections = struct.unpack_from("<HH", data, pe_off + 4)
            opt_hdr_size = struct.unpack_from("<H", data, pe_off + 20)[0]
            arch = "x64" if machine == 0x8664 else ("x86" if machine == 0x014C else f"0x{machine:04x}")

            opt_off = pe_off + 24
            opt_magic = struct.unpack_from("<H", data, opt_off)[0]
            is_pe32_plus = opt_magic == 0x20B
            dd_off = opt_off + (112 if is_pe32_plus else 96)

            # Parse Section Headers
            sec_off = opt_off + opt_hdr_size
            sections: list[tuple[int, int, int, int]] = []
            section_names: list[str] = []
            for i in range(min(num_sections, 96)):
                so = sec_off + i * 40
                if so + 40 > len(data):
                    break
                sname = data[so : so + 8].rstrip(b"\x00").decode("ascii", errors="ignore")
                vsize, vaddr, raw_sz, raw_ptr = struct.unpack_from("<IIII", data, so + 8)
                sections.append((vaddr, vsize, raw_ptr, raw_sz))
                section_names.append(sname)

            # 1. Parse PE Export Table (DataDirectory[0])
            exports: list[str] = []
            if dd_off + 8 <= len(data):
                exp_rva, exp_sz = struct.unpack_from("<II", data, dd_off)
                exp_off = cls._rva_to_offset(exp_rva, sections) if exp_rva else None
                if exp_off is not None and exp_off + 40 <= len(data):
                    num_names = struct.unpack_from("<I", data, exp_off + 24)[0]
                    names_rva = struct.unpack_from("<I", data, exp_off + 32)[0]
                    names_off = cls._rva_to_offset(names_rva, sections)
                    if names_off is not None:
                        for i in range(min(num_names, 25000)):
                            if names_off + i * 4 + 4 > len(data):
                                break
                            str_rva = struct.unpack_from("<I", data, names_off + i * 4)[0]
                            str_off = cls._rva_to_offset(str_rva, sections)
                            if str_off is not None and str_off < len(data):
                                end = data.find(b"\x00", str_off, min(len(data), str_off + 256))
                                if end != -1:
                                    exports.append(data[str_off:end].decode("ascii", errors="ignore"))

            # 2. Parse PE Import Table (DataDirectory[1])
            imports: list[str] = []
            if dd_off + 16 <= len(data):
                imp_rva, _imp_sz = struct.unpack_from("<II", data, dd_off + 8)
                imp_off = cls._rva_to_offset(imp_rva, sections) if imp_rva else None
                if imp_off is not None:
                    pos = imp_off
                    for _ in range(512):
                        if pos + 20 > len(data):
                            break
                        orig_thunk, _ts, _fwd, name_rva, first_thunk = struct.unpack_from("<IIIII", data, pos)
                        pos += 20
                        if orig_thunk == 0 and name_rva == 0 and first_thunk == 0:
                            break
                        n_off = cls._rva_to_offset(name_rva, sections)
                        if n_off is not None and n_off < len(data):
                            end = data.find(b"\x00", n_off, min(len(data), n_off + 256))
                            if end != -1:
                                imports.append(data[n_off:end].decode("ascii", errors="ignore"))

            # 3. Extract MSVC C++ RTTI Class Names (`.?AVClassName@Namespace@@` & `.?AU...`)
            rtti_raw = re.findall(rb"\.\?A[VU][A-Za-z0-9_@]{3,140}@@", data)
            rtti_classes = list(dict.fromkeys(
                cls._demangle_msvc_rtti(m.decode("ascii", errors="ignore")) for m in rtti_raw
            ))
            # Filter out noisy std:: / Microsoft STL internals
            game_classes = [
                c for c in rtti_classes
                if not c.startswith(("std::", "boost::", "Microsoft::", "__crt", "type_info"))
            ]

            runtime_fp = cls.detect_aot_runtime_fingerprint(pe_path) or f"Native C++ / AOT PE ({arch})"
            log(
                f"[*] Native AOT Analysis (`{pe_path.name}`, {runtime_fp}): "
                f"{len(game_classes):,} C++ RTTI classes, {len(exports):,} exports, {len(imports):,} imported DLLs!"
            )

            (out_dir / "rtti_classes.json").write_text(json.dumps(game_classes[:15000], indent=2), encoding="utf-8")
            (out_dir / "pe_exports.json").write_text(json.dumps(exports[:15000], indent=2), encoding="utf-8")
            (out_dir / "pe_imports.json").write_text(json.dumps(list(dict.fromkeys(imports)), indent=2), encoding="utf-8")

            # Generate C/C++ Header Stubs for modding / hooking / AI context
            hdr_lines = [
                f"// Auto-generated Native AOT / C++ RTTI Header Reference for {game_name}",
                f"// Binary: {pe_path.name} ({arch}) | Detected Runtime: {runtime_fp}",
                f"// C++ RTTI Classes: {len(game_classes):,} | Exported Symbols: {len(exports):,}",
                "#pragma once",
                "",
                "// Recovered Native Classes (via RTTI Type Descriptors):",
            ]
            for cname in game_classes[:400]:
                safe_c = re.sub(r"[^A-Za-z0-9_]", "_", cname)
                hdr_lines.append(f"class {safe_c}; // {cname}")
            if exports:
                hdr_lines.append("")
                hdr_lines.append("// Exported DLL/EXE Functions:")
                for exp in exports[:200]:
                    hdr_lines.append(f"// extern \"C\" void {exp}();")
            (out_dir / "native_aot_stubs.h").write_text("\n".join(hdr_lines), encoding="utf-8")

            report = (
                f"# Native AOT / C++ Binary Introspection Report: {game_name}\n"
                f"- **Binary Analyzed**: `{pe_path.name}` ({arch}, {file_size:,} bytes)\n"
                f"- **Detected AOT / Compiler Runtime**: `{runtime_fp}`\n"
                f"- **PE Sections**: `{', '.join(section_names)}`\n"
                f"- **Imported DLLs ({len(imports)})**: `{', '.join(imports[:25])}`\n"
                f"- **Exported Functions**: {len(exports):,}\n"
                f"- **Recovered C++ RTTI Game Classes**: {len(game_classes):,}\n\n"
                f"## Generated Files\n"
                f"- `rtti_classes.json` — Demangled C++ / HXCPP / YYC / NativeAOT class names\n"
                f"- `pe_exports.json` — Exported native symbols\n"
                f"- `pe_imports.json` — Linked runtime & middleware DLLs\n"
                f"- `native_aot_stubs.h` — C++ class & export stub header for modding/AI\n"
            )
            (out_dir / "AOT_ANALYSIS_REPORT.md").write_text(report, encoding="utf-8")

            return AOTAnalysisResult(
                True,
                runtime_fp,
                out_dir,
                f"Analyzed `{pe_path.name}` ({runtime_fp}): {len(game_classes):,} RTTI classes, {len(exports):,} exports, {len(imports):,} imports!",
                {"rtti_classes": len(game_classes), "exports": len(exports), "imports": len(imports)},
            )
        except Exception as exc:
            return AOTAnalysisResult(False, "Native AOT PE", out_dir, f"PE analysis error: {exc}")
