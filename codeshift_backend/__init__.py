"""
CodeShift High-Quality Modular Backend (`codeshift_backend`).

Provides:
  - `CancelToken` / `OperationCancelledError`: Cooperative, thread-safe cancellation for 100GB+ streaming operations.
  - `AOTAnalyzers`: Native extractors & decompilers for Ahead-of-Time (AOT) & Script-to-Native-C++ runtimes
    similar to Unity IL2CPP:
      * .NET Single-File Bundled Executables (`SingleFileHost` AppHost bundle extractor)
      * Haxe / HashLink (`hlboot.dat` `HLB` bytecode & metadata parser + HXCPP native analyzer)
      * GameMaker YYC (YoYo Compiler GML-to-C++ AOT extractor & stub generator)
      * LuaJIT (`\x1bLJ`) & Lua 5.1–5.4 (`\x1bLua`) compiled bytecode constant/prototype extractor
      * WebAssembly (`.wasm` `\x00asm`) binary section, export, import & data-string parser
      * Universal Native AOT PE Binary Analyzer (MSVC/Itanium C++ RTTI class hierarchy, PE Export & Import tables
        for HXCPP, .NET NativeAOT/ReadyToRun, Nuitka/Cython, GameMaker YYC, Godot GDExtension, Unreal C++)
  - `GameLibraryScanner`: Automatic discovery of installed Steam (`libraryfolders.vdf`), Epic Games, GOG, and Itch games.
  - `SettingsManager`: Persistent user settings (output path, recent games, options).
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path


class OperationCancelledError(Exception):
    """Raised when a user cancels an active extraction, decompilation, or recompilation task."""


class CancelToken:
    """Thread-safe cooperative cancellation token checked during streaming I/O and loops."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def reset(self) -> None:
        self._event.clear()

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise OperationCancelledError("Operation cancelled by user.")


@dataclass
class InstalledGameInfo:
    name: str
    path: Path
    launcher: str
    engine: str = "Unknown"
    runtime_hint: str = ""
    size_mb: float = 0.0


@dataclass
class AOTAnalysisResult:
    success: bool
    runtime_name: str
    output_dir: Path
    summary: str
    stats: dict[str, int] = field(default_factory=dict)


from .aot_analyzers import (
    DotNetSingleFileUnpacker,
    HashLinkDecompiler,
    GameMakerYYCAnalyzer,
    LuaBytecodeDecompiler,
    WasmModuleDecompiler,
    NativeAOTPEAnalyzer,
)
from .library_scanner import GameLibraryScanner, SettingsManager

__all__ = [
    "OperationCancelledError",
    "CancelToken",
    "InstalledGameInfo",
    "AOTAnalysisResult",
    "DotNetSingleFileUnpacker",
    "HashLinkDecompiler",
    "GameMakerYYCAnalyzer",
    "LuaBytecodeDecompiler",
    "WasmModuleDecompiler",
    "NativeAOTPEAnalyzer",
    "GameLibraryScanner",
    "SettingsManager",
]
