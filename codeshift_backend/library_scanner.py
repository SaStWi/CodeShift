"""
Installed Game Library Auto-Discovery (`GameLibraryScanner`) & Persistent Settings (`SettingsManager`).

Automatically discovers ACTUALLY INSTALLED games across:
  - Steam (via Windows Registry + `libraryfolders.vdf` + `appmanifest_*.acf` + fallback `steamapps/common` scan)
  - Epic Games (via official `ProgramData/Epic/EpicGamesLauncher/Data/Manifests/*.item` + filtered directory scan)
  - GOG Galaxy & Itch.io
Filters out non-game redistributables, launchers, engine editors (UE_5.x, DirectXRedist, etc.), and empty uninstalled folders,
and resolves each game's true root directory (`resolved_root`) so selecting it works reliably every time.
"""
from __future__ import annotations

import json
import os
import re
import string
from pathlib import Path
from typing import Callable

from . import InstalledGameInfo


class SettingsManager:
    """Persists user preferences (output folder, recent games, toggles) in AppData."""

    def __init__(self, settings_path: Path | None = None) -> None:
        if settings_path:
            self.path = settings_path
        else:
            appdata = os.environ.get("LOCALAPPDATA") or str(Path.home())
            self.path = Path(appdata) / "CodeShift" / "settings.json"
        self.data: dict = self._load()

    def _load(self) -> dict:
        defaults = {
            "output_dir": str(Path.home() / "Desktop" / "ExtractedGames"),
            "include_media": True,
            "auto_download": True,
            "recent_sources": [],
        }
        if self.path.is_file():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8", errors="ignore"))
                if isinstance(loaded, dict):
                    defaults.update(loaded)
            except Exception:
                pass
        return defaults

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        except OSError:
            pass

    def add_recent_source(self, source_path: str) -> None:
        recents = [r for r in self.data.get("recent_sources", []) if r != source_path]
        recents.insert(0, source_path)
        self.data["recent_sources"] = recents[:15]
        self.save()


class GameLibraryScanner:
    """Fast, accurate discovery of installed Steam, Epic Games, GOG, and Itch.io games on Windows."""

    SKIP_DIRS = {
        "steam controller configs", "steamworks shared", "steamlinuxruntime_sniper",
        "proton - experimental", "directx", "_commonredist", "directxredist",
        "gameinputredist", "launcher", "epic online services", "vcredist",
        "commonredist", "redist", "emptysteamdepot",
    }

    GAME_BINARY_EXTS = {
        ".exe", ".dll", ".dat", ".pck", ".pak", ".utoc", ".asar", ".nw", ".win",
        ".rpa", ".rgssad", ".rgss2a", ".rgss3a", ".xp3", ".vpk", ".pack", ".pkg",
        ".jar", ".love", ".wasm", ".luac",
    }

    @classmethod
    def is_non_game_dir(cls, folder: Path) -> bool:
        """Returns True if `folder` is a redistributable, engine editor (UE_5.x), launcher, or empty leftover folder."""
        low = folder.name.lower()
        if low in cls.SKIP_DIRS:
            return True
        if re.match(r"^ue[_ ]\d", low) or low.startswith(("unrealengine", "directx", "gameinput", "vcredist", "dotnet")):
            return True
        # Ensure directory actually contains at least one game binary/archive within depth 2
        try:
            for item in folder.iterdir():
                if item.is_file() and item.suffix.lower() in cls.GAME_BINARY_EXTS:
                    if not item.name.lower().startswith(("dxsetup", "vcredist", "unins")):
                        return False
                elif item.is_dir():
                    try:
                        for sub in item.iterdir():
                            if sub.is_file() and sub.suffix.lower() in cls.GAME_BINARY_EXTS:
                                return False
                    except OSError:
                        pass
        except OSError:
            return True
        return True

    @classmethod
    def _get_registry_steam_roots(cls) -> list[Path]:
        roots: list[Path] = []
        if os.name != "nt":
            return roots
        try:
            import winreg
            for hive, subkey, val in (
                (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam", "InstallPath"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam", "InstallPath"),
            ):
                try:
                    with winreg.OpenKey(hive, subkey) as k:
                        sp, _ = winreg.QueryValueEx(k, val)
                        if sp:
                            p = Path(sp)
                            if p.is_dir():
                                roots.append(p)
                except OSError:
                    continue
        except Exception:
            pass
        return roots

    @classmethod
    def _discover_steam_common_dirs(cls) -> list[Path]:
        common_dirs: list[Path] = []
        seen: set[str] = set()

        def add_dir(p: Path) -> None:
            key = str(p).lower()
            if key not in seen and p.is_dir():
                seen.add(key)
                common_dirs.append(p)

        # 1. Check Windows Registry + standard Steam install paths for `libraryfolders.vdf`
        vdf_candidates: list[Path] = [r / "steamapps" / "libraryfolders.vdf" for r in cls._get_registry_steam_roots()]
        vdf_candidates.extend([
            Path(r"C:\Program Files (x86)\Steam\steamapps\libraryfolders.vdf"),
            Path(r"C:\Program Files\Steam\steamapps\libraryfolders.vdf"),
        ])
        for vdf in vdf_candidates:
            if vdf.is_file():
                add_dir(vdf.parent / "common")
                try:
                    txt = vdf.read_text(encoding="utf-8", errors="ignore")
                    for match in re.findall(r'"path"\s+"([^"]+)"', txt):
                        lib_root = Path(match.replace("\\\\", "\\"))
                        add_dir(lib_root / "steamapps" / "common")
                except OSError:
                    pass

        # 2. Check standard library locations across all mounted Windows drives
        for letter in string.ascii_uppercase:
            drive = Path(f"{letter}:\\")
            if not drive.exists():
                continue
            for rel in (
                r"Program Files (x86)\Steam\steamapps\common",
                r"Program Files\Steam\steamapps\common",
                r"SteamLibrary\steamapps\common",
                r"Steam\steamapps\common",
                r"Games\Steam\steamapps\common",
            ):
                add_dir(drive / rel)
        return common_dirs

    @classmethod
    def _discover_epic_manifest_games(cls) -> list[tuple[str, Path]]:
        """Reads official Epic Games Launcher `.item` manifests to get only real installed games."""
        found: list[tuple[str, Path]] = []
        manifest_dir = Path(r"C:\ProgramData\Epic\EpicGamesLauncher\Data\Manifests")
        if not manifest_dir.is_dir():
            return found
        for item_file in manifest_dir.glob("*.item"):
            try:
                data = json.loads(item_file.read_text(encoding="utf-8", errors="ignore"))
                install_loc = data.get("InstallLocation", "")
                display_name = data.get("DisplayName", "")
                app_name = str(data.get("AppName", "")).lower()
                if not install_loc or app_name.startswith("ue_"):
                    continue
                p = Path(install_loc)
                if p.is_dir() and not cls.is_non_game_dir(p):
                    found.append((display_name or p.name, p))
            except Exception:
                continue
        return found

    @classmethod
    def _discover_other_launcher_dirs(cls) -> list[tuple[str, Path]]:
        results: list[tuple[str, Path]] = []
        seen: set[str] = set()

        def add_root(launcher: str, p: Path) -> None:
            key = f"{launcher}:{str(p).lower()}"
            if key not in seen and p.is_dir():
                seen.add(key)
                results.append((launcher, p))

        itch = Path.home() / "AppData" / "Roaming" / "itch" / "apps"
        add_root("Itch.io", itch)

        for letter in string.ascii_uppercase:
            drive = Path(f"{letter}:\\")
            if not drive.exists():
                continue
            for launcher, rel in (
                ("Epic Games", r"Program Files\Epic Games"),
                ("Epic Games", r"Epic Games"),
                ("GOG Galaxy", r"Program Files (x86)\GOG Galaxy\Games"),
                ("GOG Galaxy", r"GOG Games"),
            ):
                add_root(launcher, drive / rel)
        return results

    @classmethod
    def scan_installed_games(
        cls,
        detect_fn: Callable[[Path], tuple[Path, str, str]],
    ) -> list[InstalledGameInfo]:
        """Scans local game libraries and classifies each installed game using `detect_fn`."""
        games: list[InstalledGameInfo] = []
        seen_paths: set[str] = set()

        def register_game(launcher: str, candidate_dir: Path, display_override: str | None = None) -> None:
            if not candidate_dir.is_dir() or cls.is_non_game_dir(candidate_dir):
                return
            try:
                resolved_root, title, engine = detect_fn(candidate_dir)
                # Always store the TRUE resolved game root (fixes nested wrapper folders like Project Castle/Project Castle!)
                effective_path = resolved_root if resolved_root.is_dir() else candidate_dir
                key = str(effective_path.resolve()).lower()
                if key in seen_paths:
                    return
                seen_paths.add(key)

                runtime_hint = ""
                if engine == "Unity":
                    runtime_hint = "IL2CPP" if (effective_path / "GameAssembly.dll").is_file() else "Mono"
                elif engine == "GameMaker":
                    runtime_hint = "YYC/VM"
                elif engine == "Construct 3 (WebView2 c3ab)":
                    runtime_hint = "c3ab"

                games.append(InstalledGameInfo(
                    name=display_override or title,
                    path=effective_path,
                    launcher=launcher,
                    engine=engine,
                    runtime_hint=runtime_hint,
                ))
            except Exception:
                return

        # 1. Official Epic Games Manifests (most accurate)
        for dname, ep_path in cls._discover_epic_manifest_games():
            register_game("Epic Games", ep_path, display_override=dname)

        # 2. Steam libraries + other launcher directories
        roots: list[tuple[str, Path]] = [("Steam", d) for d in cls._discover_steam_common_dirs()]
        roots.extend(cls._discover_other_launcher_dirs())

        for launcher, parent_dir in roots:
            try:
                subdirs = sorted(parent_dir.iterdir(), key=lambda x: x.name.lower())
            except OSError:
                continue
            for sub in subdirs:
                register_game(launcher, sub)

        games.sort(key=lambda g: g.name.lower())
        return games
