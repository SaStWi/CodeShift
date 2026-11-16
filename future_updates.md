# Future Updates & Project Goals (`future_updates.md`)

This document tracks all goals and the prerequisite building blocks required to achieve them for the **Multi-Engine Game Source Extractor, Recompiler & Mod Injector**.

---

## Core Project Philosophy: Goal-Driven Prerequisite Thinking
We do not organize work by arbitrary "phases." Instead, we work by **Goals** and **Prerequisites**:
1. **Define the Goal**: Identify the concrete outcome we want for the user (e.g., *"Automatically install a working mod injector into the game so custom mods run in-game"*).
2. **Trace the Prerequisites**: Ask *"What must exist first for this goal to actually work?"*
   - *Example*: For a mod injector or modded game package to work with the code and assets you edited in the extracted folder, we **first** need a **Multi-Engine Recompiler** that can recompile modified Event Sheets, Global Variables, scripts, and assets back into the game's runnable format.
3. **Implement Prerequisites First, Then Complete the Goal**: Build and verify the foundational recompiler first, then wire the automatic mod injector searcher/downloader/installer directly into it.

---

## Core Project Constraints (Always Enforced)
1. **Multi-Engine Coverage**: Detect, extract/decompile, recompile, and inject mods across as many game engines as possible.
2. **User-Selected Output Path**: Always allow choosing the exact destination folder on disk.
3. **High Speed & Optimization**: Maintain 16 MB chunked streaming (`STREAM_BUFFER_SIZE`), pre-created directory trees, and multi-threaded operations.
4. **Exact Fallback Message**: Whenever automatic extraction is not possible, always display:
   `I was not able to extract the source code of <file/game name> becouse <reason> but you can try it yourself <how to try it yourself>`
5. **100GB+ File Size Support**: Never load archives into RAM; always use 64-bit file offsets and direct disk streaming.
6. **Lightweight Program Footprint (< 20GB)**: Keep the core application tiny (< 150 KB script) and any downloaded injectors lightweight.
7. **Ease of Use**: Clean, intuitive GUI and CLI workflows optimized for both manual modding and AI-assisted modding.

---

## Completed Goals
- [x] **Goal: Deep Multi-Layer Engine & Binary Signature Detection (`EngineDetector`)**
  - Inspects binary magic headers/footers across 14+ game engines (`c3ab`, `GDPC`, `ECFG`, `.asar`, `RPA-3.0`/`2.0`, `RENPY RPC2`, `UnityFS`, GameMaker `FORM`/`GEN8`, Unreal `.pak` `0x5A6F12E1`, RPG Maker `RGSSAD`, Kirikiri `XP3`, Defold, PyInstaller, Java `.jar`, and `.NET` `BSJB` CLR headers).
  - Resolves parent game root and true game title automatically even when a deeply nested file (like `www/assets.dat`) is selected.
- [x] **Goal: Native Multi-Engine Extraction & Decompilation (`GameExtractor`)**
  - Natively extracts and decompiles Construct 3 (`c3ab` `assets.dat` + Event Sheets + Global Variables), Godot 3/4, Unity/.NET, Unreal Engine 4/5, Ren'Py, GameMaker (`STRG`/`TXTR`), RPG Maker (`MV`/`MZ`/`RGSS` Ruby `.rb`), Kirikiri (`.xp3`), Defold, Python/PyInstaller, Love2D, and Java (`.jar`).
- [x] **Goal: Automatic Mod Injector Installation & Game Recompilation (`GameRecompiler` + `ModInjectorManager`)**
  - **Prerequisite 1 (Implemented)**: `GameRecompiler` — Recompiles modified Construct 3 `decompiled_construct3/event_sheets/*.json` & `global_variables.json` back into `data.json`, merges with original media assets (even if extracted in `--code-only` mode!), and rebuilds `c3ab` (`assets.dat`), Electron (`.asar`), Godot (`.pck`), Ren'Py (`RPA-3.0`), Kirikiri (`.xp3`), ZIP/NW.js/Jar archives, and Unity/.NET C# mod `.dll` plugins (via `dotnet` or built-in Windows `csc.exe`).
  - **Target Goal (Implemented)**: `ModInjectorManager` — Automatically searches, downloads (via official GitHub Releases API when online), and installs the right mod injector into the extracted workspace and game folder:
    - **Construct 3 / WebView2 / NW.js / Electron / RPG Maker MV & MZ**: Installs a native JavaScript Mod Loader (`mods/mod_loader.js` + `mods/custom_mod.js`), hooks `index.html`, enables `F12` DevTools in `package.json`, and recompiles the bundle.
    - **Unity (`Mono` & `IL2CPP`)**: Detects PE architecture (`x64`/`x86`), automatically searches and downloads **BepInEx** from GitHub Releases (`BepInEx/BepInEx`), installs the `winhttp.dll` doorstop injector and `BepInEx/plugins/`, generates a starter C# BepInEx plugin, and compiles it.
    - **Unreal Engine 4 & 5**: Automatically searches and downloads **UE4SS** (`UE4SS-RE/RE-UE4SS`) from GitHub Releases, sets up `Content/Paks/~mods`, and creates a starter Lua mod script.
    - **Godot / Ren'Py**: Installs native `.gd` / `99_mod_loader.rpy` mod bootstrap hooks that load custom mods automatically.
- [x] **Goal: Full Bytecode-to-Source Recompilation for Compiled Scripting Languages (`BytecodeTranspiler`)**
  - **Prerequisite A (Implemented)**: Disassembles Godot `.gdc` (`decompiled_gdscript/*.gd`), GameMaker `STRG`/`CODE` (`gamemaker_strings.json` & `decompiled_gml/*.gml`), Ren'Py `RENPY RPC2` `.rpyc` (`decompiled_rpyc/*.editable.rpy` & `*.strings.json`), and RPG Maker `Scripts.rvdata2` (`decompiled_ruby_scripts/*.rb`).
  - **Prerequisite B (Implemented)**: Recompiles edited GDScript, GameMaker strings/scripts, Ren'Py `.rpyc` Slot 1 AST streams, and RPG Maker Ruby Marshal `Scripts.rvdata2` back into runnable binary containers with zero external dependencies.
- [x] **Goal: One-Click "Deploy & Launch Modded Game" with Automatic Safe Backup/Restore (`SafeDeployManager`)**
  - **Prerequisite A (Implemented)**: Automatic backup ledger (`backups/backup_manifest.json`) that snapshots original game archives (`.bak`) before deploying any recompiled archive or injector.
  - **Prerequisite B (Implemented)**: Binary header & entry table integrity verification (`verify_archive_integrity`) before overwriting game files.
  - **Target Goal (Implemented)**: One-click **"3. Deploy Modded Game"** and **"Restore Original"** buttons in the GUI (plus `--deploy` and `--restore` in the CLI).

---

## Next Goals & Their Prerequisites

### Goal 1 (Implemented & Active): Flawless Unity Decompilation via `dnSpyEx` (`dnSpy.Console.exe` & `dnSpy.exe`) & Engine-Specific CLI Decompilers (`DecompilerToolchainManager`)
> **Strict Rule**: Only use **engine-specific code/script decompilers** — NEVER use generic asset rippers like AssetRipper!

- **What Is Needed for This Goal (Prerequisites — All Implemented in `DecompilerToolchainManager`)**:
  - **Prerequisite A (Portable Engine-Specific Toolchain Discovery & Auto-Downloader in `tools/`)**:
    1. **Unity & .NET / MonoGame / XNA (Managed C# `.dll`)**: **`dnSpyEx`** (`dnSpy.Console.exe` for headless CLI C# solution `.sln`/`.csproj`/`.cs` decompilation & `dnSpy.exe` for interactive debugging/editing — `https://github.com/dnSpyEx/dnSpy/releases/latest`).
    2. **Unity (`IL2CPP` Native `GameAssembly.dll` Builds)**: **`Cpp2IL`** (`Cpp2IL.exe` — `https://github.com/SamboyCoding/Cpp2IL/releases/latest`) to restore Managed `.dll` assemblies from `GameAssembly.dll` + `<Game>_Data/il2cpp_data/Metadata/global-metadata.dat` and pipe them directly into **`dnSpy.Console.exe`**.
    3. **Godot Engine 3 & 4**: **`GDRE Tools`** (`gdre_tools.exe` — `https://github.com/bruvzg/gdsdecomp/releases/latest`) for headless `.pck` and `.gdc` bytecode-to-`.gd` source recovery.
    4. **GameMaker Studio 1 & 2 / LTS**: **`UndertaleModCli`** (`UndertaleModCli.exe` — `https://github.com/UnderminersTeam/UndertaleModTool/releases/latest`) for headless GML VM `CODE` bytecode decompilation into `.gml` scripts.
    5. **Unreal Engine 4 & 5**: **`repak`** (`repak.exe` — `https://github.com/trumank/repak/releases/latest`) for `.pak` unpacking & **`UE4SS`** (`https://github.com/UE4SS-RE/RE-UE4SS/releases/latest`) for Lua/Blueprint script generation.
    6. **Ren'Py Visual Novel Engine**: **`unrpyc`** (`unrpyc.py` — `https://github.com/CensoredUsername/unrpyc/releases/latest`) for `.rpyc` AST-to-`.rpy` source decompilation.
    7. **Java / LibGDX / LWJGL**: **`CFR`** (`cfr.jar` — `https://github.com/leibnitz27/cfr/releases/latest`) for `.jar`/`.class` JVM bytecode-to-`.java` source decompilation.
  - **Prerequisite B (Automatic Specific-Program Detection vs. Default Extractor Routing)**:
    - Automatically detects (`DecompilerToolchainManager.get_installed_program_for_engine`) whether the game's engine corresponds to one of the specific programs installed locally (`dnSpy.Console.exe`/`ilspycmd`/`Cpp2IL` for Unity/.NET, `gdre_tools` for Godot, `UndertaleModCli` for GameMaker, `repak` for Unreal Engine, `unrpyc` for Ren'Py, `cfr` for Java).
    - If the specific program is installed for that engine, automatically runs the specific program (passing `-r "<Game>_Data/Managed"` and `--sln-name "<Game>.sln"` to `dnSpy.Console.exe` for Unity); if the engine is not for a specific program or the specific program is not installed, automatically runs the default built-in extractor.
- **Goal Outcome (Implemented)**: Automatic detection and routing between installed engine-specific decompilers (`dnSpyEx`, `Cpp2IL`, `GDRE Tools`, `UndertaleModCli`, `repak`, `unrpyc`, `CFR`) and the default built-in multi-engine extractor.

### Goal 2: Official CodeShift Community Discord Server (with Dedicated Discord Bots) & Public GitHub Repository (`https://github.com/SaStWi/CodeShift`)
- **Prerequisite A (Public GitHub Repository & Release Packaging — `https://github.com/SaStWi/CodeShift`)**: Prepare a clean, production-ready repository layout (`README.md`, documentation, `.gitignore`, release scripts, and downloadable release packages) and publish **CodeShift** to `https://github.com/SaStWi/CodeShift` so anyone can download, run, and contribute to the project.
- **Prerequisite B (Well-Executed Discord Server Architecture)**: Set up and structure the official **CodeShift** Discord server with clear onboarding, role hierarchies, announcement & GitHub release channels, engine-specific modding support forums (Construct 3, Unity, Unreal, Godot, Ren'Py, RPG Maker, GameMaker, etc.), and a community mod showcase.
- **Prerequisite C (Dedicated CodeShift Discord Bots)**: Build and deploy custom Discord bots for the **CodeShift** server:
  1. **CodeShift Modding & Engine Bot**: Slash-command bot (`/detect-engine`, `/mod-guide`, `/troubleshoot`) that helps users identify game archive formats, explains how to extract/recompile specific engines, and troubleshoots common modding errors.
  2. **CodeShift GitHub Release & Repo Sync Bot**: Connects to `https://github.com/SaStWi/CodeShift` to post instant release announcements, changelogs, download links, and issue/PR updates directly into the Discord server.
  3. **Community Mod Showcase & Verification Bot**: Allows members to submit, tag, search, and rate community mods built with **CodeShift**.
- **Goal Outcome**: A polished, automated **CodeShift** Discord community powered by dedicated bots and paired with the official GitHub repository (`https://github.com/SaStWi/CodeShift`) where everyone can download the project and collaborate on mods.

### Goal 3: Multi-Mod Profile Manager & Conflict Resolver
- **Prerequisite A**: Store individual mods as isolated patch layers (`mods/profiles/<mod_name>/`) rather than mutating a single shared workspace.
- **Prerequisite B**: Build a JSON/Event-Sheet merge resolver that detects if two enabled mods modify the same global variable or event sheet.
- **Goal Outcome**: Enable, disable, reorder, and combine multiple independent mods with 1 click.

### Goal 4: Live In-Game Hot-Reload & Memory/Variable Inspector Bridge
- **Prerequisite A**: Add a local WebSocket/HTTP loopback bridge inside the injected `mod_loader.js` / `mod_loader.gd` / Lua mod hook.
- **Goal Outcome**: Edit global variables or stats in the desktop GUI while the game is running and see changes take effect immediately without restarting the game.

### Goal 5: Built-In AI Modding Prompt & Patch Generator (Future)
- **Prerequisite A**: Index the extracted game's schemas (such as Construct 3 Global Variables, JSON database structures, or C# class methods) into a compact JSON schema summary once AI patch integration is ready to be enabled.
- **Goal Outcome**: Let the user type what mod they want in plain English (or generate an AI prompt bundle) so AI can automatically edit the extracted files, trigger `GameRecompiler`, and inject the mod.






