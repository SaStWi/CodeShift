# Project Memory (`memory.md`)

## Project Overview
- **Goal**: Build an optimized, easy-to-use multi-engine game source code and script extractor ([`game_extractor.py`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/game_extractor.py)) to make modding games (manually or with AI) effortless.
- **Workspace**: `y:\Digibende\Utrecht\Kandidaten\Samuel Steven Willemsen\Test`
- **Roadmap Document**: [`future_updates.md`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/future_updates.md)
- **Key Requirements**:
  1. Support multiple game engines (Construct 3, Unity, Unreal Engine 4/5, Godot 3/4, Ren'Py, RPG Maker MV/MZ/XP/VX/VX Ace, GameMaker, Kirikiri, Defold, Python/PyInstaller, Java/LibGDX/LWJGL, Love2D, .NET/MonoGame/XNA).
  2. Allow choosing the output extraction directory on the computer.
  3. High speed and optimization (multi-threaded copying + 16 MB chunked streaming + pre-created directory trees + optional Code/Data-only fast extraction toggle).
  4. Exact fallback message when extraction fails:
     `I was not able to extract the source code of <file/game name> becouse <reason> but you can try it yourself <how to try it yourself>`
  5. Support 100GB+ game files/folders via direct local disk streaming (no RAM or upload size limits).
  6. Keep total program size well under 20GB (< 100KB script / zero external package dependencies required).
  7. Easy-to-use graphical interface (dark-mode Tkinter desktop GUI + `--cli` mode + `run_extractor.bat` launcher).

---

## Agent Action Log

### Step 1 — Initial Workspace Inspection (`2026-11-10 10:09`)
- **Agent**: Main Agent (Antigravity)
- **Action**: Attempted to list workspace files via `run_command` (`Get-ChildItem -Force`) and clarify requirements via `ask_question`.
- **Outcome**: Blocked by Antigravity pre-tool hook `jsonhook__googlecloudtools.datacloud_telemetry_PreToolUse_0_0` because `node` was not installed on the system `PATH`.
- **Resolution**: Reported the plugin hook issue to User and provided the initial multi-engine extractor design and source code.

### Step 2 — Full Multi-Engine Extractor & AI Modding Guide Design (`2026-11-10 10:15`)
- **Agent**: Main Agent (Antigravity)
- **Action**: Attempted to write `game_extractor.py` to `y:\Digibende\Utrecht\Kandidaten\Samuel Steven Willemsen\Test\game_extractor.py` using `write_file`.
- **Outcome**: Blocked because the IDE extension hook required disabling/reloading in the Extensions panel (`Ctrl+Shift+X`).

### Step 3 — Window Reload & IDE Extension Hook Diagnosis (`2026-11-10 10:18`)
- **Agent**: Main Agent (Antigravity)
- **User Action**: Created `y:\Digibende\Utrecht\Kandidaten\Samuel Steven Willemsen\Test\memory.md` and reloaded the Antigravity window.
- **Agent Action**: Attempted `read_file` on `memory.md` and identified that the `googlecloudtools.datacloud` VS Code extension in `Ctrl+Shift+X` registered the global `PreToolUse` hook.
- **Resolution**: User disabled the extension / resolved the hook and reloaded the window.

### Step 4 — Implementation, Launcher Creation & Automated Verification (`2026-11-10 10:24 - 10:27`)
- **Agent**: Main Agent (Antigravity)
- **Actions Taken**:
  1. Verified workspace access by reading `memory.md` and checking the `managing-python-dependencies` skill.
  2. Created [`game_extractor.py`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/game_extractor.py), [`run_extractor.bat`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/run_extractor.py), and [`test_extractor.py`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/test_extractor.py).
  3. Executed `python test_extractor.py` via `run_command` — all **8/8 initial tests passed**.

### Step 5 — Deep Binary Signature Analysis, Construct 3 WebView2 (`c3ab` / `assets.dat`) Support & Project Decompiler (`2026-11-13 11:40 - 11:54`)
- **Agent**: Main Agent (Antigravity)
- **User Feedback**: Tested the program on **Devices Tycoon** (Steam) by selecting `www\assets.dat` (`C:\Program Files (x86)\Steam\steamapps\common\Devices Tycoon\www\assets.dat`), which failed to detect/extract.
- **Actions Taken**:
  1. Reverse-engineered the Construct 3 WebView2 `c3ab` (`fdir` + `blob`) container format used by `Devices Tycoon\www\assets.dat`.
  2. Added binary signature detection (`EngineDetector.detect_file_signature`), ancestor game-root traversal (`resolve_game_context`), native `c3ab` streaming extraction, Construct 3 `data.json` decompilation (`CONSTRUCT3_PROJECT_MAP.md`, `global_variables.json`, `event_sheets/*.json`, `layouts_index.json`, `readable_scripts/*.js`), and `repack_c3ab.py`.
  3. Verified on `Devices Tycoon\www\assets.dat` and passed **9/9 unit tests**.

### Step 6 — v2.0 Expansion: Native Support for 6 New Engines, Upgraded Existing Engines & `future_updates.md` (`2026-11-13 12:05 - 12:14`)
- **Agent**: Main Agent (Antigravity)
- **User Request**: Confirmed `Devices Tycoon` works perfectly; requested adding native support for more game engines, upgrading support for existing engines, and creating a `future_updates.md` roadmap file.
- **Upgrades Implemented in [`game_extractor.py`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/game_extractor.py) (v2.0)**:
  1. **Upgraded Existing Engines**:
     - **GameMaker Studio 1 & 2 (`_extract_gamemaker_iff_native`)**: Natively parses the `STRG` string table chunk inside `data.win` (`FORM`/`GEN8`) to extract all strings, script/object names, and dialogues into `gamemaker_strings.json`, plus extracts embedded PNG sprite sheets from the `TXTR` chunk into `textures/`.
     - **Unity & .NET (`_extract_dotnet_clr_streams` & `_inspect_unity_metadata`)**: Natively parses the ECMA-335 `BSJB` metadata header and `#Strings` / `#US` (UTF-16LE user strings) streams inside `Assembly-CSharp.dll` into `decompiled_dotnet_metadata/`, extracts `StreamingAssets/`, and inspects `globalgamemanagers` / `data.unity3d` for the exact Unity version.
     - **Unreal Engine 4 & 5 (`_unpack_unreal_pak_native`)**: Added a native pure-Python `FPakInfo` footer inspector (`0x5A6F12E1`) and unencrypted v3–v8 `.pak` unpacker (in addition to `repak` CLI integration and loose `.uproject`/`.ini`/`.lua`/`.usf` extraction).
     - **Godot 3 & 4 (`_postprocess_godot_extracted`)**: Added recovery of settings from compiled `project.binary` (`ECFG` magic) and symbol extraction from compiled `.gdc` bytecode files.
     - **Ren'Py (`_decompile_rpyc_strings`)**: Added a native `RENPY RPC2` `.rpyc` slot reader that decompresses AST Slot 1 and recovers readable dialogue and script lines even when `.rpy` files are absent.
  2. **Added Native Support for 6 New Game Engines**:
     - **RPG Maker XP / VX / VX Ace (`_extract_rpgmaker_rgss`)**: Native pure-Python `RGSSAD` v1/v2 (`.rgssad`, `.rgss2a`) and v3 (`.rgss3a`) archive decrypter/unpacker + native Ruby Marshal `Scripts.rvdata2` / `Scripts.rxdata` zlib stream decompiler that outputs clean `.rb` Ruby source scripts into `decompiled_ruby_scripts/`!
     - **Kirikiri 2 / Kirikiri Z (`_extract_kirikiri_xp3`)**: Native pure-Python `.xp3` visual novel archive unpacker (`File` -> `info` + `segm` zlib segment stream extractor for `.ks` KAG scripts and `.tjs` source files).
     - **Defold Engine (`_extract_defold`)**: Extracts `.projectc`, `.arci`, `.arcd`, `.dmanifest`, and Lua strings/scripts.
     - **Python / PyInstaller (`_extract_pyinstaller`)**: Detects `_internal/base_library.zip` and `MEI` CArchive signatures, extracting Python modules and `.pyc` bytecode.
     - **Java / LibGDX / LWJGL (`_extract_java_jar`)**: Detects and unpacks `.jar` and fat-JAR `.exe` game packages.
     - **.NET / MonoGame / FNA / XNA**: Detects `FNA.dll` / `MonoGame.Framework.dll` / `Microsoft.Xna.Framework.dll` and extracts CLR metadata/source.
  3. **Created [`future_updates.md`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/future_updates.md)**: Documented all completed v2.0 milestones and the structured roadmap for v2.1 (GUI Mod Repacker & Event Sheet Re-Compiler), v2.5 (Full AST/Bytecode Decompilers & Unity LZ4 unpacker), and v3.0 (AI Prompt Builder & Optional Portable Tool Manager).
  4. **Expanded [`test_extractor.py`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/test_extractor.py)**: Added unit tests for GameMaker `FORM`/`STRG` native extraction, RPG Maker `Scripts.rvdata2` Ruby `.rb` decompilation, Kirikiri `.xp3` native extraction, and Java/LibGDX `.jar` extraction — all **13/13 unit tests passed** in `0.435s`.

### Step 7 — Project Inspection by New Agent (`2026-11-13 13:13`)
- **Agent**: New Agent (Antigravity)
- **Action**: Inspected the entire workspace (`memory.md`, `future_updates.md`, `game_extractor.py`, `test_extractor.py`, and `run_extractor.bat`) without modifying any code or other project files.
- **Inspection Findings**:
  1. [`game_extractor.py`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/game_extractor.py) (2,073 lines, last modified `12:11`) and [`test_extractor.py`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/test_extractor.py) (326 lines, 13 unit tests, last modified `12:12`) are currently at **v2.0** (`EngineDetector`, `GameExtractor`, and `ExtractorApp` with 14+ game engines supported).
  2. [`future_updates.md`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/future_updates.md) (last modified `12:23`) was updated by the previous agent to use a **Goal-Driven Prerequisite Thinking** structure and lists `GameRecompiler` + `ModInjectorManager` under "Completed Goals", along with 3 Next Goals (Bytecode-to-Source Recompilation, One-Click Deploy & Launch with Safe Backup/Restore, and Built-In AI Modding Prompt & Patch Generator).
  3. **Where the Previous Agent Left Off**: The previous agent updated [`future_updates.md`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/future_updates.md) at `12:23` to describe `GameRecompiler` and `ModInjectorManager`, but stopped before implementing those two classes in [`game_extractor.py`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/game_extractor.py) or adding their unit tests to [`test_extractor.py`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/test_extractor.py).

### Step 8 — Full Implementation of `GameRecompiler`, `ModInjectorManager`, `BytecodeTranspiler`, `SafeDeployManager` & `AIModdingAssistant` (`2026-11-13 13:15 - 13:31`)
- **Agent**: New Agent (Antigravity)
- **Changes Made in [`game_extractor.py`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/game_extractor.py) (v2.1)**:
  1. **Added Extraction Metadata Persistence (`_write_extraction_manifest`)**:
     - Writes `extraction_manifest.json` inside every `<Game>_extracted` folder recording `game_name`, `engine`, `source_path`, `game_root`, `extracted_dir`, `include_media`, and `primary_archive`.
  2. **Implemented `BytecodeTranspiler` (Goal 1 — Bytecode-to-Source Disassembly & Re-Assembly)**:
     - **Godot (`.gdc` / `ECFG`)**: Disassembles compiled `.gdc` token tables into editable `decompiled_gdscript/*.gd` scripts and compiles edits back into `.gd`/`.gdc` before packing `.pck`.
     - **Ren'Py (`RENPY RPC2` `.rpyc`)**: Extracts AST Slot 1 strings into `decompiled_rpyc/*.strings.json` and `*.editable.rpy`, and re-assembles modified dialogue/strings directly back into the zlib-compressed `RENPY RPC2` binary Slot 1 stream.
     - **GameMaker (`FORM` IFF `data.win`)**: Generates `decompiled_gml/gml_scripts_overview.gml` alongside `gamemaker_strings.json` and rebuilds valid binary `FORM`/`STRG` IFF `data.win` containers with recalculated pointer offsets and chunk lengths.
     - **RPG Maker RGSS (`Scripts.rvdata2`)**: Extracts zlib-compressed Ruby scripts with `scripts_manifest.json` and re-serializes modified `.rb` scripts into a valid Ruby Marshal `Scripts.rvdata2` binary.
  3. **Implemented `GameRecompiler` (Prerequisite 1 — Multi-Engine Recompiler & Archive Builder)**:
     - Syncs modified Construct 3 `decompiled_construct3/event_sheets/*.json`, `global_variables.json`, and `layouts_index.json` back into `data.json` (and upgraded standalone `repack_c3ab.py` with the same sync logic).
     - Rebuilds Construct 3 WebView2 `c3ab` (`assets_modded.dat`) via 16 MB chunked streaming, including **automatic `--code-only` media merging** directly from the original `assets.dat` on disk without loading media into RAM.
     - Rebuilds Electron `.asar`, Godot `GDPC` `.pck`, Ren'Py `RPA-3.0` `.rpa`, Kirikiri `.xp3`, GameMaker `data.win`, RPG Maker `Scripts.rvdata2`, ZIP/NW.js/Love2D/Jar containers, and compiles Unity/.NET C# mod `.cs` files into `.dll` plugins via Windows `csc.exe`.
  4. **Implemented `ModInjectorManager` (Target Goal — Automatic Mod Injector Searcher, Downloader & Installer)**:
     - **Construct 3 / WebView2 / NW.js / Electron / RPG Maker MV & MZ**: Installs `mods/mod_loader.js` and `mods/custom_mod.js`, hooks `index.html` and main JS entry scripts, enables `F12` DevTools in `package.json`, and recompiles the archive.
     - **Unity (`Mono` & `IL2CPP`)**: Detects PE architecture (`x64`/`x86`), queries GitHub Releases for `BepInEx` when online, configures `doorstop_config.ini` and `BepInEx/plugins/`, generates `mods/CustomUnityMod.cs`, and compiles `CustomUnityMod.dll`.
     - **Unreal Engine 4 & 5**: Queries GitHub Releases for `UE4SS` when online, sets up `Content/Paks/~mods`, and installs a starter Lua mod in `Binaries/Win64/Mods/CustomMod/Scripts/main.lua`.
     - **Godot / Ren'Py / RPG Maker RGSS / Kirikiri / GameMaker**: Installs engine-native mod bootstrap scripts and recompiles.
  5. **Implemented `SafeDeployManager` (Goal 2 — One-Click Deploy & Safe Backup/Restore)**:
     - Verifies binary header & entry structure of recompiled archives (`verify_archive_integrity`), creates non-destructive `.bak` snapshots tracked in `backups/backup_manifest.json`, deploys modded archives into `game_root`, and supports 1-click restoration (`restore_original_game`).
  6. **Implemented `AIModdingAssistant` (Goal 3 — Schema Indexer & Plain-English Mod Patcher)**:
     - Automatically builds `ai_schema_index.json` on extraction, generates `AI_PROMPT_BUNDLE.md`, and applies natural-language mod commands (e.g. `Set StartingBudget to 999999`) across Construct 3 Global Variables, JSON databases, GDScript, and Ruby scripts.
  7. **Upgraded GUI (`ExtractorApp`) & CLI (`main`)**:
     - Added GUI buttons (`2. Install Mod Injector & Recompile`, `3. Deploy Modded Game`, `Restore Original`, and `Apply AI Mod & Recompile`) and CLI flags (`--recompile`, `--inject-mod`, `--deploy`, `--restore`, `--ai-mod`).
- **Changes Made in [`test_extractor.py`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/test_extractor.py) & [`future_updates.md`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/future_updates.md)**:
  - Added 5 comprehensive end-to-end unit tests covering `GameRecompiler` (including `--code-only` media merging), `ModInjectorManager`, `BytecodeTranspiler` round-trips, `SafeDeployManager` deploy & restore, and `AIModdingAssistant`.
  - Executed `python test_extractor.py` — all **18/18 unit tests passed** in `0.708s`.
  - Updated [`future_updates.md`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/future_updates.md) to mark the completed goals and define the next goals.

### Step 9 — Removed AI Mod Patch & Added Goal 2 (CodeShift Discord Server, Bots & GitHub Repository) (`2026-11-13 13:37 - 13:41`)
- **Agent**: New Agent (Antigravity)
- **User Request**: Remove the AI mod patch feature for now while keeping all recompilers and mod injectors; add a new **Goal 2** in [`future_updates.md`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/future_updates.md) featuring a well-executed Discord server with dedicated Discord bots and the official GitHub repository (`https://github.com/SaStWi/CodeShift`) where everyone can download the project.
- **Changes Made**:
  1. **[`game_extractor.py`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/game_extractor.py)**:
     - Removed `AIModdingAssistant`, automatic `ai_schema_index.json` generation in `GameExtractor.extract()`, the `AI Mod Patch` GUI bar in `ExtractorApp`, and the `--ai-mod` CLI argument in `main()`.
     - Kept `BytecodeTranspiler`, `GameRecompiler`, `ModInjectorManager`, and `SafeDeployManager` intact.
  2. **[`test_extractor.py`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/test_extractor.py)**:
     - Removed `AIModdingAssistant` import and `test_ai_modding_assistant_schema_and_natural_language_patch`.
     - Ran `python test_extractor.py` — all **17/17 unit tests passed** in `0.552s`.
  3. **[`future_updates.md`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/future_updates.md)**:
     - Moved the AI Modding Prompt & Patch Generator back to Future Goals (Goal 4).
     - Added **Goal 2: Official CodeShift Community Discord Server (with Dedicated Discord Bots) & Public GitHub Repository (`https://github.com/SaStWi/CodeShift`)** with its Prerequisites (Repository & Release Packaging at `https://github.com/SaStWi/CodeShift`, Discord Server Architecture, and Dedicated CodeShift Discord Bots).

### Step 10 — Implemented Goal 1: `dnSpyEx` (`dnSpy.Console.exe` / `dnSpy.exe`) for Flawless Unity Decompilation & Engine-Specific Decompiler Toolchain (`DecompilerToolchainManager`) (`2026-11-13 13:47 - 13:54`)
- **Agent**: New Agent (Antigravity)
- **User Request**: Add Goal 1 featuring the implementation of `dnSpy` (`dnSpyEx`) for flawless Unity engine decompilation along with other engine-specific decompiler programs (strictly forbidding generic asset rippers like AssetRipper), document everything needed for it in [`future_updates.md`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/future_updates.md), and implement it immediately.
- **Changes Made**:
  1. **[`future_updates.md`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/future_updates.md)**:
     - Documented **Goal 1: Flawless Unity Decompilation via `dnSpyEx` (`dnSpy.Console.exe` & `dnSpy.exe`) & Engine-Specific CLI Decompilers (`DecompilerToolchainManager`)** with all required prerequisites and engine-specific tools (`dnSpyEx` for Unity/.NET, `Cpp2IL` for Unity IL2CPP, `GDRE Tools` for Godot, `UndertaleModCli` for GameMaker, `repak` & `UE4SS` for Unreal, `unrpyc` for Ren'Py, and `CFR` for Java/LibGDX), while keeping **Goal 2** as the Official CodeShift Community Discord Server & GitHub Repository (`https://github.com/SaStWi/CodeShift`).
  2. **[`game_extractor.py`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/game_extractor.py)**:
     - Removed all references to `AssetRipper` from fallback messages.
     - Implemented **`DecompilerToolchainManager`**:
       - Manages portable engine-specific decompilers in `tools/` (`dnspy`, `cpp2il`, `gdre_tools`, `undertalemodcli`, `repak`, `unrpyc`, `cfr`) with automatic GitHub Releases download support (`ensure_tool`).
       - Implemented `decompile_unity_with_dnspy`: passes `-r "<Game>_Data/Managed"` and `--sln-name "<Game>.sln"` to `dnSpy.Console.exe`, chains `Cpp2IL.exe` -> `dnSpy.Console.exe` for Unity IL2CPP builds when `global-metadata.dat` is present, generates a 1-click `open_in_dnspy.bat` launcher script, and includes a native ECMA-335 C# `.csproj` + `.cs` class/method/field decompiler (`_decompile_dotnet_ecma335_native`) so Unity Managed C# extraction succeeds even offline.
       - Wired `DecompilerToolchainManager` into `_extract_unity_or_dotnet`, `_extract_godot` (`gdre_tools`), `_extract_unreal` (`repak`), `_extract_gamemaker` (`undertalemodcli`), and `_extract_java_jar` (`cfr`).
       - Added the **"Setup dnSpy & Tools"** button to `ExtractorApp` and `--setup-tools` to `main()`.
  3. **[`test_extractor.py`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/test_extractor.py)**:
     - Added `test_unity_dnspy_and_engine_specific_toolchain` verifying the engine-specific tool registry (confirming zero `AssetRipper` references) and testing Unity C# `.csproj` + `.cs` + `open_in_dnspy.bat` decompilation.
     - Executed `python test_extractor.py` — all **18/18 unit tests passed** in `0.686s`.




### Step 11 — Restored Default Extractor Behavior with Automatic Engine-Specific Program Routing & Published CodeShift Release to GitHub (`https://github.com/SaStWi/CodeShift`) (`2026-11-13 14:01 - 14:06`)
- **Agent**: New Agent (Antigravity)
- **User Request**: Restore the previous default extractor behavior and GUI while keeping the engine-specific programs (`DecompilerToolchainManager`), automatically routing to the specific program when the detected game engine matches an installed specific program and falling back to the default extractor otherwise; then upload all project files to `https://github.com/SaStWi/CodeShift` without touching `README.md` and create a GitHub Release of the program.
- **Changes Made**:
  1. **[`game_extractor.py`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/game_extractor.py)**:
     - Restored the clean GUI (`ExtractorApp`) and CLI (`main()`) from before Step 10 by removing the manual `Setup dnSpy & Tools` button and `--setup-tools` flag, and removed `_decompile_dotnet_ecma335_native` so Unity Managed `.dll` extraction uses the default extractor (`Managed_Assemblies/`, `decompiled_dotnet_metadata/`, `open_in_dnspy.bat`, and the standard fallback message) whenever `dnSpy.Console.exe` / `ilspycmd` is not installed.
     - Added `DecompilerToolchainManager.ENGINE_TO_SPECIFIC_TOOL` and `DecompilerToolchainManager.get_installed_program_for_engine(engine)` to automatically detect during `GameExtractor.extract()` whether the game engine has a dedicated external program installed locally (`dnSpyEx`/`ilspycmd`/`Cpp2IL` for Unity/.NET, `GDRE Tools` for Godot, `UndertaleModCli` for GameMaker, `repak` for Unreal Engine, `unrpyc` for Ren'Py, `CFR` for Java):
       - If the specific program is installed for that engine, `GameExtractor` automatically uses that specific program.
       - If the engine is not for a specific program or that specific program is not installed, `GameExtractor` automatically uses the default built-in extractor.
  2. **[`test_extractor.py`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/test_extractor.py)**:
     - Updated `test_unity_dnspy_and_engine_specific_toolchain` to test both automatic routing to the default extractor when no specific program is installed and automatic routing to `dnSpy.Console` when installed in `tools/dnSpy/`.
     - Executed `python test_extractor.py` — all **18/18 unit tests passed** in `0.809s`.
  3. **[`future_updates.md`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/future_updates.md)**:
     - Updated Goal 1 to reflect automatic detection and routing between installed engine-specific programs and the default built-in extractor.
  4. **GitHub Repository (`https://github.com/SaStWi/CodeShift`) & Release**:
     - Added all project files (`game_extractor.py`, `run_extractor.bat`, `test_extractor.py`, `future_updates.md`, `memory.md`) to `https://github.com/SaStWi/CodeShift` without modifying `README.md`, and published the official **CodeShift v2.1.0** Release.

### Step 12 — Connected Local Workspace to GitHub Repository (`https://github.com/SaStWi/CodeShift`), Configured Git on PATH & Created `.gitignore` (`2026-11-16 10:21 - 10:25`)
- **Agent**: New Agent (Antigravity)
- **User Request**: Connect the GitHub repository (`https://github.com/SaStWi/CodeShift`) to this project and install/configure the necessary files and Git.
- **Changes Made**:
  1. **Configured Git & Installed GitHub CLI (`gh`) on Persistent User `PATH`**:
     - Added `C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Git\cmd` (`git version 2.51.0.windows.2`) to the persistent Windows User `PATH`.
     - Installed **GitHub CLI (`gh version 2.104.0`)** to `%LOCALAPPDATA%\Programs\GitHubCLI\bin\gh.exe` and added it to the persistent Windows User `PATH`.
     - Configured `git config --global --add safe.directory` for the `Y:\Digibende\Utrecht\Kandidaten\Samuel Steven Willemsen\Test` workspace and set commit author identity to `TheSSW <137823139+SaStWi@users.noreply.github.com>`.
  2. **Connected Project Directory (`y:\Digibende\Utrecht\Kandidaten\Samuel Steven Willemsen\Test`) to `https://github.com/SaStWi/CodeShift.git`**:
     - Synced `.git` and the untouched `README.md` (`49e7e80`) from `origin/main` (`https://github.com/SaStWi/CodeShift.git`) directly into the project folder.
     - Created [`.gitignore`](file:///y:/Digibende/Utrecht/Kandidaten/Samuel%20Steven%20Willemsen/Test/.gitignore) to exclude `__pycache__/`, `*_extracted/`, `backups/`, `*.bak`, and `tools/`.
     - Staged and committed all project files (`game_extractor.py`, `run_extractor.bat`, `test_extractor.py`, `future_updates.md`, `memory.md`, `.gitignore`) on `main` and created tag `v2.1.0` + release bundle `CodeShift_v2.1.0_Release.zip`.
