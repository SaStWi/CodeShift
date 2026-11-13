




# Game Extractor and Modding Suite

A zero-dependency Python tool designed to detect, extract, decompile, recompile, and inject mods into games across multiple game engines.

## Overview

This tool simplifies game modding and reverse engineering. It automatically identifies the engine used by a target game, unpacks archives, extracts source code and scripts into human-readable formats, and allows you to recompile changes or install mod loaders directly.

Key characteristics:
- Standard Library Only: Built entirely using Python's built-in libraries. No external packages or pip install commands required.
- Memory Efficient: Uses 16 MB chunked streaming to handle large game files (100 GB+) with minimal RAM consumption.
- Dual Interface: Includes both a desktop graphical user interface (Tkinter) and a full command-line interface (CLI).


## Requirements

- Python 3.8 or higher installed on your system.

## How to Use

### 1. Graphical User Interface (GUI)

On Windows, launch the tool by double-clicking:
```cmd
run_extractor.bat
```

Alternatively, launch it from the command line:
```bash
python game_extractor.py
```

Using the GUI:
1. Click "Browse File" or "Browse Folder" to select a game executable, archive, or installation directory.
2. Select your desired output directory.
3. (Optional) Check "Fast Mode (Code & Data Only)" if you only want scripts and config files rather than large audio and video files.
4. Click "Extract Game".
5. Use the "Recompile" or "Inject Mod" buttons to repack modified files or set up mod loaders.

### 2. Command Line Interface (CLI)

Add the --cli argument to run without opening a window.

#### Extracting a Game
Extract all files from a game executable, archive, or folder:
```bash
python game_extractor.py --cli --input "C:\Games\TargetGame\game.exe" --output "C:\Mods\TargetGame_Extracted"
```

Extract code and data files only (skips heavy media assets for speed):
```bash
python game_extractor.py --cli --input "C:\Games\TargetGame" --output "C:\Mods\TargetGame_Extracted" --code-only
```

#### Recompiling Changes
Rebuild an extracted workspace back into a playable game package:
```bash
python game_extractor.py --cli --recompile --input "C:\Mods\TargetGame_Extracted" --output "C:\Games\TargetGame\assets.dat"
```

#### Installing Mod Injectors
Automatically detect the engine and install the appropriate mod loader (such as BepInEx for Unity, UE4SS for Unreal Engine, or custom JavaScript loaders for web-based engines):
```bash
python game_extractor.py --cli --inject-mod --input "C:\Games\TargetGame"
```

## Modding Workflow

1. Extract: Run the extractor against the game folder. The tool detects the engine and unpacks code, assets, and configuration files.
2. Edit: Modify the extracted source files, scripts, or global variable definitions manually or using an AI coding assistant.
3. Recompile or Inject: Use the recompile command to write changes back to the game format, or run the injector to load custom scripts automatically.
