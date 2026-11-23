from __future__ import annotations
import json
import zlib
import pickle
import struct
import shutil
import zipfile
import tempfile
import unittest
from pathlib import Path

from game_extractor import (
    EngineDetector,
    GameExtractor,
    DecompilerToolchainManager,
    BytecodeTranspiler,
    GameRecompiler,
    ModInjectorManager,
    SafeDeployManager,
    format_fallback_message,
)


class TestGameExtractor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="game_extractor_test_"))
        self.out_dir = self.temp_dir / "Output"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.extractor = GameExtractor(log_callback=lambda m: None, progress_callback=lambda p: None)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_fallback_message_exact_format(self):
        msg = format_fallback_message("CyberGame", "it is encrypted", "using QuickBMS")
        self.assertEqual(
            msg,
            "I was not able to extract the source code of CyberGame becouse it is encrypted but you can try it yourself using QuickBMS",
        )

    def test_construct3_webview2_c3ab_assets_dat_and_decompiler(self):
        game_dir = self.temp_dir / "Devices Tycoon Mock"
        www_dir = game_dir / "www"
        www_dir.mkdir(parents=True)
        (game_dir / "package.json").write_text(
            json.dumps({
                "name": "Devices Tycoon Mock",
                "bundle": {"type": "asset-bundle", "assets-path": "www\\assets.dat"},
                "project-details": {"name": "Devices Tycoon Mock"},
            }),
            encoding="utf-8",
        )

        mock_proj = [None] * 40
        mock_proj[0] = "Devices Tycoon Mock"
        mock_proj[1] = "START PAGE"
        mock_proj[3] = [["PhoneObject", 0]]
        mock_proj[4] = []
        mock_proj[5] = [["START PAGE", 1920, 1080, False, False, 0.5, 0.5, "auto", 0.03, "Event START"]]
        mock_proj[6] = [["Event START", [[1, "StartingBudget", 0, 50000]]]]
        mock_proj[16] = "1.6.0"
        mock_proj[38] = "com.example.devicestycoon"

        files_to_pack = [
            ("scripts/c3main.js", b'"use strict";function initGame(){let x=1;return x;}'),
            ("data.json", json.dumps({"project": mock_proj}).encode("utf-8")),
            ("ArrayOffices.json", b'{"c2array":true,"size":[1,1,1],"data":[[[100]]]}'),
        ]

        fdir_entries = bytearray()
        blob_payload = bytearray()
        for rel_name, content in files_to_pack:
            name_bytes = rel_name.encode("utf-8")
            offset = len(blob_payload)
            sz = len(content)
            fdir_entries += struct.pack(">QQQQBI", 0, offset, sz, sz, 0, len(name_bytes))
            fdir_entries += name_bytes
            blob_payload += content

        assets_dat = www_dir / "assets.dat"
        with open(assets_dat, "wb") as f:
            f.write(struct.pack(">4sQI", b"c3ab", 0x10, 0))
            f.write(struct.pack(">4sQI", b"fdir", 4 + len(fdir_entries), len(files_to_pack)))
            f.write(fdir_entries)
            f.write(struct.pack(">4sQ", b"blob", len(blob_payload)))
            f.write(blob_payload)

        resolved_root, resolved_title, detected_engine = EngineDetector.resolve_game_context(assets_dat)
        self.assertEqual(resolved_root, game_dir)
        self.assertEqual(resolved_title, "Devices Tycoon Mock")
        self.assertEqual(detected_engine, "Construct 3 (WebView2 c3ab)")

        ok, msg = self.extractor.extract(assets_dat, self.out_dir)
        self.assertTrue(ok, msg)

        extracted_root = self.out_dir / "Devices Tycoon Mock_extracted"
        self.assertTrue((extracted_root / "scripts" / "c3main.js").exists())
        self.assertTrue((extracted_root / "data.json").exists())
        self.assertTrue((extracted_root / "repack_c3ab.py").exists())
        self.assertTrue((extracted_root / "decompiled_construct3" / "CONSTRUCT3_PROJECT_MAP.md").exists())
        self.assertTrue((extracted_root / "decompiled_construct3" / "global_variables.json").exists())
        self.assertTrue((extracted_root / "decompiled_construct3" / "event_sheets" / "Event START.json").exists())

    def test_construct3_nwjs_extraction(self):
        game_dir = self.temp_dir / "ConstructGame"
        game_dir.mkdir()
        pkg_nw = game_dir / "package.nw"
        with zipfile.ZipFile(pkg_nw, "w") as zf:
            zf.writestr("index.html", "<html></html>")
            zf.writestr("scripts/c3runtime.js", "console.log('Construct 3 Runtime');")
            zf.writestr("data.json", '{"project": "C3Test"}')

        self.assertEqual(EngineDetector.detect(game_dir), "Construct 3 / NW.js")
        ok, msg = self.extractor.extract(game_dir, self.out_dir)
        self.assertTrue(ok, msg)
        extracted_root = self.out_dir / "ConstructGame_extracted"
        self.assertTrue((extracted_root / "scripts" / "c3runtime.js").exists())
        self.assertTrue((extracted_root / "AI_MODDING_GUIDE.md").exists())

    def test_construct3_electron_asar_extraction(self):
        game_dir = self.temp_dir / "ElectronGame"
        res_dir = game_dir / "resources"
        res_dir.mkdir(parents=True)
        asar_file = res_dir / "app.asar"

        payload = b"console.log('Hello from Electron ASAR');"
        header_dict = {"files": {"main.js": {"offset": "0", "size": len(payload)}}}
        json_bytes = json.dumps(header_dict).encode("utf-8")
        padding = (4 - (len(json_bytes) % 4)) % 4
        json_padded = json_bytes + (b"\x00" * padding)
        header_size = len(json_padded) + 8
        header_bin = struct.pack("<IIII", 4, header_size, header_size - 4, len(json_bytes)) + json_padded

        with open(asar_file, "wb") as f:
            f.write(header_bin)
            f.write(payload)

        self.assertEqual(EngineDetector.detect(game_dir), "Construct 3 / Electron")
        ok, msg = self.extractor.extract(game_dir, self.out_dir)
        self.assertTrue(ok, msg)
        extracted_js = self.out_dir / "ElectronGame_extracted" / "main.js"
        self.assertTrue(extracted_js.exists())
        self.assertEqual(extracted_js.read_bytes(), payload)

    def test_godot_pck_and_ecfg_extraction(self):
        pck_path = self.temp_dir / "GodotPlatformer.pck"
        gd_script = b"extends CharacterBody2D\nvar speed = 300.0\n"
        rel_path_bytes = b"res://player.gd\x00"

        header = bytearray()
        header += b"GDPC"
        header += struct.pack("<IIIII", 1, 4, 2, 0, 0)
        header += b"\x00" * (16 * 4)
        header += struct.pack("<I", 1)

        entry_meta_size = 4 + len(rel_path_bytes) + 8 + 8 + 16
        data_offset = len(header) + entry_meta_size

        header += struct.pack("<I", len(rel_path_bytes))
        header += rel_path_bytes
        header += struct.pack("<QQ", data_offset, len(gd_script))
        header += b"\x00" * 16

        with open(pck_path, "wb") as f:
            f.write(header)
            f.write(gd_script)

        self.assertEqual(EngineDetector.detect(pck_path), "Godot")
        ok, msg = self.extractor.extract(pck_path, self.out_dir)
        self.assertTrue(ok, msg)
        extracted_gd = self.out_dir / "GodotPlatformer_extracted" / "player.gd"
        self.assertTrue(extracted_gd.exists())
        self.assertEqual(extracted_gd.read_bytes(), gd_script)

    def test_renpy_rpa3_and_rpyc_extraction(self):
        rpa_path = self.temp_dir / "VisualNovel.rpa"
        rpy_content = b"label start:\n    'Hello Modder!'\n"
        key = 0xDEADBEEF
        header_placeholder = b"RPA-3.0 0000000000000000 deadbeef\n"
        data_offset = len(header_placeholder)
        index_offset = data_offset + len(rpy_content)

        index = {b"script.rpy": [(data_offset ^ key, len(rpy_content) ^ key, b"")]}
        compressed_index = zlib.compress(pickle.dumps(index))

        real_header = f"RPA-3.0 {index_offset:016x} {key:08x}\n".encode("ascii")
        with open(rpa_path, "wb") as f:
            f.write(real_header)
            f.write(rpy_content)
            f.write(compressed_index)

        self.assertEqual(EngineDetector.detect(rpa_path), "Ren'Py")
        ok, msg = self.extractor.extract(rpa_path, self.out_dir)
        self.assertTrue(ok, msg)
        extracted_rpy = self.out_dir / "VisualNovel_extracted" / "script.rpy"
        self.assertTrue(extracted_rpy.exists())
        self.assertEqual(extracted_rpy.read_bytes(), rpy_content)

    def test_gamemaker_iff_native_extraction(self):
        gm_dir = self.temp_dir / "UndertaleLikeGame"
        gm_dir.mkdir()
        data_win = gm_dir / "data.win"

        # Construct valid FORM + GEN8 + STRG IFF container
        gen8_payload = b"\x00" * 32
        s1 = b"scr_player_movement"
        s2 = b"Hello from GameMaker String Table!"
        # STRG layout: count=2, ptr0, ptr1, followed by [len, bytes, 0]
        # strg_offset in file will be: 8 (FORM) + 8 (GEN8 hdr) + 32 (GEN8 data) + 8 (STRG hdr) = 56
        strg_data_start = 56
        ptr0 = strg_data_start + 4 + 8
        ptr1 = ptr0 + 4 + len(s1) + 1
        strg_payload = (
            struct.pack("<III", 2, ptr0, ptr1)
            + struct.pack("<I", len(s1)) + s1 + b"\x00"
            + struct.pack("<I", len(s2)) + s2 + b"\x00"
        )
        form_body = (
            struct.pack("<4sI", b"GEN8", len(gen8_payload)) + gen8_payload
            + struct.pack("<4sI", b"STRG", len(strg_payload)) + strg_payload
        )
        with open(data_win, "wb") as f:
            f.write(struct.pack("<4sI", b"FORM", len(form_body)) + form_body)

        self.assertEqual(EngineDetector.detect(data_win), "GameMaker")
        ok, msg = self.extractor.extract(data_win, self.out_dir)
        self.assertTrue(ok, msg)
        extracted_strings = json.loads(
            (self.out_dir / "UndertaleLikeGame_extracted" / "gamemaker_strings.json").read_text(encoding="utf-8")
        )
        self.assertIn("scr_player_movement", extracted_strings)
        self.assertIn("Hello from GameMaker String Table!", extracted_strings)

    def test_rpgmaker_rgss_ruby_decompilation(self):
        rgss_dir = self.temp_dir / "FantasyRPG_VXAce"
        data_sub = rgss_dir / "Data"
        data_sub.mkdir(parents=True)
        rvdata2 = data_sub / "Scripts.rvdata2"

        ruby_code = b"class Game_Actor < Game_Battler\n  def setup(actor_id)\n    @hp = 9999\n  end\nend\n"
        compressed_ruby = zlib.compress(ruby_code)
        # Simulated Ruby Marshal header + compressed script payload
        rvdata2.write_bytes(b"\x04\x08[\x06[\x08i\x01\"\x0eGame_Actor" + compressed_ruby)

        self.assertEqual(EngineDetector.detect(rgss_dir), "RPG Maker (RGSS)")
        ok, msg = self.extractor.extract(rgss_dir, self.out_dir)
        self.assertTrue(ok, msg)
        rb_file = self.out_dir / "FantasyRPG_VXAce_extracted" / "decompiled_ruby_scripts" / "script_001.rb"
        self.assertTrue(rb_file.exists())
        self.assertIn("class Game_Actor", rb_file.read_text(encoding="utf-8"))

    def test_kirikiri_xp3_native_extraction(self):
        xp3_file = self.temp_dir / "VisualNovelKrkr.xp3"
        ks_script = b"*start\n[cm]\nHello from Kirikiri KAG script!\n[s]\n"

        # Build valid XP3 container
        magic = b"XP3\r\n \n\x1a\x8b\x67\x01"
        data_offset = 11 + 8  # right after magic + index_offset
        fname_utf16 = "scenario/first.ks".encode("utf-16le")
        info_payload = struct.pack("<IQQH", 0, len(ks_script), len(ks_script), len("scenario/first.ks")) + fname_utf16
        info_chunk = b"info" + struct.pack("<Q", len(info_payload)) + info_payload
        segm_payload = struct.pack("<IQQQ", 0, data_offset, len(ks_script), len(ks_script))
        segm_chunk = b"segm" + struct.pack("<Q", len(segm_payload)) + segm_payload
        file_payload = info_chunk + segm_chunk
        file_chunk = b"File" + struct.pack("<Q", len(file_payload)) + file_payload

        index_offset = data_offset + len(ks_script)
        with open(xp3_file, "wb") as f:
            f.write(magic)
            f.write(struct.pack("<Q", index_offset))
            f.write(ks_script)
            f.write(struct.pack("<BQ", 0, len(file_chunk)))
            f.write(file_chunk)

        self.assertEqual(EngineDetector.detect(xp3_file), "Kirikiri / XP3")
        ok, msg = self.extractor.extract(xp3_file, self.out_dir)
        self.assertTrue(ok, msg)
        extracted_ks = (
            self.out_dir / "VisualNovelKrkr_extracted" / "VisualNovelKrkr" / "scenario" / "first.ks"
        )
        self.assertTrue(extracted_ks.exists())
        self.assertEqual(extracted_ks.read_bytes(), ks_script)

    def test_java_libgdx_jar_extraction(self):
        jar_file = self.temp_dir / "DungeonCrawler.jar"
        with zipfile.ZipFile(jar_file, "w") as zf:
            zf.writestr("META-INF/MANIFEST.MF", "Main-Class: com.game.DesktopLauncher\n")
            zf.writestr("assets/items.json", '{"sword": {"damage": 50}}')

        self.assertEqual(EngineDetector.detect(jar_file), "Java / LibGDX / LWJGL")
        ok, msg = self.extractor.extract(jar_file, self.out_dir)
        self.assertTrue(ok, msg)
        self.assertTrue(
            (self.out_dir / "DungeonCrawler_extracted" / "DungeonCrawler" / "assets" / "items.json").exists()
        )

    def test_unity_il2cpp_fallback_message(self):
        unity_dir = self.temp_dir / "UnityIL2CPPGame"
        unity_dir.mkdir()
        (unity_dir / "UnityPlayer.dll").write_bytes(b"MZ")
        (unity_dir / "GameAssembly.dll").write_bytes(b"MZ")

        self.assertEqual(EngineDetector.detect(unity_dir), "Unity")
        ok, msg = self.extractor.extract(unity_dir, self.out_dir)
        self.assertFalse(ok)
        self.assertTrue(msg.startswith("I was not able to extract the source code of UnityIL2CPPGame becouse "))
        self.assertIn("but you can try it yourself", msg)

    def test_unreal_engine_fallback_message(self):
        ue_dir = self.temp_dir / "UnrealShooter"
        paks_dir = ue_dir / "Shooter" / "Content" / "Paks"
        paks_dir.mkdir(parents=True)
        (paks_dir / "pakchunk0-WindowsNoEditor.pak").write_bytes(b"\x00" * 32 + b"\xe1\x12\x6f\x5a" + b"\x00" * 20)

        self.assertEqual(EngineDetector.detect(ue_dir), "Unreal Engine")
        ok, msg = self.extractor.extract(ue_dir, self.out_dir)
        if not shutil.which("repak"):
            self.assertFalse(ok)
            self.assertTrue(msg.startswith("I was not able to extract the source code of UnrealShooter becouse "))
            self.assertIn("but you can try it yourself", msg)

    def test_unknown_engine_fallback_message(self):
        unknown_dir = self.temp_dir / "MysteryCustomGame"
        unknown_dir.mkdir()
        (unknown_dir / "custom.bin").write_bytes(b"\x01\x02\x03\x04")

        self.assertEqual(EngineDetector.detect(unknown_dir), "Unknown")
        ok, msg = self.extractor.extract(unknown_dir, self.out_dir)
        self.assertFalse(ok)
        self.assertTrue(msg.startswith("I was not able to extract the source code of MysteryCustomGame becouse "))
        self.assertIn("but you can try it yourself", msg)

    def test_construct3_recompiler_and_code_only_media_merge(self):
        game_dir = self.temp_dir / "TycoonCodeOnly"
        www_dir = game_dir / "www"
        www_dir.mkdir(parents=True)
        (game_dir / "package.json").write_text(
            json.dumps({
                "name": "TycoonCodeOnly",
                "enable-devtools": False,
                "project-details": {"name": "TycoonCodeOnly"},
            }),
            encoding="utf-8",
        )

        mock_proj = [None] * 40
        mock_proj[0] = "TycoonCodeOnly"
        mock_proj[1] = "START PAGE"
        mock_proj[3] = [["PhoneObject", 0]]
        mock_proj[4] = []
        mock_proj[5] = [["START PAGE", 1920, 1080, False, False, 0.5, 0.5, "auto", 0.03, "Event START"]]
        mock_proj[6] = [["Event START", [[1, "StartingBudget", 0, 50000]]]]

        png_payload = b"\x89PNG\r\n\x1a\nMOCK_IMAGE_DATA"
        files_to_pack = [
            ("scripts/c3main.js", b'"use strict";function initGame(){return 1;}'),
            ("data.json", json.dumps({"project": mock_proj}).encode("utf-8")),
            ("images/logo.png", png_payload),
        ]

        fdir_entries = bytearray()
        blob_payload = bytearray()
        for rel_name, content in files_to_pack:
            name_bytes = rel_name.encode("utf-8")
            offset = len(blob_payload)
            sz = len(content)
            fdir_entries += struct.pack(">QQQQBI", 0, offset, sz, sz, 0, len(name_bytes))
            fdir_entries += name_bytes
            blob_payload += content

        assets_dat = www_dir / "assets.dat"
        with open(assets_dat, "wb") as f:
            f.write(struct.pack(">4sQI", b"c3ab", 0x10, 0))
            f.write(struct.pack(">4sQI", b"fdir", 4 + len(fdir_entries), len(files_to_pack)))
            f.write(fdir_entries)
            f.write(struct.pack(">4sQ", b"blob", len(blob_payload)))
            f.write(blob_payload)

        # Extract in --code-only mode (include_media=False)
        code_only_extractor = GameExtractor(log_callback=lambda m: None, progress_callback=lambda p: None, include_media=False)
        ok, _ = code_only_extractor.extract(assets_dat, self.out_dir)
        self.assertTrue(ok)

        extracted_root = self.out_dir / "TycoonCodeOnly_extracted"
        self.assertFalse((extracted_root / "images" / "logo.png").exists())

        # Edit StartingBudget in global_variables.json
        gv_path = extracted_root / "decompiled_construct3" / "global_variables.json"
        gvars = json.loads(gv_path.read_text(encoding="utf-8"))
        gvars[0]["initial_value"] = 999999
        gv_path.write_text(json.dumps(gvars, indent=2), encoding="utf-8")

        # Recompile and verify media was merged from original assets.dat AND StartingBudget was updated in data.json!
        recompiler = GameRecompiler(log_callback=lambda m: None)
        ok_rec, modded_dat, _ = recompiler.recompile(extracted_root)
        self.assertTrue(ok_rec)
        self.assertTrue(modded_dat and modded_dat.exists())

        verify_dir = self.out_dir / "VerifyUnpack"
        verify_extractor = GameExtractor(log_callback=lambda m: None, progress_callback=lambda p: None, include_media=True)
        ok_ver, _ = verify_extractor.extract(modded_dat, verify_dir)
        self.assertTrue(ok_ver)
        re_extracted = verify_dir / "assets_modded_extracted"
        self.assertTrue((re_extracted / "images" / "logo.png").exists())
        self.assertEqual((re_extracted / "images" / "logo.png").read_bytes(), png_payload)
        re_gvars = json.loads((re_extracted / "decompiled_construct3" / "global_variables.json").read_text(encoding="utf-8"))
        self.assertEqual(re_gvars[0]["initial_value"], 999999)

    def test_mod_injector_construct3_unity_and_unreal(self):
        # 1. Construct 3 JS Mod Injector
        c3_dir = self.temp_dir / "C3ModTarget"
        c3_dir.mkdir()
        pkg_nw = c3_dir / "package.nw"
        with zipfile.ZipFile(pkg_nw, "w") as zf:
            zf.writestr("index.html", "<html><body><h1>Game</h1></body></html>")
            zf.writestr("scripts/c3main.js", "console.log('init');")
        self.extractor.extract(c3_dir, self.out_dir)
        c3_ext = self.out_dir / "C3ModTarget_extracted"

        inj = ModInjectorManager(log_callback=lambda m: None)
        ok_c3, _ = inj.install_injector(c3_ext, allow_network=False)
        self.assertTrue(ok_c3)
        self.assertTrue((c3_ext / "mods" / "mod_loader.js").exists())
        self.assertTrue((c3_ext / "mods" / "custom_mod.js").exists())
        self.assertIn("mods/mod_loader.js", (c3_ext / "index.html").read_text(encoding="utf-8"))

        # 2. Unity BepInEx Doorstop & C# Plugin Injector
        unity_dir = self.temp_dir / "UnityModTarget"
        unity_dir.mkdir()
        (unity_dir / "UnityPlayer.dll").write_bytes(b"MZ")
        (unity_dir / "GameAssembly.dll").write_bytes(b"MZ")
        self.extractor.extract(unity_dir, self.out_dir)
        unity_ext = self.out_dir / "UnityModTarget_extracted"
        ok_u, _ = inj.install_injector(unity_ext, game_root=unity_dir, allow_network=False)
        self.assertTrue(ok_u)
        self.assertTrue((unity_dir / "doorstop_config.ini").exists())
        self.assertTrue((unity_ext / "mods" / "CustomUnityMod.cs").exists())

        # 3. Unreal Engine UE4SS & ~mods Injector
        ue_dir = self.temp_dir / "UnrealModTarget"
        (ue_dir / "Game" / "Content" / "Paks").mkdir(parents=True)
        self.extractor.extract(ue_dir, self.out_dir)
        ue_ext = self.out_dir / "UnrealModTarget_extracted"
        ok_ue, _ = inj.install_injector(ue_ext, game_root=ue_dir, allow_network=False)
        self.assertTrue(ok_ue)
        self.assertTrue((ue_dir / "Binaries" / "Win64" / "Mods" / "CustomMod" / "Scripts" / "main.lua").exists())
        self.assertTrue((ue_dir / "Content" / "Paks" / "~mods").is_dir())

    def test_bytecode_transpiler_roundtrip_gamemaker_renpy_rgss_and_asar(self):
        recompiler = GameRecompiler(log_callback=lambda m: None)

        # 1. GameMaker data.win round-trip string editing & recompilation
        gm_dir = self.temp_dir / "GMRoundTrip"
        gm_dir.mkdir()
        data_win = gm_dir / "data.win"
        BytecodeTranspiler.assemble_gamemaker_win(gm_dir, None, data_win)
        # Write initial strings and build initial data.win
        (gm_dir / "gamemaker_strings.json").write_text(json.dumps(["init_str", "Old Dialogue"]), encoding="utf-8")
        BytecodeTranspiler.assemble_gamemaker_win(gm_dir, None, data_win)
        (gm_dir / "gamemaker_strings.json").unlink()

        ok, _ = self.extractor.extract(data_win, self.out_dir)
        self.assertTrue(ok)
        gm_ext = self.out_dir / "GMRoundTrip_extracted"
        gm_strings = json.loads((gm_ext / "gamemaker_strings.json").read_text(encoding="utf-8"))
        self.assertEqual(gm_strings[1], "Old Dialogue")
        gm_strings[1] = "Modded GameMaker Dialogue!"
        (gm_ext / "gamemaker_strings.json").write_text(json.dumps(gm_strings), encoding="utf-8")
        ok_gm, modded_win, _ = recompiler.recompile(gm_ext)
        self.assertTrue(ok_gm and modded_win and modded_win.exists())

        # Re-extract modded_win to confirm binary STRG table was updated
        verify_gm_dir = self.out_dir / "VerifyGM"
        self.extractor.extract(modded_win, verify_gm_dir)
        re_gm_strings = json.loads(
            (verify_gm_dir / "data_modded_extracted" / "gamemaker_strings.json").read_text(encoding="utf-8")
        )
        self.assertEqual(re_gm_strings[1], "Modded GameMaker Dialogue!")

        # 2. Ren'Py .rpyc Slot 1 AST round-trip recompilation
        rpyc_dir = self.temp_dir / "RenpyRoundTrip" / "game"
        rpyc_dir.mkdir(parents=True)
        rpyc_file = rpyc_dir / "script.rpyc"
        slot1_raw = zlib.compress(b"label start:\n    'Original RenPy Line'\n")
        rpyc_bin = b"RENPY RPC2" + struct.pack("<III", 1, 34, len(slot1_raw)) + struct.pack("<III", 0, 0, 0) + slot1_raw
        rpyc_file.write_bytes(rpyc_bin)

        ok_rp, _ = self.extractor.extract(rpyc_file, self.out_dir)
        self.assertTrue(ok_rp)
        rp_ext = self.out_dir / "RenpyRoundTrip_extracted"
        shutil.copy2(rpyc_file, rp_ext / "script.rpyc")
        sjson_path = rp_ext / "decompiled_rpyc" / "script.strings.json"
        self.assertTrue(sjson_path.exists())
        s_entries = json.loads(sjson_path.read_text(encoding="utf-8"))
        s_entries[0]["modified"] = "label start:\n    'Modded RenPy Line!!'\n"
        sjson_path.write_text(json.dumps(s_entries), encoding="utf-8")
        BytecodeTranspiler.assemble_renpy_dir(rp_ext)
        BytecodeTranspiler.disassemble_rpyc_file(rp_ext / "script.rpyc", rp_ext / "verify_rpyc")
        self.assertIn(
            "Modded RenPy Line!!",
            (rp_ext / "verify_rpyc" / "script.recovered.rpy.txt").read_text(encoding="utf-8"),
        )

        # 3. RPG Maker RGSS Scripts.rvdata2 round-trip recompilation
        rgss_dir = self.temp_dir / "RGSSRoundTrip" / "Data"
        rgss_dir.mkdir(parents=True)
        rvdata2 = rgss_dir / "Scripts.rvdata2"
        rvdata2.write_bytes(b"\x04\x08[\x06[\x08i\x01\"\x04Main" + zlib.compress(b"class Main\n  @gold = 100\nend\n"))
        self.extractor.extract(rgss_dir.parent, self.out_dir)
        rgss_ext = self.out_dir / "RGSSRoundTrip_extracted"
        rb1 = rgss_ext / "decompiled_ruby_scripts" / "script_001.rb"
        rb1.write_text("class Main\n  @gold = 999999\nend\n", encoding="utf-8")
        ok_rb, modded_rv, _ = recompiler.recompile(rgss_ext)
        self.assertTrue(ok_rb and modded_rv and modded_rv.exists())
        verify_rb_dir = rgss_ext / "verify_rb"
        BytecodeTranspiler.disassemble_rgss_scripts(modded_rv, verify_rb_dir)
        self.assertIn("@gold = 999999", (verify_rb_dir / "script_001.rb").read_text(encoding="utf-8"))

    def test_safe_deploy_and_restore_original_game(self):
        game_dir = self.temp_dir / "DeployTestGame"
        www_dir = game_dir / "www"
        www_dir.mkdir(parents=True)
        (game_dir / "package.json").write_text('{"name": "DeployTestGame", "enable-devtools": false}', encoding="utf-8")

        payload = b'{"test": 1}'
        name_b = b"config.json"
        fdir = struct.pack(">QQQQBI", 0, 0, len(payload), len(payload), 0, len(name_b)) + name_b
        assets_dat = www_dir / "assets.dat"
        orig_bytes = (
            struct.pack(">4sQI", b"c3ab", 0x10, 0)
            + struct.pack(">4sQI", b"fdir", 4 + len(fdir), 1)
            + fdir
            + struct.pack(">4sQ", b"blob", len(payload))
            + payload
        )
        assets_dat.write_bytes(orig_bytes)

        self.extractor.extract(assets_dat, self.out_dir)
        ext_dir = self.out_dir / "DeployTestGame_extracted"
        (ext_dir / "config.json").write_text('{"test": 9999}', encoding="utf-8")

        deployer = SafeDeployManager(log_callback=lambda m: None)
        ok_dep, dep_msg = deployer.deploy_modded_game(ext_dir, launch_after=False, allow_network=False)
        self.assertTrue(ok_dep, dep_msg)
        self.assertTrue((www_dir / "assets.dat.bak").exists())
        self.assertTrue((ext_dir / "backups" / "backup_manifest.json").exists())
        self.assertNotEqual(assets_dat.read_bytes(), orig_bytes)

        # Now restore original game and verify byte-for-byte identity
        ok_rest, rest_msg = deployer.restore_original_game(ext_dir)
        self.assertTrue(ok_rest, rest_msg)
        self.assertEqual(assets_dat.read_bytes(), orig_bytes)

    def test_unity_dnspy_and_engine_specific_toolchain(self):
        # Verify strictly engine-specific tools are registered (and NO AssetRipper)
        for key in ("dnspy", "cpp2il", "gdre_tools", "undertalemodcli", "repak", "unrpyc", "cfr"):
            self.assertIn(key, DecompilerToolchainManager.ENGINE_SPECIFIC_TOOLS)
        all_names = " ".join(str(v) for v in DecompilerToolchainManager.ENGINE_SPECIFIC_TOOLS.values()).lower()
        self.assertNotIn("assetripper", all_names)

        # Engines without external specific tools return (None, None) -> use default extractor
        self.assertEqual(
            DecompilerToolchainManager.get_installed_program_for_engine("Construct 3 (WebView2 c3ab)"),
            (None, None),
        )

        # Build a mock Unity Managed game with a valid ECMA-335 BSJB Assembly-CSharp.dll
        unity_game = self.temp_dir / "SpaceSimUnity"
        managed_dir = unity_game / "SpaceSim_Data" / "Managed"
        managed_dir.mkdir(parents=True)
        (unity_game / "UnityPlayer.dll").write_bytes(b"MZ")

        strings_heap = b"\x00PlayerController\x00Update\x00PlayerSpeed\x00CalculateOrbit\x00"
        ver_str = b"v4.0.30319\x00\x00"
        stream_hdr = (
            struct.pack("<II", 36, len(strings_heap))
            + b"#Strings\x00\x00\x00\x00"
        )
        bsjb_root = (
            b"BSJB"
            + struct.pack("<HHII", 1, 1, 0, len(ver_str))
            + ver_str
            + struct.pack("<HH", 0, 1)
            + stream_hdr
            + strings_heap
        )
        asm_dll = managed_dir / "Assembly-CSharp.dll"
        asm_dll.write_bytes(b"MZ" + (b"\x00" * 64) + b"mscoree.dll\x00" + bsjb_root)

        self.assertEqual(EngineDetector.detect(unity_game), "Unity")

        # Case 1: Specific program is NOT installed -> automatically use default extractor
        orig_tools_root = DecompilerToolchainManager.TOOLS_ROOT
        try:
            empty_tools = self.temp_dir / "empty_tools"
            empty_tools.mkdir(parents=True, exist_ok=True)
            DecompilerToolchainManager.TOOLS_ROOT = empty_tools

            ok_default, msg_default = self.extractor.extract(unity_game, self.out_dir)
            ext_dir = self.out_dir / "SpaceSimUnity_extracted"
            self.assertTrue((ext_dir / "Managed_Assemblies" / "Assembly-CSharp.dll").exists())
            self.assertTrue((ext_dir / "decompiled_dotnet_metadata" / "csharp_identifiers.json").exists())
            self.assertTrue((ext_dir / "open_in_dnspy.bat").exists())
            self.assertNotIn("assetripper", msg_default.lower())
            if not ok_default:
                self.assertTrue(
                    msg_default.startswith("I was not able to extract the source code of SpaceSimUnity becouse ")
                )

            # Case 2: Specific program (dnSpy.Console) IS installed -> automatically detect & use specific program
            mock_tools = self.temp_dir / "mock_tools"
            dnspy_dir = mock_tools / "dnSpy"
            dnspy_dir.mkdir(parents=True, exist_ok=True)
            mock_dnspy_bat = dnspy_dir / "dnSpy.Console.bat"
            mock_dnspy_bat.write_text(
                '@echo off\n'
                'mkdir "%~2" 2>nul\n'
                'echo namespace SpaceSimUnity { public class PlayerController { public void Update() {} } } > "%~2\\PlayerController.cs"\n'
                'exit /b 0\n',
                encoding="utf-8",
            )
            DecompilerToolchainManager.TOOLS_ROOT = mock_tools
            tool_name, tool_path = DecompilerToolchainManager.get_installed_program_for_engine("Unity")
            self.assertIsNotNone(tool_path)
            self.assertIn("dnSpyEx", tool_name)

            out_dir_2 = self.temp_dir / "OutWithDnSpy"
            ok_spec, msg_spec = self.extractor.extract(unity_game, out_dir_2)
            self.assertTrue(ok_spec, msg_spec)
            spec_ext = out_dir_2 / "SpaceSimUnity_extracted"
            self.assertTrue((spec_ext / "Decompiled_CSharp_Source" / "PlayerController.cs").exists())
            cs_text = (spec_ext / "Decompiled_CSharp_Source" / "PlayerController.cs").read_text(encoding="utf-8")
            self.assertIn("class PlayerController", cs_text)
        finally:
            DecompilerToolchainManager.TOOLS_ROOT = orig_tools_root

    def test_unity_il2cpp_among_us_global_metadata_decompilation(self):
        """Tests native Unity IL2CPP `global-metadata.dat` (`0xFAB11BAF`) extraction & C# stub generation (like Among Us)."""
        among_us = self.temp_dir / "Among Us"
        meta_dir = among_us / "Among Us_Data" / "il2cpp_data" / "Metadata"
        meta_dir.mkdir(parents=True)
        (among_us / "UnityPlayer.dll").write_bytes(b"MZ")
        (among_us / "GameAssembly.dll").write_bytes(b"MZ")

        # Build valid IL2CPP v29 global-metadata.dat with string literals + identifiers
        lit1 = b"ImpostorVictory"
        lit2 = b"EmergencyMeeting"
        sld_blob = lit1 + lit2
        str_blob = b"\x00Assembly-CSharp.dll\x00PlayerControl\x00MurderPlayer\x00ShipStatus\x00"

        hdr_size = 64
        sl_off = hdr_size
        sl_entries = struct.pack("<IIII", len(lit1), 0, len(lit2), len(lit1))
        sld_off = sl_off + len(sl_entries)
        str_off = sld_off + len(sld_blob)

        header = struct.pack(
            "<IIIIIIII",
            0xFAB11BAF, 29,
            sl_off, len(sl_entries),
            sld_off, len(sld_blob),
            str_off, len(str_blob),
        ) + (b"\x00" * (hdr_size - 32))
        meta_file = meta_dir / "global-metadata.dat"
        meta_file.write_bytes(header + sl_entries + sld_blob + str_blob)

        self.assertEqual(EngineDetector.detect(among_us), "Unity")
        ok, msg = self.extractor.extract(among_us, self.out_dir)
        self.assertTrue(ok, msg)
        il2cpp_dir = self.out_dir / "Among Us_extracted" / "decompiled_il2cpp"
        self.assertTrue((il2cpp_dir / "IL2CPP_DUMP_REPORT.md").exists())
        self.assertTrue((il2cpp_dir / "cs_stubs" / "Among_Us_IL2CPPStubs.cs").exists())
        idents = json.loads((il2cpp_dir / "il2cpp_identifiers.json").read_text(encoding="utf-8"))
        lits = json.loads((il2cpp_dir / "string_literals.json").read_text(encoding="utf-8"))
        self.assertIn("PlayerControl", idents)
        self.assertIn("MurderPlayer", idents)
        self.assertIn("ImpostorVictory", lits)

    def test_nested_wrapper_folder_and_new_engines_vpk_pack_pkg(self):
        """Tests downward wrapper folder detection (like Project Castle) + Source VPK, Total War PFH, and Wallpaper Engine PKG."""
        # 1. Nested wrapper folder (e.g., Project Castle/Project Castle/UnityPlayer.dll)
        wrapper = self.temp_dir / "Project Castle"
        inner = wrapper / "Project Castle"
        inner.mkdir(parents=True)
        (inner / "UnityPlayer.dll").write_bytes(b"MZ")
        root, title, eng = EngineDetector.resolve_game_context(wrapper)
        self.assertEqual(root, inner)
        self.assertEqual(eng, "Unity")

        # 2. Source Engine Valve VPK v1
        vpk_file = self.temp_dir / "CounterStrike_dir.vpk"
        cfg_data = b"sv_cheats 1\nmp_startmoney 16000\n"
        tree = (
            b"cfg\x00"
            b"scripts\x00"
            b"autoexec\x00"
            + struct.pack("<IHHIIH", 0, 0, 0x7FFF, 0, len(cfg_data), 0xFFFF)
            + b"\x00\x00\x00"
        )
        vpk_file.write_bytes(struct.pack("<III", 0x55AA1234, 1, len(tree)) + tree + cfg_data)
        self.assertEqual(EngineDetector.detect(vpk_file), "Source / Source 2 (VPK)")
        ok_vpk, msg_vpk = self.extractor.extract(vpk_file, self.out_dir)
        self.assertTrue(ok_vpk, msg_vpk)
        self.assertEqual(
            (self.out_dir / "CounterStrike_dir_extracted" / "CounterStrike_dir" / "scripts" / "autoexec.cfg").read_bytes(),
            cfg_data,
        )

        # 3. Total War Warscape PFH4 `.pack`
        tw_dir = self.temp_dir / "Total War Mock" / "data"
        tw_dir.mkdir(parents=True)
        pack_file = tw_dir / "data_rome2.pack"
        lua_data = b"function OnCampaignStart() end\n"
        file_idx = struct.pack("<I", len(lua_data)) + b"script/campaign.lua\x00"
        pack_hdr = b"PFH4" + struct.pack("<IIIIII", 0, 0, 0, 1, len(file_idx), 0)
        pack_file.write_bytes(pack_hdr + file_idx + lua_data)
        self.assertEqual(EngineDetector.detect(tw_dir.parent), "Total War (Warscape Pack)")
        ok_tw, msg_tw = self.extractor.extract(tw_dir.parent, self.out_dir)
        self.assertTrue(ok_tw, msg_tw)
        self.assertEqual(
            (self.out_dir / "Total War Mock_extracted" / "data_rome2" / "script" / "campaign.lua").read_bytes(),
            lua_data,
        )

        # 4. Wallpaper Engine PKGV `.pkg`
        pkg_file = self.temp_dir / "scene.pkg"
        scene_json = b'{"general":{"fov":60}}'
        ver = b"PKGV0001"
        name = b"scene.json"
        pkg_file.write_bytes(
            struct.pack("<I", len(ver)) + ver
            + struct.pack("<I", 1)
            + struct.pack("<I", len(name)) + name
            + struct.pack("<II", 0, len(scene_json))
            + scene_json
        )
        self.assertEqual(EngineDetector.detect(pkg_file), "Wallpaper Engine (PKG)")
        ok_pkg, msg_pkg = self.extractor.extract(pkg_file, self.out_dir)
        self.assertTrue(ok_pkg, msg_pkg)
        self.assertEqual(
            (self.out_dir / "scene_extracted" / "scene" / "scene.json").read_bytes(),
            scene_json,
        )

    def test_auto_decompile_before_inject_and_recompiled_exe_generation(self):
        """Tests that `ensure_decompiled_and_install` decompiles FIRST automatically AND builds a runnable Windows `.exe`."""
        game_dir = self.temp_dir / "AutoDecompileGame"
        game_dir.mkdir()
        (game_dir / "AutoDecompileGame.exe").write_bytes(b"MZ" + b"\x00" * 64)
        pkg_nw = game_dir / "package.nw"
        with zipfile.ZipFile(pkg_nw, "w") as zf:
            zf.writestr("index.html", "<html><body><h1>Play</h1></body></html>")
            zf.writestr("scripts/c3main.js", "console.log('ready');")

        # Call ensure_decompiled_and_install DIRECTLY on the raw game folder without calling extract() first!
        out_fresh = self.temp_dir / "FreshOut"
        mgr = ModInjectorManager(log_callback=lambda m: None)
        ok, ext_dir, msg = mgr.ensure_decompiled_and_install(
            game_dir, output_dir=out_fresh, allow_network=False, include_media=True
        )
        self.assertTrue(ok, msg)
        self.assertIsNotNone(ext_dir)
        self.assertTrue((ext_dir / "index.html").exists())
        self.assertTrue((ext_dir / "mods" / "mod_loader.js").exists())
        self.assertTrue((ext_dir / "recompiled_build" / "package.nw").exists())
        # Verify real Windows PE executable (.exe) was compiled!
        modded_exe = ext_dir / "AutoDecompileGame_Modded.exe"
        self.assertTrue(modded_exe.exists(), f"Expected runnable .exe at {modded_exe}\nLog: {msg}")
        self.assertTrue(modded_exe.read_bytes().startswith(b"MZ"))

    def test_il2cpp_like_aot_runtimes_hashlink_dotnet_singlefile_yyc_luajit_wasm_hxcpp(self):
        """Tests all newly added IL2CPP-like AOT & Script-to-Native extractors in `codeshift_backend`."""
        from codeshift_backend import (
            CancelToken,
            DotNetSingleFileUnpacker,
            GameMakerYYCAnalyzer,
            SettingsManager,
        )

        # 1. Haxe / HashLink (`hlboot.dat` HLB v5 — Dead Cells, Northgard, Wartales)
        hl_dir = self.temp_dir / "DeadCellsLike"
        hl_dir.mkdir()
        str_blob = b"game.Player\x00game.WeaponDatabase\x00HeroSlash\x00"
        hl_bytes = (
            b"HLB\x05"  # magic + v5
            + bytes([0, 0, 0, 3, 0, 2, 1, 0, 5, 0, 0])  # varuints: flags, nints, nfloats, nstrings, nbytes, ntypes, nglobals, nnatives, nfuncs, nconst, entry
            + struct.pack("<I", len(str_blob))
            + str_blob
        )
        (hl_dir / "hlboot.dat").write_bytes(hl_bytes)
        self.assertEqual(EngineDetector.detect(hl_dir), "Haxe / HashLink")
        ok_hl, msg_hl = self.extractor.extract(hl_dir, self.out_dir)
        self.assertTrue(ok_hl, msg_hl)
        hl_out = self.out_dir / "DeadCellsLike_extracted" / "decompiled_hashlink"
        self.assertTrue((hl_out / "HL_METADATA_REPORT.md").exists())
        self.assertTrue((hl_out / "RecoveredHashLinkSymbols.hx").exists())
        self.assertIn("game.Player", json.loads((hl_out / "hl_strings.json").read_text(encoding="utf-8")))

        # 2. .NET Single-File Bundled Executable (`SingleFileHost` v6)
        sf_exe = self.temp_dir / "SingleFileCSharpGame.exe"
        embedded_cfg = b'{"difficulty":"hard","maxPlayers":4}'
        rel_name = b"config/settings.json"
        # Layout: [MZ stub (64B)] [embedded_cfg] [BundleHeader v6] [8B hdr_off + 32B sig]
        data_off = 64
        hdr_off = data_off + len(embedded_cfg)
        bundle_id = b"TestBundle"
        header_v6 = (
            struct.pack("<III", 6, 0, 1)  # major=6, minor=0, file_count=1
            + bytes([len(bundle_id)]) + bundle_id
            + (b"\x00" * 40)  # v2+ deps/runtimeconfig/flags offsets
            + struct.pack("<QQQB", data_off, len(embedded_cfg), 0, 1)
            + bytes([len(rel_name)]) + rel_name
        )
        sf_exe.write_bytes(
            b"MZ" + (b"\x00" * 62)
            + embedded_cfg
            + header_v6
            + struct.pack("<Q", hdr_off)
            + DotNetSingleFileUnpacker.BUNDLE_SIGNATURE
        )
        self.assertEqual(EngineDetector.detect(sf_exe), ".NET Single-File Bundle")
        ok_sf, msg_sf = self.extractor.extract(sf_exe, self.out_dir)
        self.assertTrue(ok_sf, msg_sf)
        self.assertEqual(
            (self.out_dir / "SingleFileCSharpGame_extracted" / "unpacked_dotnet_bundle" / "config" / "settings.json").read_bytes(),
            embedded_cfg,
        )

        # 3. GameMaker YYC (YoYo Compiler GML->C++ AOT — empty CODE chunk in data.win)
        yyc_dir = self.temp_dir / "YYCActionGame"
        yyc_dir.mkdir()
        yyc_win = yyc_dir / "data.win"
        gen8 = b"\x00" * 32
        s1 = b"gml_Script_player_dash"
        s2 = b"obj_hero_controller"
        strg_off = 56
        p0 = strg_off + 12
        p1 = p0 + 4 + len(s1) + 1
        strg = struct.pack("<III", 2, p0, p1) + struct.pack("<I", len(s1)) + s1 + b"\x00" + struct.pack("<I", len(s2)) + s2 + b"\x00"
        body = struct.pack("<4sI", b"GEN8", len(gen8)) + gen8 + struct.pack("<4sI", b"STRG", len(strg)) + strg
        yyc_win.write_bytes(struct.pack("<4sI", b"FORM", len(body)) + body)
        self.assertTrue(GameMakerYYCAnalyzer.is_yyc_build(yyc_win))
        ok_yyc, msg_yyc = self.extractor.extract(yyc_dir, self.out_dir)
        self.assertTrue(ok_yyc, msg_yyc)
        self.assertTrue((self.out_dir / "YYCActionGame_extracted" / "decompiled_yyc" / "YYC_GML_STUBS.gml").exists())
        self.assertIn(
            "gml_Script_player_dash",
            (self.out_dir / "YYCActionGame_extracted" / "decompiled_yyc" / "YYC_GML_STUBS.gml").read_text(encoding="utf-8"),
        )

        # 4. LuaJIT Bytecode (`\x1bLJ` — Hades, Noita, Balatro)
        lj_file = self.temp_dir / "boss_ai.luac"
        lj_file.write_bytes(b"\x1bLJ\x02\x00\x00BossAttackPhase\x00FireballDamage\x00")
        self.assertEqual(EngineDetector.detect(lj_file), "Lua / LuaJIT Bytecode")
        ok_lj, msg_lj = self.extractor.extract(lj_file, self.out_dir)
        self.assertTrue(ok_lj, msg_lj)
        self.assertIn(
            "BossAttackPhase",
            (self.out_dir / "boss_ai_extracted" / "decompiled_lua" / "boss_ai.decompiled.lua").read_text(encoding="utf-8"),
        )

        # 5. WebAssembly (`.wasm` `\x00asm\x01\x00\x00\x00`)
        wasm_file = self.temp_dir / "physics_engine.wasm"
        exp_name = b"step_physics"
        exp_sec = bytes([1, len(exp_name)]) + exp_name + bytes([0, 0])
        wasm_file.write_bytes(b"\x00asm\x01\x00\x00\x00" + bytes([7, len(exp_sec)]) + exp_sec)
        self.assertEqual(EngineDetector.detect(wasm_file), "WebAssembly (WASM)")
        ok_w, msg_w = self.extractor.extract(wasm_file, self.out_dir)
        self.assertTrue(ok_w, msg_w)
        exports = json.loads((self.out_dir / "physics_engine_extracted" / "decompiled_wasm" / "physics_engine" / "wasm_exports.json").read_text(encoding="utf-8"))
        self.assertEqual(exports[0]["name"], "step_physics")

        # 6. Haxe HXCPP (C++ AOT PE Binary with MSVC RTTI Type Descriptors)
        hxcpp_exe = self.temp_dir / "HaxeFighter.exe"
        # Minimal valid PE64 header + MSVC RTTI class descriptors + HXCPP marker
        pe_off = 0x80
        dos_hdr = b"MZ" + (b"\x00" * (0x3C - 2)) + struct.pack("<I", pe_off) + (b"\x00" * (pe_off - 0x40))
        pe_hdr = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 240, 0x22)
        opt_hdr = struct.pack("<H", 0x20B) + (b"\x00" * 238)
        payload = b"hx::Object\x00.?AVCombatManager@Game@@\x00.?AVFighterEntity@Game@@\x00"
        hxcpp_exe.write_bytes(dos_hdr + pe_hdr + opt_hdr + payload)
        self.assertEqual(EngineDetector.detect(hxcpp_exe), "Haxe HXCPP (C++ AOT)")
        ok_hx, msg_hx = self.extractor.extract(hxcpp_exe, self.out_dir)
        self.assertTrue(ok_hx, msg_hx)
        rtti = json.loads((self.out_dir / "HaxeFighter_extracted" / "decompiled_native_aot" / "rtti_classes.json").read_text(encoding="utf-8"))
        self.assertIn("Game::CombatManager", rtti)
        self.assertIn("Game::FighterEntity", rtti)

        # 7. CancelToken cooperative cancellation & SettingsManager persistence
        tok = CancelToken()
        tok.cancel()
        cancelled_ext = GameExtractor(log_callback=lambda m: None, cancel_token=tok)
        ok_c, msg_c = cancelled_ext.extract(hl_dir, self.out_dir)
        self.assertFalse(ok_c)
        self.assertIn("cancelled", msg_c.lower())

        sm = SettingsManager(self.temp_dir / "test_settings.json")
        sm.add_recent_source(str(hl_dir))
        sm2 = SettingsManager(self.temp_dir / "test_settings.json")
        self.assertEqual(sm2.data["recent_sources"][0], str(hl_dir))

    def test_installed_game_scanner_filtering_and_quick_pick_selection(self):
        """Regression test for Quick-Pick Installed Game dropdown filtering & active game switching."""
        from codeshift_backend import GameLibraryScanner

        # 1. Verify non-game folders (DirectXRedist, UE_5.4, Launcher, empty dir) are excluded
        for non_game in ("DirectXRedist", "GameInputRedist", "Launcher", "UE_5.4", "EmptyLeftover"):
            d = self.temp_dir / non_game
            d.mkdir()
            if non_game == "DirectXRedist":
                (d / "DXSETUP.exe").write_bytes(b"MZ")
            self.assertTrue(GameLibraryScanner.is_non_game_dir(d), f"{non_game} should be ignored")

        # 2. Verify real game folder IS accepted
        real_game = self.temp_dir / "RealIndieGame"
        real_game.mkdir()
        (real_game / "RealIndieGame.exe").write_bytes(b"MZ")
        self.assertFalse(GameLibraryScanner.is_non_game_dir(real_game))


if __name__ == "__main__":
    unittest.main(verbosity=2)
