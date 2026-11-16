@echo off
title Multi-Engine Game Source Extractor
python "%~dp0game_extractor.py"
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Program exited with code %ERRORLEVEL%.
    pause
)

