@echo off
echo Starting Fikrado Security...
cd /d "%~dp0"
if exist "dist\FikradoSecurity.exe" (
    start "" "dist\FikradoSecurity.exe"
) else (
    echo Executable not found. Please build first.
    pause
)
