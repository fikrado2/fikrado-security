@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo          Fikrado Security - Build Automation
echo =======================================================
echo.

cd /d "%~dp0"

REM 1. Check Python / Virtual Environment
if exist ".venv\Scripts\python.exe" (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
    set "PYINSTALLER_EXE=.venv\Scripts\pyinstaller.exe"
    echo [*] Using virtual environment Python: !PYTHON_EXE!
) else (
    where python >nul 2>&1
    if errorlevel 1 (
        echo [!] Error: Python is not installed or not in PATH.
        exit /b 1
    )
    set "PYTHON_EXE=python"
    set "PYINSTALLER_EXE=pyinstaller"
    echo [*] Using system Python.
)

REM 2. Verify / Build Assets
echo [*] Checking branding and assets...
if not exist "assets\logo.ico" (
    echo [*] Generating assets\logo.ico from assets\logo.png...
    !PYTHON_EXE! -c "from PIL import Image; img = Image.open('assets/logo.png').convert('RGBA'); img.save('assets/logo.ico', format='ICO', sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])"
)

REM 3. Clean previous builds
echo [*] Cleaning previous build artifacts...
if exist "build" rmdir /s /q "build"
if exist "dist\FikradoSecurity.exe" del /f /q "dist\FikradoSecurity.exe"

REM 4. Execute PyInstaller
echo [*] Packaging standalone executable with PyInstaller...
echo [*] Requesting Administrator UAC manifest and bundling assets...
!PYINSTALLER_EXE! --clean FikradoSecurity.spec

if errorlevel 1 (
    echo.
    echo [!] Build failed during PyInstaller packaging.
    exit /b 1
)

REM 5. Verify Output Executable
if exist "dist\FikradoSecurity.exe" (
    echo.
    echo =======================================================
    echo [SUCCESS] FikradoSecurity.exe successfully created!
    echo Output Location: %~dp0dist\FikradoSecurity.exe
    for %%F in ("dist\FikradoSecurity.exe") do (
        set /a size_mb=%%~zF / 1048576
        echo Binary Size: !size_mb! MB - %%~zF bytes
    )
    echo =======================================================
    exit /b 0
)

echo.
echo [!] Error: dist\FikradoSecurity.exe was not generated.
exit /b 1
