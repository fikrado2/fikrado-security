@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo          Fikrado Security - Rust Native Build
echo =======================================================
echo.

cd /d "%~dp0"

REM 1. Check Cargo / Rust
where cargo >nul 2>&1
if errorlevel 1 (
    echo [!] Error: Cargo is not installed or not in PATH.
    echo Please install Rust from https://rustup.rs
    exit /b 1
)

REM 2. Ensure dist/ exists
if not exist "dist" mkdir "dist"

REM 3. Compile Main Application and Uninstaller
echo [*] Step 1/2: Compiling Fikrado Security and Uninstaller...
cargo build --release --bin FikradoSecurity --bin FikradoSecurityUninstall
if errorlevel 1 (
    echo [!] Main application build failed.
    exit /b 1
)

copy /y "target\release\FikradoSecurity.exe" "dist\FikradoSecurity.exe" >nul
copy /y "target\release\FikradoSecurityUninstall.exe" "dist\FikradoSecurityUninstall.exe" >nul
if exist "assets\logo.ico" copy /y "assets\logo.ico" "dist\logo.ico" >nul

REM 4. Compile Installer (embeds the compiled app)
echo [*] Step 2/2: Compiling Fikrado Security Setup Installer...
cargo build --release --bin FikradoSecuritySetup
if errorlevel 1 (
    echo [!] Installer build failed.
    exit /b 1
)

copy /y "target\release\FikradoSecuritySetup.exe" "dist\FikradoSecuritySetup.exe" >nul

echo.
echo =======================================================
echo [SUCCESS] All native deliverables built successfully!
echo.
echo  - Main App:  %~dp0dist\FikradoSecurity.exe
echo  - Installer: %~dp0dist\FikradoSecuritySetup.exe
echo  - Uninstall: %~dp0dist\FikradoSecurityUninstall.exe
echo =======================================================
