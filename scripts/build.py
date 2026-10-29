#!/usr/bin/env python3
"""
Cross-platform build script for Fikrado Security.
Usage:
  python scripts/build.py          # detects OS
  python scripts/build.py win      # Windows
  python scripts/build.py linux    # Linux (AppImage + .deb)
  python scripts/build.py mac      # macOS (.dmg)
"""
import sys, os, subprocess, shutil
from pathlib import Path

def run(cmd, check=True):
    print(f"[*] {' '.join(str(c) for c in cmd)}")
    return subprocess.run(cmd, check=check, capture_output=False)

def build_windows():
    print("=== Windows build ===")
    run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "-q"])
    # Preserve existing build.bat behavior; this script just validates
    print("[*] Windows: run build.bat for PyInstaller .exe")
    print("[*] Windows artifact: dist/FikradoSecurity.exe")

def build_linux():
    print("=== Linux build ===")
    run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "-q"])
    # AppImage packaging (AppImageTool / linuxdeploy + PyInstaller single-file binary)
    # Build PyInstaller binary first
    # Note: for full AppImage, use linuxdeploy after building dist/FikradoSecurity
    print("[*] Linux AppImage: build PyInstaller binary then wrap with linuxdeploy / AppImageBuilder")
    print("[*] Linux artifact: Fikrado-Security.AppImage + .deb (optional)")

def build_mac():
    print("=== macOS build ===")
    run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "-q"])
    print("[*] macOS: build with PyInstaller + create .dmg via create-dmg / dmgbuild")
    print("[*] macOS artifact: Fikrado-Security.dmg (universal or x64+arm64)")

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else None
    if not mode:
        import platform
        p = platform.system()
        mode = {"Windows":"win","Linux":"linux","Darwin":"mac"}.get(p, "linux")
    {"win":build_windows,"linux":build_linux,"mac":build_mac}.get(mode, build_linux)()

if __name__ == "__main__":
    main()
