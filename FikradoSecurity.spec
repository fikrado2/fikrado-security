# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller Spec file for Fikrado Security
Produces standalone dist/FikradoSecurity.exe with embedded UAC Administrator manifest.
"""
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None
IS_WINDOWS = sys.platform == "win32"
project_root = Path.cwd()

# Per-OS build settings
icon_path = str(project_root / 'assets' / 'logo.ico') if IS_WINDOWS else None
if not IS_WINDOWS:
    icns_path = str(project_root / 'assets' / 'logo.icns')
    if (project_root / 'assets' / 'logo.icns').exists():
        icon_path = icns_path
    else:
        # Fallback: no icon on POSIX until .icns is generated
        icon_path = None

datas = [
    (str(project_root / 'assets'), 'assets'),
    (str(project_root / 'plugins'), 'plugins'),
]

hiddenimports = [
    'PySide6.QtCore',
    'PySide6.QtGui',
    'PySide6.QtWidgets',
    'PySide6.QtPrintSupport',
    'PySide6.QtSvg',
    'yara',
    'pefile',
    'psutil',
    'cryptography',
    'cryptography.hazmat.primitives.ciphers.aead',
    'cryptography.hazmat.primitives.kdf.pbkdf2',
    'win32crypt',
    'requests',
    'sqlite3',
    'plugins.base_plugin',
    'plugins.gemini_plugin',
    'plugins.openai_plugin',
    'plugins.openrouter_plugin',
    'plugins.anthropic_plugin',
    'plugins.ollama_plugin',
    'plugins.custom_plugin',
]

a = Analysis(
    ['main.py'],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'scipy', 'pandas'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

if IS_WINDOWS:
    exe_kwargs = {
        'icon': icon_path,
        'version': str(project_root / 'version_info.txt') if (project_root / 'version_info.txt').exists() else None,
        'uac_admin': True,
    }
else:
    exe_kwargs = {
        'icon': icon_path,
    }

exe_kwargs['console'] = False

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='FikradoSecurity',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    **{k: v for k, v in exe_kwargs.items() if v is not None},
)
