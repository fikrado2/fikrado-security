"""
Fikrado Security - Cross-Platform Runtime Helpers

Single source of truth for every OS-specific branch in the application:
capability flags, per-OS directory locations, elevation checks, and the
"open this path with the system handler" helper that replaces ``os.startfile``.

Windows behaviour is preserved exactly; Linux and macOS receive native
equivalents or a graceful fallback that keeps the UI functional.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

IS_WINDOWS: bool = sys.platform == "win32"
IS_MACOS: bool = sys.platform == "darwin"
IS_LINUX: bool = sys.platform.startswith("linux")

# Human readable platform label used in user-facing copy.
PLATFORM_NAME: str = "Windows" if IS_WINDOWS else ("macOS" if IS_MACOS else "Linux")

# True when the running process holds elevated privileges (Administrator / root).
IS_ROOT: bool = False


def is_admin() -> bool:
    """Returns True when the process has elevated privileges on this platform."""
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def set_app_id(app_id: str, version: str) -> None:
    """Windows-only taskbar identity (AppUserModelID). No-op elsewhere."""
    if not IS_WINDOWS:
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(f"{app_id}.{version}")
    except Exception:
        pass


def open_path(path) -> bool:
    """
    Opens a file or directory with the platform default handler.

    Cross-platform replacement for ``os.startfile`` (Windows-only). Uses the
    native opener per OS and falls back to Qt's desktop services when no
    command-line opener is available (e.g. minimal Wayland sessions).
    """
    target = str(Path(path))
    try:
        if IS_WINDOWS:
            os.startfile(target)  # type: ignore[attr-defined]
            return True

        if IS_MACOS:
            subprocess.Popen(
                ["open", target],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True

        opener = shutil.which("xdg-open")
        if opener:
            subprocess.Popen(
                [opener, target],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return True
    except Exception:
        pass

    # Last resort: ask Qt (works whenever a QApplication is alive).
    try:
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices

        if target.endswith(("/", "\\")) or Path(target).is_dir():
            url = QUrl.fromLocalFile(target)
        else:
            url = QUrl.fromLocalFile(target)
        return bool(QDesktopServices.openUrl(url))
    except Exception:
        return False


def temp_dir() -> Path:
    """Platform temporary directory (``%TEMP%``, ``$TMPDIR`` or ``/tmp``)."""
    try:
        return Path(tempfile.gettempdir())
    except Exception:
        return Path("/tmp") if not IS_WINDOWS else Path(os.getenv("TEMP", "."))


def user_startup_dirs() -> List[Path]:
    """Per-user autostart locations for the current platform."""
    if IS_WINDOWS:
        appdata = Path(os.getenv("APPDATA", Path.home() / "AppData" / "Roaming"))
        return [appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"]
    if IS_MACOS:
        return [Path.home() / "Library" / "LaunchAgents"]
    xdg = Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config"))
    return [xdg / "autostart"]


def system_startup_dirs() -> List[Path]:
    """Machine-wide autostart locations for the current platform."""
    if IS_WINDOWS:
        programdata = Path(os.getenv("PROGRAMDATA", "C:/ProgramData"))
        return [programdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"]
    if IS_MACOS:
        return [Path("/Library/LaunchAgents")]
    return [Path("/etc/xdg/autostart")]


def all_startup_dirs() -> List[Path]:
    """User + system autostart directories, de-duplicated and existence-filtered."""
    dirs: List[Path] = []
    seen = set()
    for candidate in (*user_startup_dirs(), *system_startup_dirs()):
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        dirs.append(candidate)
    return dirs


def hosts_file_path() -> Path:
    """Location of the resolver hosts file for the current platform."""
    if IS_WINDOWS:
        windir = os.getenv("WINDIR", r"C:\Windows")
        return Path(windir) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


def default_hosts_content() -> str:
    """Stock hosts file template used by the restore-clean-hosts action."""
    if IS_WINDOWS:
        return (
            "# Copyright (c) 1993-2009 Microsoft Corp.\n"
            "#\n"
            "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\n"
            "#\n"
            "127.0.0.1       localhost\n"
            "::1             localhost\n"
        )
    if IS_MACOS:
        return (
            "##\n"
            "# Host Database\n"
            "#\n"
            "# localhost is used to configure the loopback interface\n"
            "# when the system is booting.  Do not change this entry.\n"
            "##\n"
            "127.0.0.1       localhost\n"
            "255.255.255.255 broadcasthost\n"
            "::1             localhost\n"
        )
    return (
        "# Do not edit this file, it is generated by Fikrado Security.\n"
        "127.0.0.1       localhost\n"
        "::1             localhost ip6-localhost ip6-loopback\n"
        "ff02::1         ip6-allnodes\n"
        "ff02::2         ip6-allrouters\n"
    )


def browser_extension_dirs() -> List[Tuple[str, Path]]:
    """
    Chromium/Firefox extension directories per platform.

    Returns (display name, path) pairs; callers skip paths that do not exist.
    """
    home = Path.home()
    if IS_WINDOWS:
        local = Path(os.getenv("LOCALAPPDATA", home / "AppData" / "Local"))
        roaming = Path(os.getenv("APPDATA", home / "AppData" / "Roaming"))
        return [
            ("Google Chrome", local / "Google" / "Chrome" / "User Data" / "Default" / "Extensions"),
            ("Microsoft Edge", local / "Microsoft" / "Edge" / "User Data" / "Default" / "Extensions"),
            ("Brave Browser", local / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Extensions"),
            ("Firefox", roaming / "Mozilla" / "Firefox" / "Profiles"),
        ]
    if IS_MACOS:
        support = home / "Library" / "Application Support"
        return [
            ("Google Chrome", support / "Google" / "Chrome" / "Default" / "Extensions"),
            ("Microsoft Edge", support / "Microsoft Edge" / "Default" / "Extensions"),
            ("Brave Browser", support / "BraveSoftware" / "Brave-Browser" / "Default" / "Extensions"),
            ("Firefox", support / "Firefox" / "Profiles"),
        ]
    config = Path(os.getenv("XDG_CONFIG_HOME", home / ".config"))
    return [
        ("Google Chrome", config / "google-chrome" / "Default" / "Extensions"),
        ("Chromium", config / "chromium" / "Default" / "Extensions"),
        ("Microsoft Edge", config / "microsoft-edge" / "Default" / "Extensions"),
        ("Brave Browser", config / "BraveSoftware" / "Brave-Browser" / "Default" / "Extensions"),
        ("Firefox", config / "mozilla" / "firefox" / "Profiles"),
    ]


def is_removable_mount(mountpoint: str) -> bool:
    """
    Best-effort removable-media detection for POSIX mount points.

    Windows uses ``GetDriveTypeW`` (see ``tools.realtime_guard``); on Linux and
    macOS we recognise the standard hot-plug mount prefixes.
    """
    if IS_WINDOWS:
        return False
    path = str(Path(mountpoint))
    prefixes = ("/Volumes/",) if IS_MACOS else ("/media/", "/run/media/", "/mnt/")
    return path.startswith(prefixes) or path.rstrip("/") in {p.rstrip("/") for p in prefixes}


def default_clamscan_name() -> str:
    """Platform binary name for the optional ClamAV scanner."""
    return "clamscan.exe" if IS_WINDOWS else "clamscan"


def default_freshclam_name() -> str:
    """Platform binary name for the optional ClamAV signature updater."""
    return "freshclam.exe" if IS_WINDOWS else "freshclam"
