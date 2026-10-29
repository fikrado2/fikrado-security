"""
Fikrado Security - Real-Time Protection Shield

Continuously watches the places threats actually use:
  * user drop folders (Downloads, Desktop, Documents, Temp, Public)
  * newly launched processes (especially from Temp/AppData)
  * Windows startup persistence (Run/RunOnce keys + Startup folders)
  * new network listeners
  * removable drives and, optionally, every local drive root

The guard is intentionally lightweight: it only inspects files that appear after
startup, caps how many entries it walks, and skips whitelisted paths.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple

import psutil
from PySide6.QtCore import QObject, Signal

from config.constants import APPDATA_BASE
from config.settings import SettingsManager
from core.logger import logger
from core.platforms import (
    IS_MACOS,
    IS_WINDOWS,
    all_startup_dirs,
    is_removable_mount,
    system_startup_dirs,
    temp_dir,
    user_startup_dirs,
)
from scanners.malware_scanner import compute_sha256
from scanners.pe_analyzer import pe_analyzer
from scanners.yara_engine import yara_engine

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows import safety
    winreg = None

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".msi", ".msp",
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".jar", ".py", ".pyw", ".lnk",
    # POSIX script / installer / package formats
    ".sh", ".run", ".bin", ".appimage", ".command", ".desktop",
    ".deb", ".rpm", ".pkg", ".dmg", ".app",
}

# POSIX payloads frequently have no suffix at all (ELF binaries, shell
# scripts); on those platforms extensionless files are scanned when they carry
# the executable bit.
_SCAN_EXTENSIONLESS_EXECUTABLES = not IS_WINDOWS

_SKIP_DIR_NAMES = {
    "node_modules", ".git", ".svn", "__pycache__", "windows", "winsxs",
    "$recycle.bin", "system volume information", "recovery", "perflogs",
}

_COMMON_LISTEN_PORTS = {
    80, 443, 135, 139, 445, 500, 1900, 2869, 3389, 3702, 5040,
    5353, 5355, 5985, 5986, 7680,
}

_SYSTEM_PROCESS_NAMES = {
    # Windows
    "system", "system idle process", "svchost.exe", "services.exe",
    "lsass.exe", "wininit.exe", "winlogon.exe", "spoolsv.exe",
    "smss.exe", "csrss.exe", "dwm.exe", "fontdrvhost.exe",
    # Linux
    "systemd", "kthreadd", "ksoftirqd", "rcu_sched", "kworker", "kcompactd0",
    "dbus-daemon", "gdm-session-worker", "gnome-shell", "Xorg", "Xwayland",
    "pipewire", "wireplumber", "pulseaudio", "sddm", "lightdm", "sshd",
    "containerd", "dockerd",
    # macOS
    "launchd", "kernel_task", "WindowServer", "loginwindow", "opendirectoryd",
    "distnoted", "cfprefsd", "powerd", "syslogd", "logd",
}

_MAX_TRACKED_FILES = 60_000
_MAX_NEW_FILES_PER_CYCLE = 600


class RealtimeGuardSignals(QObject):
    threat_intercepted = Signal(dict)
    guard_status_changed = Signal(bool, str)


class RealtimeGuard(threading.Thread):
    """Background monitoring thread for filesystem, process and network surveillance."""

    def __init__(self):
        super().__init__(daemon=True, name="RealtimeGuardThread")
        self.signals = RealtimeGuardSignals()
        self.settings = SettingsManager()
        self._running = False
        self._paused = False
        self._seen_pids: Set[int] = set()
        self._seen_files: Set[str] = set()
        self._seen_startup: Set[str] = set()
        self._seen_listeners: Set[Tuple[int, int]] = set()
        self._seen_drives: Set[str] = set()
        self._removable_roots: Set[str] = set()
        self._monitored_paths: List[Path] = []
        self._scan_depth = 2

    # ------------------------------------------------------------------ state
    @property
    def is_active(self) -> bool:
        return (
            self._running
            and not self._paused
            and self.settings.get("realtime", "enabled", True)
        )

    def start_guard(self):
        """Start the guard, or resume it if it was paused."""
        if not self.settings.get("realtime", "enabled", True):
            logger.info("Real-Time Protection is disabled in settings; guard not started.")
            return
        if self._running:
            if self._paused:
                self.resume_guard()
            return
        self._paused = False
        self._running = True
        self._refresh_monitored_paths()
        self._seed_state()
        self.start()
        self.signals.guard_status_changed.emit(True, self.scope_summary())
        logger.info("Real-Time Protection guard started. Scope: %s", self.scope_summary())

    def pause_guard(self):
        if not self._running or self._paused:
            return
        self._paused = True
        self.signals.guard_status_changed.emit(False, "Real-Time Protection is paused.")
        logger.info("Real-Time Protection guard paused.")

    def resume_guard(self):
        if not self._running:
            self.start_guard()
            return
        if not self._paused:
            return
        self._paused = False
        self._refresh_monitored_paths()
        self._seed_state()
        self.signals.guard_status_changed.emit(True, self.scope_summary())
        logger.info("Real-Time Protection guard resumed.")

    def stop_guard(self):
        if not self._running:
            return
        self._running = False
        self._paused = False
        self.signals.guard_status_changed.emit(False, "Real-Time Protection stopped.")
        logger.info("Real-Time Protection guard stopped.")

    def scope_summary(self) -> str:
        parts = []
        if self.settings.get("realtime", "monitor_processes", True):
            parts.append("processes")
        if self._filesystem_enabled():
            parts.append("files")
        if self.settings.get("realtime", "monitor_startup", True):
            parts.append("startup")
        if self.settings.get("realtime", "monitor_network", True):
            parts.append("network")
        if self.settings.get("realtime", "monitor_removable", True):
            parts.append("USB")
        if self.settings.get("realtime", "monitor_all_drives", False):
            parts.append("all drives")
        return "Monitoring " + ", ".join(parts) if parts else "Monitoring paused"

    # -------------------------------------------------------------- path setup
    def _filesystem_enabled(self) -> bool:
        return any(
            self.settings.get("realtime", key, True)
            for key in ("scan_downloads", "scan_temp", "monitor_user_folders")
        )

    def _refresh_monitored_paths(self):
        paths: List[Path] = []
        home = Path.home()

        if self.settings.get("realtime", "scan_downloads", True):
            paths.append(home / "Downloads")
            if IS_WINDOWS:
                public = os.getenv("PUBLIC")
                if public:
                    paths.append(Path(public) / "Downloads")
        if self.settings.get("realtime", "scan_temp", True):
            paths.append(temp_dir())
        if self.settings.get("realtime", "monitor_user_folders", True):
            folder_names = ("Desktop", "Documents")
            if IS_WINDOWS:
                # OneDrive keeps redirected copies of the standard user folders.
                folder_names += ("OneDrive\\Desktop", "OneDrive\\Documents")
            for name in folder_names:
                paths.append(home / name)
            if IS_WINDOWS:
                public = os.getenv("PUBLIC")
                if public:
                    paths.append(Path(public))
        if self.settings.get("realtime", "monitor_startup", True):
            paths.extend(user_startup_dirs())
            paths.extend(system_startup_dirs())
        if self.settings.get("realtime", "monitor_removable", True):
            paths.extend(Path(root) for root in self._removable_roots)
        if self.settings.get("realtime", "monitor_all_drives", False):
            for part in self._local_partitions():
                paths.append(Path(part.mountpoint))

        seen: Set[str] = set()
        unique: List[Path] = []
        for path in paths:
            try:
                key = str(path.resolve()).lower()
            except OSError:
                key = str(path).lower()
            if key in seen or not path.exists():
                continue
            seen.add(key)
            unique.append(path)
        self._monitored_paths = unique
        self._scan_depth = 1 if self.settings.get("realtime", "monitor_all_drives", False) else 2

    @staticmethod
    def _local_partitions() -> List[psutil._common.sdiskpart]:
        partitions = []
        try:
            for part in psutil.disk_partitions(all=False):
                if "cdrom" in part.opts.lower():
                    continue
                partitions.append(part)
        except Exception:
            pass
        return partitions

    def _seed_state(self):
        """Remember current state so only genuinely new activity is reported."""
        for proc in psutil.process_iter(["pid"]):
            try:
                self._seen_pids.add(proc.info["pid"])
            except Exception:
                continue

        if self._filesystem_enabled():
            for root in self._monitored_paths:
                for file_path in self._iter_files(root, self._scan_depth):
                    self._seen_files.add(str(file_path))
                    if len(self._seen_files) >= _MAX_TRACKED_FILES:
                        break

        self._seen_startup = set(self._snapshot_startup().keys())
        self._seen_listeners = self._snapshot_listeners()
        self._seen_drives = {part.mountpoint.lower() for part in self._local_partitions()}

    # ---------------------------------------------------------------- main loop
    def run(self):
        while self._running:
            interval = 3
            try:
                interval = max(1, min(60, int(self.settings.get("realtime", "check_interval_seconds", 3))))
                if not self._paused and self.settings.get("realtime", "enabled", True):
                    if self.settings.get("realtime", "monitor_processes", True):
                        self._check_new_processes()
                    if self._filesystem_enabled():
                        self._check_new_files()
                    if self.settings.get("realtime", "monitor_startup", True):
                        self._check_startup_changes()
                    if self.settings.get("realtime", "monitor_network", True):
                        self._check_network_listeners()
                    if (
                        self.settings.get("realtime", "monitor_removable", True)
                        or self.settings.get("realtime", "monitor_all_drives", False)
                    ):
                        self._check_drives()
            except Exception as exc:
                logger.debug(f"Realtime guard error: {exc}")
            time.sleep(interval)

    # ------------------------------------------------------------------ process
    def _check_new_processes(self):
        current_pids: Set[int] = set()
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid"]):
            try:
                pid = proc.info["pid"]
                current_pids.add(pid)
                if pid in self._seen_pids:
                    continue
                self._seen_pids.add(pid)
                # Children of this application (clamscan, xdg-open, ...) are
                # intentional and must not be reported as untrusted launches.
                if proc.info.get("ppid") == os.getpid():
                    continue
                exe = proc.info.get("exe") or ""
                pname = proc.info.get("name") or ""
                cmdline = " ".join(proc.info.get("cmdline") or [])[:400]
                lower = f"{exe} {cmdline}".lower()
                suspicious_path = any(
                    marker in lower
                    for marker in (
                        "\\appdata\\local\\temp", "\\windows\\temp", "\\temp\\",
                        "\\downloads\\", "\\public\\", "\\$recycle.bin",
                        "/tmp/", "/var/tmp/", "/dev/shm/",
                    )
                )
                suspicious_cmd = any(
                    marker in lower
                    for marker in (
                        "-enc ", "-encodedcommand", "frombase64string",
                        "downloadstring", "invoke-expression", "iex(",
                        "bitsadmin", "certutil -urlcache", "mshta ",
                        "base64 -d", "bash -i", "nc -e", "/dev/shm/",
                    )
                )
                if suspicious_path or suspicious_cmd:
                    severity = "High" if suspicious_cmd else "Medium"
                    self._emit(
                        engine="Real-Time Process Monitor",
                        threat_name=f"Untrusted Process Launched ({pname})",
                        threat_type="Suspicious",
                        severity=severity,
                        description=(
                            f"Process {pname} (PID: {pid}) started from a high-risk location "
                            f"or with an obfuscated command line.\nExecutable: {exe or 'unknown'}\n"
                            f"Command: {cmdline or 'unavailable'}"
                        ),
                        file_path=exe,
                    )
            except Exception:
                continue
        self._seen_pids = current_pids

    # -------------------------------------------------------------------- files
    @staticmethod
    def _iter_files(root: Path, max_depth: int) -> Iterator[Path]:
        stack: List[Tuple[Path, int]] = [(root, 0)]
        while stack:
            current, level = stack.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        try:
                            if entry.is_file(follow_symlinks=False):
                                yield Path(entry.path)
                            elif entry.is_dir(follow_symlinks=False) and level < max_depth:
                                if entry.name.lower() in _SKIP_DIR_NAMES:
                                    continue
                                stack.append((Path(entry.path), level + 1))
                        except OSError:
                            continue
            except (OSError, PermissionError):
                continue

    def _check_new_files(self):
        if len(self._seen_files) > _MAX_TRACKED_FILES:
            # Keep memory bounded; re-seeding is cheap compared to unbounded growth.
            self._seen_files = set(list(self._seen_files)[-_MAX_TRACKED_FILES // 2:])

        max_bytes = int(self.settings.get("realtime", "max_realtime_file_mb", 64)) * 1024 * 1024
        new_candidates = 0
        for root in self._monitored_paths:
            for item in self._iter_files(root, self._scan_depth):
                path_str = str(item)
                if path_str in self._seen_files:
                    continue
                self._seen_files.add(path_str)
                new_candidates += 1
                if new_candidates > _MAX_NEW_FILES_PER_CYCLE:
                    return
                try:
                    if item.suffix.lower() not in EXECUTABLE_EXTENSIONS:
                        if not (
                            _SCAN_EXTENSIONLESS_EXECUTABLES
                            and not item.suffix
                            and os.access(item, os.X_OK)
                        ):
                            continue
                    if item.stat().st_size > max_bytes:
                        continue
                    if self.settings.is_whitelisted(file_path=path_str):
                        continue
                    if str(item).lower().startswith(str(APPDATA_BASE).lower()):
                        continue
                except OSError:
                    continue
                self._scan_file_realtime(path_str)

    def _scan_file_realtime(self, file_path: str):
        try:
            matches = yara_engine.scan_file(file_path)
            if matches:
                threat = matches[0]
                threat["engine"] = "Real-Time Shield (YARA)"
                self.signals.threat_intercepted.emit(threat)
                return

            if file_path.lower().endswith((".exe", ".dll", ".scr")):
                pe_matches = pe_analyzer.analyze(file_path)
                if pe_matches:
                    threat = pe_matches[0]
                    threat["engine"] = "Real-Time Shield (Heuristics)"
                    self.signals.threat_intercepted.emit(threat)
        except Exception as exc:
            logger.debug(f"Real-time scan error on {file_path}: {exc}")

    # ------------------------------------------------------------------ startup
    def _snapshot_startup(self) -> Dict[str, dict]:
        entries: Dict[str, dict] = {}

        if winreg is not None:
            run_keys = (
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            )
            for hive, subkey in run_keys:
                try:
                    with winreg.OpenKey(hive, subkey) as key:
                        index = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, index)
                            except OSError:
                                break
                            index += 1
                            identity = f"registry|{subkey}|{name}"
                            entries[identity] = {
                                "name": name,
                                "command": str(value),
                                "source": subkey,
                            }
                except (OSError, PermissionError):
                    continue

        # Autostart folders exist on every supported platform (Startup folder,
        # ~/.config/autostart, /etc/xdg/autostart, ~/Library/LaunchAgents).
        for directory in all_startup_dirs():
            try:
                for item in directory.iterdir():
                    if item.is_file():
                        identity = f"folder|{directory}|{item.name}"
                        entries[identity] = {
                            "name": item.name,
                            "command": str(item),
                            "source": str(directory),
                        }
            except (OSError, PermissionError):
                continue
        return entries

    def _check_startup_changes(self):
        current = self._snapshot_startup()
        for identity, entry in current.items():
            if identity in self._seen_startup:
                continue
            self._seen_startup.add(identity)
            self._emit(
                engine="Real-Time Startup Monitor",
                threat_name=f"New Startup Persistence Entry ({entry['name']})",
                threat_type="Persistence",
                severity="Medium",
                description=(
                    f"A new auto-start entry was added.\nSource: {entry['source']}\n"
                    f"Command: {entry['command']}"
                ),
                file_path=entry["command"],
            )
        self._seen_startup = set(current.keys())

    # ------------------------------------------------------------------ network
    def _snapshot_listeners(self) -> Set[Tuple[int, int]]:
        listeners: Set[Tuple[int, int]] = set()
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status != psutil.CONN_LISTEN or not conn.laddr:
                    continue
                listeners.add((int(conn.laddr.port), int(conn.pid or 0)))
        except (psutil.AccessDenied, OSError):
            pass
        return listeners

    def _check_network_listeners(self):
        current = self._snapshot_listeners()
        for port, pid in current:
            if (port, pid) in self._seen_listeners:
                continue
            self._seen_listeners.add((port, pid))
            if port in _COMMON_LISTEN_PORTS or pid == os.getpid():
                continue
            name = "Unknown process"
            exe = ""
            try:
                if pid:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    exe = proc.exe()
            except Exception:
                pass
            if name.lower() in _SYSTEM_PROCESS_NAMES:
                continue
            self._emit(
                engine="Real-Time Network Monitor",
                threat_name=f"New Network Listener on Port {port}",
                threat_type="Suspicious",
                severity="Low",
                description=(
                    f"A new service started listening on TCP/UDP port {port}.\n"
                    f"Process: {name} (PID: {pid})\nExecutable: {exe or 'unknown'}\n"
                    "Verify this service is expected; close it if you do not recognise it."
                ),
                file_path=exe,
            )
        self._seen_listeners = current

    # ------------------------------------------------------------------- drives
    @staticmethod
    def _is_removable(root: str) -> bool:
        if IS_WINDOWS:
            try:
                import ctypes
                return ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) == 2
            except Exception:
                return False
        return is_removable_mount(root)

    def _check_drives(self):
        partitions = self._local_partitions()

        if self.settings.get("realtime", "monitor_removable", True):
            removable_now = {
                part.mountpoint for part in partitions
                if self._is_removable(part.mountpoint)
            }
            new_removable = removable_now - self._removable_roots
            removed = self._removable_roots - removable_now
            if new_removable or removed:
                self._removable_roots = set(removable_now)
                self._refresh_monitored_paths()
            for root in sorted(new_removable):
                self._emit(
                    engine="Real-Time Device Monitor",
                    threat_name=f"Removable Drive Connected ({root})",
                    threat_type="Suspicious",
                    severity="Low",
                    description=(
                        f"Removable media was mounted at {root}. "
                        "Fikrado is now watching this volume for new executable files."
                    ),
                    file_path=root,
                )
                self._scan_drive_root(Path(root))

        if self.settings.get("realtime", "monitor_all_drives", False):
            for part in partitions:
                root = part.mountpoint
                if root.lower() in self._seen_drives:
                    continue
                self._seen_drives.add(root.lower())
                self._scan_drive_root(Path(root))

    def _scan_drive_root(self, root: Path):
        try:
            for item in root.iterdir():
                if item.is_file() and item.suffix.lower() in EXECUTABLE_EXTENSIONS:
                    self._scan_file_realtime(str(item))
                    self._seen_files.add(str(item))
        except (OSError, PermissionError):
            pass

    # -------------------------------------------------------------------- utils
    def _emit(self, engine: str, threat_name: str, threat_type: str, severity: str,
              description: str, file_path: str = ""):
        threat = {
            "engine": engine,
            "threat_name": threat_name,
            "threat_type": threat_type,
            "severity": severity,
            "description": description,
            "file_path": file_path,
            "sha256": "",
        }
        if file_path and Path(file_path).is_file():
            try:
                threat["sha256"] = compute_sha256(file_path) or ""
            except Exception:
                pass
        logger.warning("[Real-Time] %s — %s", threat_name, file_path or "n/a")
        self.signals.threat_intercepted.emit(threat)


realtime_guard = RealtimeGuard()
