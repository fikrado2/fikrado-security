"""
Fikrado Security - Real-Time Protection Shield
Monitors high-risk directories (Downloads, Temp) and newly spawned processes in real time.
"""
import os
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional
import psutil
from PySide6.QtCore import QObject, Signal
from config.settings import SettingsManager
from core.logger import logger
from scanners.malware_scanner import compute_sha256
from scanners.pe_analyzer import pe_analyzer
from scanners.yara_engine import yara_engine


class RealtimeGuardSignals(QObject):
    threat_intercepted = Signal(dict)
    guard_status_changed = Signal(bool, str)


class RealtimeGuard(threading.Thread):
    """Background monitoring thread for real-time filesystem and process surveillance."""

    def __init__(self):
        super().__init__(daemon=True, name="RealtimeGuardThread")
        self.signals = RealtimeGuardSignals()
        self.settings = SettingsManager()
        self._running = False
        self._seen_pids = set()
        self._seen_files = set()
        self.monitored_paths = [
            Path(os.path.expanduser("~/Downloads")),
            Path(os.getenv("TEMP", "")),
        ]

    def start_guard(self):
        """Starts real-time monitoring."""
        if self._running:
            return
        self._running = True
        # Populate initial PIDs and file mtimes
        for p in psutil.process_iter(["pid"]):
            self._seen_pids.add(p.info["pid"])
        for p in self.monitored_paths:
            if p.exists():
                try:
                    for f in p.iterdir():
                        if f.is_file():
                            self._seen_files.add(str(f))
                except Exception:
                    pass

        self.start()
        self.signals.guard_status_changed.emit(True, "Real-Time Protection is Active.")
        logger.info("Real-Time Protection guard started.")

    def stop_guard(self):
        self._running = False
        self.signals.guard_status_changed.emit(False, "Real-Time Protection is Paused.")
        logger.info("Real-Time Protection guard stopped.")

    def run(self):
        while self._running:
            try:
                if self.settings.get("realtime", "enabled", True):
                    if self.settings.get("realtime", "monitor_processes", True):
                        self._check_new_processes()
                    if self.settings.get("realtime", "scan_downloads", True):
                        self._check_new_files()
            except Exception as e:
                logger.debug(f"Realtime guard error: {e}")

            time.sleep(self.settings.get("realtime", "check_interval_seconds", 3))

    def _check_new_processes(self):
        """Detects newly started processes and performs reputation inspection."""
        current_pids = set()
        for p in psutil.process_iter(["pid", "name", "exe"]):
            try:
                pid = p.info["pid"]
                current_pids.add(pid)
                if pid not in self._seen_pids:
                    self._seen_pids.add(pid)
                    exe = p.info.get("exe") or ""
                    pname = p.info.get("name") or ""
                    # Check if running from Temp
                    if exe and ("\\appdata\\local\\temp" in exe.lower() or "\\temp\\" in exe.lower()):
                        threat = {
                            "engine": "Real-Time Process Monitor",
                            "threat_name": f"Untrusted Process Launched from Temp ({pname})",
                            "threat_type": "Suspicious",
                            "severity": "High",
                            "description": f"Process {pname} (PID: {pid}) was initiated from temporary directory: {exe}",
                            "file_path": exe
                        }
                        self.signals.threat_intercepted.emit(threat)
            except Exception:
                continue
        # Clean up exited PIDs
        self._seen_pids = current_pids

    def _check_new_files(self):
        """Scans new files downloaded or dropped into monitored folders."""
        for root in self.monitored_paths:
            if not root.exists():
                continue
            try:
                for item in root.iterdir():
                    if item.is_file():
                        p_str = str(item)
                        if p_str not in self._seen_files:
                            self._seen_files.add(p_str)
                            # Inspect if executable or script
                            ext = item.suffix.lower()
                            if ext in (".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".scr"):
                                self._scan_file_realtime(p_str)
            except Exception:
                continue

    def _scan_file_realtime(self, file_path: str):
        """Runs fast real-time scan on newly dropped file."""
        try:
            # Check YARA
            y_matches = yara_engine.scan_file(file_path)
            if y_matches:
                t = y_matches[0]
                t["engine"] = "Real-Time Shield (YARA)"
                self.signals.threat_intercepted.emit(t)
                return

            # Check PE Heuristics
            if file_path.lower().endswith(".exe"):
                pe_matches = pe_analyzer.analyze(file_path)
                if pe_matches:
                    t = pe_matches[0]
                    t["engine"] = "Real-Time Shield (Heuristics)"
                    self.signals.threat_intercepted.emit(t)
        except Exception as e:
            logger.debug(f"Real-time scan error on {file_path}: {e}")


realtime_guard = RealtimeGuard()
