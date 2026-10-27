"""
Fikrado Security - Base Scanner Architecture
Provides thread-safe scanner controls, progress reporting, ETA calculation, and cancellation signals.
"""
import time
from typing import Optional
from PySide6.QtCore import QObject, Signal, QThread


class BaseScannerSignals(QObject):
    """Signals emitted during scanning lifecycle."""
    started = Signal(str)                          # scan_type
    progress = Signal(int, int, str, float)        # current, total, current_file, eta_seconds
    threat_found = Signal(dict)                    # threat finding dictionary
    status_message = Signal(str)                   # general status update
    finished = Signal(dict)                        # summary dictionary
    paused = Signal(bool)                          # True if paused, False if resumed
    error = Signal(str)                            # error description


class BaseScannerThread(QThread):
    """Base QThread with pause, resume, and cancellation mechanics."""

    def __init__(self):
        super().__init__()
        self.signals = BaseScannerSignals()
        self._is_cancelled = False
        self._is_paused = False
        self.start_time: float = 0.0
        self.scanned_count: int = 0
        self.total_count: int = 0
        self.threats_found: list = []

    def cancel(self):
        """Requests graceful cancellation."""
        self._is_cancelled = True
        self.signals.status_message.emit("Cancelling scan operation...")

    def pause(self):
        """Pauses scan execution."""
        self._is_paused = True
        self.signals.paused.emit(True)
        self.signals.status_message.emit("Scan paused by user.")

    def resume(self):
        """Resumes paused scan."""
        self._is_paused = False
        self.signals.paused.emit(False)
        self.signals.status_message.emit("Resuming scan...")

    def check_pause_and_cancel(self) -> bool:
        """
        Helper to be called inside worker loops.
        Returns True if cancelled, otherwise waits while paused.
        """
        while self._is_paused:
            if self._is_cancelled:
                return True
            time.sleep(0.1)
        return self._is_cancelled

    def calculate_eta(self) -> float:
        """Estimates remaining seconds based on processing speed."""
        elapsed = time.time() - self.start_time
        if self.scanned_count <= 0 or elapsed <= 0:
            return 0.0
        rate = self.scanned_count / elapsed
        remaining = max(0, self.total_count - self.scanned_count)
        return remaining / rate if rate > 0 else 0.0
