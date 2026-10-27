"""
Fikrado Security - Background Workers
Small QThread helpers that keep slow system queries off the UI thread.
"""
from __future__ import annotations

from typing import Any, Callable

from PySide6.QtCore import QThread, Signal


class FunctionWorker(QThread):
    """Runs a callable in a worker thread and emits its result or error."""

    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(self, fn: Callable[[], Any], parent=None):
        super().__init__(parent)
        self._fn = fn

    def run(self):
        try:
            result = self._fn()
        except Exception as exc:  # pragma: no cover - defensive boundary
            self.failed.emit(str(exc))
            return
        self.finished_ok.emit(result)
