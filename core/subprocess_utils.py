"""
Fikrado Security - Hidden Subprocess Helpers

Every external command (PowerShell, netsh, winget, schtasks, ClamAV, ...) must run
without flashing a console window.  All subprocess usage in the application goes
through these wrappers so the Windows ``CREATE_NO_WINDOW`` contract is enforced in
one place.
"""
from __future__ import annotations

import subprocess
import sys
from typing import Any, Sequence

CREATE_NO_WINDOW = 0x08000000
STARTF_USESHOWWINDOW = 0x00000001
SW_HIDE = 0


def _startup_info() -> "subprocess.STARTUPINFO | None":
    if sys.platform != "win32":
        return None
    info = subprocess.STARTUPINFO()
    info.dwFlags |= STARTF_USESHOWWINDOW
    info.wShowWindow = SW_HIDE
    return info


def hidden_creationflags() -> int:
    """Return the platform creation flags that suppress a console window."""
    return CREATE_NO_WINDOW if sys.platform == "win32" else 0


def _apply_hidden(kwargs: dict[str, Any]) -> dict[str, Any]:
    if sys.platform == "win32":
        kwargs.setdefault("creationflags", CREATE_NO_WINDOW)
        kwargs.setdefault("startupinfo", _startup_info())
    return kwargs


def run_hidden(args: Sequence[str] | str, **kwargs: Any) -> subprocess.CompletedProcess:
    """Drop-in replacement for ``subprocess.run`` that never opens a console."""
    if "stdout" not in kwargs and "stderr" not in kwargs:
        kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    _apply_hidden(kwargs)
    return subprocess.run(args, **kwargs)


def popen_hidden(args: Sequence[str] | str, **kwargs: Any) -> subprocess.Popen:
    """Drop-in replacement for ``subprocess.Popen`` that never opens a console."""
    _apply_hidden(kwargs)
    return subprocess.Popen(args, **kwargs)


def call_hidden(args: Sequence[str] | str, **kwargs: Any) -> int:
    """Drop-in replacement for ``subprocess.call`` that never opens a console."""
    _apply_hidden(kwargs)
    return subprocess.call(args, **kwargs)


def check_output_hidden(args: Sequence[str] | str, **kwargs: Any) -> bytes | str:
    """Drop-in replacement for ``subprocess.check_output`` that never opens a console."""
    kwargs.setdefault("text", True)
    _apply_hidden(kwargs)
    return subprocess.check_output(args, **kwargs)
