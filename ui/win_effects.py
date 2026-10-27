"""
Fikrado Security - Native Windows 11 Window Chrome

Applies DWM rounded corners, immersive dark mode and a dark window border to the
frameless main window.  All calls are defensive: on Windows 10 (or any failure)
the application simply keeps its painted fallback styling.
"""
from __future__ import annotations

import ctypes
import sys

from PySide6.QtWidgets import QWidget

# Documented DWMWINDOWATTRIBUTE values (SDK 10.0.22621)
_DWMWA_USE_IMMERSIVE_DARK_MODE = 20
_DWMWA_WINDOW_CORNER_PREFERENCE = 33
_DWMWA_BORDER_COLOR = 34

_DWMWCP_ROUND = 2


def _dwm_set(hwnd: int, attribute: int, value: int) -> bool:
    try:
        dwmapi = ctypes.windll.dwmapi
        data = ctypes.c_int(value)
        result = dwmapi.DwmSetWindowAttribute(
            ctypes.c_void_p(hwnd), ctypes.c_uint(attribute),
            ctypes.byref(data), ctypes.sizeof(data),
        )
        return result == 0
    except Exception:
        return False


def apply_window_effects(widget: QWidget) -> bool:
    """Apply rounded corners and dark chrome when supported."""
    if sys.platform != "win32" or widget is None:
        return False
    try:
        hwnd = int(widget.winId())
    except Exception:
        return False
    if not hwnd:
        return False

    applied = False
    applied |= _dwm_set(hwnd, _DWMWA_USE_IMMERSIVE_DARK_MODE, 1)
    applied |= _dwm_set(hwnd, _DWMWA_WINDOW_CORNER_PREFERENCE, _DWMWCP_ROUND)
    # COLORREF is 0x00BBGGRR.  Deep blue-black border around the glass shell.
    applied |= _dwm_set(hwnd, _DWMWA_BORDER_COLOR, 0x002C241C)
    return applied
