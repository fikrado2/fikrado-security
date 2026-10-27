"""
Fikrado Security - Colored Vector Icon Loader

Loads the generated SVG icon set from ``assets/icons`` and renders it at a crisp
device-pixel-ratio aware size.  Icons are real vectors (no emoji fonts), which
keeps the UI identical on every Windows machine.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from PySide6.QtCore import QByteArray, QSize, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QAbstractButton, QLabel

from config.constants import ICONS_DIR

# Palette used by scripts/generate_icons.py.  Used for monochrome tinting.
_PALETTE = (
    "#88C0D0", "#A3BE8C", "#EBCB8B", "#FFD93D", "#BF616A",
    "#D08770", "#B48EAD", "#9BA3AF", "#ECEFF4", "#FFFFFF",
    "#0A66C2",
)

_DEFAULT_DPR = 2.0


def icon_path(name: str) -> Path:
    """Resolve an icon name (with or without ``.svg``) to its file."""
    filename = name if name.endswith(".svg") else f"{name}.svg"
    return ICONS_DIR / filename


def icon_exists(name: str) -> bool:
    return icon_path(name).exists()


@lru_cache(maxsize=256)
def _render_svg(name: str, size: int, tint: str | None, dpr: float) -> QPixmap:
    path = icon_path(name)
    pixmap = QPixmap(int(size * dpr), int(size * dpr))
    pixmap.fill(Qt.GlobalColor.transparent)
    if not path.exists():
        return pixmap

    if tint:
        svg = path.read_text(encoding="utf-8")
        for color in _PALETTE:
            svg = svg.replace(color, tint)
            svg = svg.replace(color.lower(), tint)
        renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    else:
        renderer = QSvgRenderer(str(path))

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
    renderer.render(painter)
    painter.end()
    pixmap.setDevicePixelRatio(dpr)
    return pixmap


def icon_pixmap(name: str, size: int = 24, tint: str | None = None, dpr: float = _DEFAULT_DPR) -> QPixmap:
    """Render an SVG icon into a crisp pixmap."""
    return _render_svg(name, int(size), tint, float(dpr))


@lru_cache(maxsize=256)
def _build_icon(name: str, size: int, tint: str | None) -> QIcon:
    """Cache assembled QIcons because each one renders three pixmap scales."""
    icon = QIcon()
    for scale in (1.0, 2.0, 3.0):
        icon.addPixmap(_render_svg(name, int(size), tint, scale))
    return icon


def load_icon(name: str, size: int = 24, tint: str | None = None) -> QIcon:
    """Build a multi-resolution QIcon from the vector source (cached)."""
    return _build_icon(name, int(size), tint)


def set_icon(button: QAbstractButton, name: str, size: int = 18, tint: str | None = None) -> None:
    """Attach a vector icon to any button without changing its text."""
    if button is None:
        return
    button.setIcon(load_icon(name, size, tint))
    button.setIconSize(QSize(size, size))


def icon_label(name: str, size: int = 24, tint: str | None = None) -> QLabel:
    """Create a transparent QLabel displaying a vector icon."""
    label = QLabel()
    label.setPixmap(icon_pixmap(name, size, tint))
    label.setFixedSize(size, size)
    label.setStyleSheet("background: transparent; border: none;")
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    return label


def refresh_icon_label(label: QLabel, name: str, size: int = 24, tint: str | None = None) -> None:
    if label is None:
        return
    label.setPixmap(icon_pixmap(name, size, tint))
