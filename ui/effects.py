"""
Fikrado Security - Visual Effects
Reusable helpers for ambient text glow, pulsing highlights, and smooth fades.
"""
import re

from PySide6.QtCore import QEasingCurve, QPropertyAnimation
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QGraphicsDropShadowEffect,
    QGraphicsOpacityEffect,
    QHeaderView,
    QLabel,
    QTableWidget,
    QWidget,
)

_COLOR_RE = re.compile(r"color\s*:\s*(#[0-9A-Fa-f]{6})")
_FONT_SIZE_RE = re.compile(r"font-size\s*:\s*(\d+)px")
_BOLD_RE = re.compile(r"font-weight\s*:\s*(?:bold|[6-9]00)", re.IGNORECASE)


def apply_text_glow(widget, color: str = "#88C0D0", blur: int = 18, opacity: int = 150):
    """Attach a soft zero-offset drop shadow that reads as a text glow."""
    if widget is None:
        return None

    glow = QColor(color)
    if not glow.isValid():
        glow = QColor("#88C0D0")
    glow.setAlpha(max(0, min(255, opacity)))

    effect = QGraphicsDropShadowEffect(widget)
    effect.setBlurRadius(blur)
    effect.setOffset(0, 0)
    effect.setColor(glow)
    widget.setGraphicsEffect(effect)
    return effect


def update_glow(widget, color: str, opacity: int = 150):
    """Recolor an existing glow effect without replacing it."""
    effect = widget.graphicsEffect() if widget is not None else None
    if not isinstance(effect, QGraphicsDropShadowEffect):
        return None

    glow = QColor(color)
    if not glow.isValid():
        return effect
    glow.setAlpha(max(0, min(255, opacity)))
    effect.setColor(glow)
    return effect


def pulse_glow(effect, min_blur: int = 14, max_blur: int = 30, duration: int = 2200):
    """Breathing glow animation for logos and status indicators."""
    if effect is None:
        return None

    anim = QPropertyAnimation(effect, b"blurRadius", effect)
    anim.setDuration(duration)
    anim.setKeyValueAt(0.0, float(min_blur))
    anim.setKeyValueAt(0.5, float(max_blur))
    anim.setKeyValueAt(1.0, float(min_blur))
    anim.setEasingCurve(QEasingCurve.InOutSine)
    anim.setLoopCount(-1)
    anim.start()
    return anim


def fade_in(widget, duration: int = 240):
    """Fade a page or panel in with a smooth ease-out curve."""
    if widget is None:
        return None

    previous = getattr(widget, "_fikrado_fade", None)
    if previous is not None:
        previous.stop()
        previous.deleteLater()
        widget._fikrado_fade = None

    effect = QGraphicsOpacityEffect(widget)
    effect.setOpacity(0.0)
    widget.setGraphicsEffect(effect)

    anim = QPropertyAnimation(effect, b"opacity", widget)
    anim.setDuration(duration)
    anim.setStartValue(0.0)
    anim.setEndValue(1.0)
    anim.setEasingCurve(QEasingCurve.OutCubic)

    def _finish():
        # Release the temporary effect so the page paints natively again.
        widget.setGraphicsEffect(None)
        widget._fikrado_fade = None

    anim.finished.connect(_finish)
    widget._fikrado_fade = anim
    anim.start()
    return anim


def _inline_color(label: QLabel) -> str:
    match = _COLOR_RE.search(label.styleSheet() or "")
    if match:
        return match.group(1)
    return label.palette().color(label.foregroundRole()).name()


def _is_headline(label: QLabel) -> bool:
    pixmap = label.pixmap()
    if pixmap is not None and not pixmap.isNull():
        return False
    if not label.text().strip():
        return False

    parent = label.parentWidget()
    while parent is not None:
        if isinstance(parent, (QTableWidget, QHeaderView, QComboBox, QAbstractItemView)):
            return False
        parent = parent.parentWidget()

    sheet = label.styleSheet() or ""
    size_match = _FONT_SIZE_RE.search(sheet)
    if not size_match:
        return False

    size = int(size_match.group(1))
    if size >= 18:
        return True
    return size >= 15 and bool(_BOLD_RE.search(sheet))


def decorate_text_glow(root: QWidget, opacity: int = 115) -> int:
    """Apply ambient glow to headline, stat, and section labels under *root*."""
    if root is None:
        return 0

    count = 0
    for label in root.findChildren(QLabel):
        if label.graphicsEffect() is not None:
            continue
        if not _is_headline(label):
            continue

        size_match = _FONT_SIZE_RE.search(label.styleSheet() or "")
        size = int(size_match.group(1)) if size_match else 16
        blur = 10 if size < 18 else 14 if size < 24 else 18
        apply_text_glow(label, _inline_color(label), blur=blur, opacity=opacity)
        count += 1
    return count
