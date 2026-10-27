"""
Fikrado Security - Ambient Background

Paints the layered deep-space gradient, coloured aurora blooms and a soft vignette
that the glass surfaces sit on top of.  Painting is resolution independent and
re-runs on every resize.
"""
from __future__ import annotations

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPen, QRadialGradient
from PySide6.QtWidgets import QWidget


class AmbientBackground(QWidget):
    """Central canvas with a premium glass-friendly backdrop."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("AppRoot")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)
        self.setAutoFillBackground(False)

    def paintEvent(self, event):  # noqa: N802 - Qt naming
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        rect = self.rect()
        width = max(1, rect.width())
        height = max(1, rect.height())

        # 1. Base diagonal gradient: near-black blue to graphite.
        base = QLinearGradient(0, 0, width, height)
        base.setColorAt(0.0, QColor("#1B2029"))
        base.setColorAt(0.45, QColor("#232A35"))
        base.setColorAt(1.0, QColor("#151A21"))
        painter.fillRect(rect, base)

        # 2. Aurora blooms (colour, position, radius, alpha).
        blooms = (
            ("#5E81AC", 0.10, -0.05, 0.62, 52),
            ("#88C0D0", 0.22, 0.02, 0.42, 34),
            ("#FFD93D", 0.96, 0.06, 0.46, 20),
            ("#A3BE8C", 0.52, 1.02, 0.50, 18),
            ("#B48EAD", 0.88, 0.92, 0.36, 16),
        )
        for color, fx, fy, fr, alpha in blooms:
            center = QPointF(width * fx, height * fy)
            radius = max(width, height) * fr
            glow = QRadialGradient(center, radius)
            inner = QColor(color)
            inner.setAlpha(alpha)
            middle = QColor(color)
            middle.setAlpha(max(4, alpha // 3))
            glow.setColorAt(0.0, inner)
            glow.setColorAt(0.45, middle)
            glow.setColorAt(1.0, QColor(0, 0, 0, 0))
            painter.fillRect(rect, glow)

        # 3. Vignette to pull focus toward the centre content.
        vignette = QRadialGradient(
            QPointF(width * 0.5, height * 0.46), max(width, height) * 0.78
        )
        vignette.setColorAt(0.0, QColor(0, 0, 0, 0))
        vignette.setColorAt(0.62, QColor(0, 0, 0, 0))
        vignette.setColorAt(1.0, QColor(0, 0, 0, 104))
        painter.fillRect(rect, vignette)

        # 4. Hairline top highlight for the 3D window edge.
        painter.setPen(QPen(QColor(255, 255, 255, 22), 1))
        painter.drawLine(0, 0, width, 0)
        painter.setPen(QPen(QColor(0, 0, 0, 120), 1))
        painter.drawLine(0, height - 1, width, height - 1)
        painter.end()
