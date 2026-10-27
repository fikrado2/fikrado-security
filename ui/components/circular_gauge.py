"""
Fikrado Security - Circular Security Score Gauge Widget
Animates a glowing circular progress arc with Nord aurora colors and brand gradient.
"""
from PySide6.QtCore import Property, QEasingCurve, QPointF, QRectF, Qt, QTimeLine
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontMetricsF,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
)
from PySide6.QtWidgets import QWidget


class CircularSecurityGauge(QWidget):
    """Modern circular gauge displaying system security health score (0-100)."""

    def __init__(self, parent=None, size: int = 190):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self._score = 0
        self._target_score = 88
        self._timeline = QTimeLine(1200, self)
        self._timeline.setEasingCurve(QEasingCurve(QEasingCurve.OutCubic))
        self._timeline.setUpdateInterval(16)
        self._timeline.frameChanged.connect(self._on_animation_frame)

        # Build the fonts once.  ``setFamilies()`` with a fallback list is very
        # expensive on first paint (seconds on some Windows font stacks), so we
        # request a single family and let Qt substitute if it is unavailable.
        self._score_font = QFont("Segoe UI Variable Display")
        self._score_font.setPointSize(34)
        self._score_font.setBold(True)

        self._caption_font = QFont("Segoe UI")
        self._caption_font.setPointSize(8)
        self._caption_font.setBold(True)

        self._badge_font = QFont("Segoe UI")
        self._badge_font.setPointSize(7)
        self._badge_font.setBold(True)

    def get_score(self) -> int:
        return self._score

    def set_score(self, val: int, animated: bool = True):
        val = max(0, min(100, val))
        self._target_score = val
        if animated:
            self._timeline.stop()
            self._timeline.setFrameRange(self._score, val)
            self._timeline.start()
        else:
            self._score = val
            self.update()

    def _on_animation_frame(self, frame: int):
        self._score = frame
        self.update()

    score = Property(int, get_score, set_score)

    def _tier_palette(self):
        if self._score >= 80:
            return QColor("#FFD93D"), QColor("#88C0D0"), "PROTECTED", QColor("#A3BE8C")
        if self._score >= 50:
            return QColor("#D08770"), QColor("#EBCB8B"), "NEEDS AUDIT", QColor("#EBCB8B")
        return QColor("#BF616A"), QColor("#D08770"), "AT RISK", QColor("#BF616A")

    def _draw_glow_text(self, painter: QPainter, rect: QRectF, text: str,
                        font: QFont, color: QColor, glow_color: QColor):
        """Draws centered text with a layered halo for a true glow effect."""
        metrics = QFontMetricsF(font)
        text_width = metrics.horizontalAdvance(text)
        baseline = rect.center().y() + (metrics.ascent() - metrics.descent()) / 2.0

        path = QPainterPath()
        path.addText(rect.center().x() - text_width / 2.0, baseline, font, text)

        for stroke_width, alpha in ((10, 14), (7, 26), (4, 48)):
            pen = QPen(
                QColor(glow_color.red(), glow_color.green(), glow_color.blue(), alpha),
                stroke_width,
            )
            pen.setJoinStyle(Qt.RoundJoin)
            painter.setPen(pen)
            painter.setBrush(Qt.NoBrush)
            painter.drawPath(path)

        painter.setPen(Qt.NoPen)
        painter.setBrush(color)
        painter.drawPath(path)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setRenderHint(QPainter.TextAntialiasing)

        width = self.width()
        height = self.height()
        center = QPointF(width / 2.0, height / 2.0)
        margin = 15
        rect = QRectF(margin, margin, width - 2 * margin, height - 2 * margin)

        # 1. Soft ambient halo behind the ring
        halo = QRadialGradient(center, width / 2.0)
        halo.setColorAt(0.0, QColor(136, 192, 208, 16))
        halo.setColorAt(0.68, QColor(136, 192, 208, 9))
        halo.setColorAt(1.0, QColor(136, 192, 208, 0))
        painter.setPen(Qt.NoPen)
        painter.setBrush(halo)
        painter.drawEllipse(QRectF(2, 2, width - 4, height - 4))

        # 2. Background track
        track_pen = QPen(QColor(59, 66, 82, 220), 11)
        track_pen.setCapStyle(Qt.RoundCap)
        painter.setPen(track_pen)
        painter.drawArc(rect, 90 * 16, -360 * 16)

        # 3. Foreground score arc with layered glow
        if self._score > 0:
            start_c, end_c, badge_text, badge_color = self._tier_palette()
            span_angle = -int((self._score / 100.0) * 360 * 16)

            for extra_width, alpha in ((14, 16), (9, 30), (4, 52)):
                glow_grad = QLinearGradient(rect.topLeft(), rect.bottomRight())
                glow_grad.setColorAt(0.0, QColor(start_c.red(), start_c.green(), start_c.blue(), alpha))
                glow_grad.setColorAt(1.0, QColor(end_c.red(), end_c.green(), end_c.blue(), alpha))
                glow_pen = QPen(glow_grad, 11 + extra_width)
                glow_pen.setCapStyle(Qt.RoundCap)
                painter.setPen(glow_pen)
                painter.drawArc(rect, 90 * 16, span_angle)

            gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
            gradient.setColorAt(0.0, start_c)
            gradient.setColorAt(1.0, end_c)
            arc_pen = QPen(gradient, 11)
            arc_pen.setCapStyle(Qt.RoundCap)
            painter.setPen(arc_pen)
            painter.drawArc(rect, 90 * 16, span_angle)
        else:
            badge_text = "UNKNOWN"
            badge_color = QColor("#9BA3AF")

        # 4. Center score with a soft cyan halo
        self._draw_glow_text(
            painter,
            QRectF(0, height * 0.235, width, 54),
            str(self._score),
            self._score_font,
            QColor("#ECEFF4"),
            QColor("#88C0D0"),
        )

        # 5. Caption
        painter.setPen(QColor("#9BA3AF"))
        painter.setFont(self._caption_font)
        painter.drawText(QRectF(0, height * 0.52, width, 18), Qt.AlignCenter, "SECURITY SCORE")

        # 6. Status badge pill
        badge_rect = QRectF(width / 2.0 - 46, height * 0.665, 92, 21)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(badge_color.red(), badge_color.green(), badge_color.blue(), 26))
        painter.drawRoundedRect(badge_rect, 10, 10)
        painter.setPen(badge_color)
        painter.setFont(self._badge_font)
        painter.drawText(badge_rect, Qt.AlignCenter, badge_text)
