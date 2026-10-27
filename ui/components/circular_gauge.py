"""
Fikrado Security - Circular Security Score Gauge Widget
Animates a circular progress arc with Nord aurora colors and brand gradient.
"""
from PySide6.QtCore import Property, QPointF, QRectF, Qt, QTimeLine
from PySide6.QtGui import QColor, QConicalGradient, QFont, QLinearGradient, QPainter, QPen
from PySide6.QtWidgets import QWidget


class CircularSecurityGauge(QWidget):
    """Modern circular gauge displaying system security health score (0-100)."""

    def __init__(self, parent=None, size: int = 190):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self._score = 0
        self._target_score = 88
        self._timeline = QTimeLine(1200, self)
        self._timeline.frameChanged.connect(self._on_animation_frame)

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

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        width = self.width()
        height = self.height()
        margin = 14
        rect = QRectF(margin, margin, width - 2 * margin, height - 2 * margin)

        # 1. Background Track
        track_pen = QPen(QColor("#3B4252"), 12)
        track_pen.setCapStyle(Qt.RoundCap)
        painter.setPen(track_pen)
        painter.drawArc(rect, -90 * 16, -360 * 16)

        # 2. Foreground Score Arc
        if self._score > 0:
            span_angle = -int((self._score / 100.0) * 360 * 16)

            # Choose color gradient based on score tier
            if self._score >= 80:
                start_c = QColor("#FFD93D")  # Brand Yellow
                end_c = QColor("#88C0D0")    # Brand Frost Cyan
                badge_text = "PROTECTED"
                badge_color = QColor("#A3BE8C")
            elif self._score >= 50:
                start_c = QColor("#D08770")  # Aurora Orange
                end_c = QColor("#EBCB8B")    # Aurora Yellow
                badge_text = "NEEDS AUDIT"
                badge_color = QColor("#EBCB8B")
            else:
                start_c = QColor("#BF616A")  # Aurora Red
                end_c = QColor("#D08770")    # Aurora Orange
                badge_text = "AT RISK"
                badge_color = QColor("#BF616A")

            gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
            gradient.setColorAt(0.0, start_c)
            gradient.setColorAt(1.0, end_c)

            arc_pen = QPen(gradient, 12)
            arc_pen.setCapStyle(Qt.RoundCap)
            painter.setPen(arc_pen)
            painter.drawArc(rect, 90 * 16, span_angle)
        else:
            badge_text = "UNKNOWN"
            badge_color = QColor("#9BA3AF")

        # 3. Center Score Text
        painter.setPen(QColor("#ECEFF4"))
        font_score = QFont("Segoe UI", 32, QFont.Bold)
        painter.setFont(font_score)
        painter.drawText(QRectF(0, height * 0.24, width, 45), Qt.AlignCenter, str(self._score))

        # 4. "/100" Subtitle
        painter.setPen(QColor("#9BA3AF"))
        font_sub = QFont("Segoe UI", 11)
        painter.setFont(font_sub)
        painter.drawText(QRectF(0, height * 0.52, width, 20), Qt.AlignCenter, "SECURITY SCORE")

        # 5. Status Badge Pill
        painter.setPen(badge_color)
        font_badge = QFont("Segoe UI", 10, QFont.Bold)
        painter.setFont(font_badge)
        painter.drawText(QRectF(0, height * 0.68, width, 20), Qt.AlignCenter, badge_text)
