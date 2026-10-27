"""
Fikrado Security - Loading Feedback
A reusable glass overlay and animated vector spinner used while pages are
created and while slow security data is collected in the background.
"""
from __future__ import annotations

from PySide6.QtCore import QEvent, QRectF, Qt, QTimer
from PySide6.QtGui import QBrush, QColor, QConicalGradient, QPainter, QPen
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget


class SpinnerWidget(QWidget):
    """Compact anti-aliased spinner with a subtle brand-colored gradient."""

    def __init__(self, size: int = 38, color: str = "#88C0D0", line_width: int = 3, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self._color = QColor(color)
        if not self._color.isValid():
            self._color = QColor("#88C0D0")
        self._line_width = max(2, int(line_width))
        self._angle = 0
        self._timer = QTimer(self)
        self._timer.setInterval(16)
        self._timer.timeout.connect(self._advance)

    def start(self):
        if not self._timer.isActive():
            self._timer.start()

    def stop(self):
        self._timer.stop()

    def is_spinning(self) -> bool:
        return self._timer.isActive()

    def _advance(self):
        self._angle = (self._angle + 9) % 360
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        width = self._line_width
        rect = QRectF(
            width / 2.0 + 1.0,
            width / 2.0 + 1.0,
            self.width() - width - 2.0,
            self.height() - width - 2.0,
        )

        track = QColor(self._color)
        track.setAlpha(42)
        painter.setPen(QPen(track, width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawEllipse(rect)

        gradient = QConicalGradient(rect.center(), -self._angle)
        gradient.setColorAt(0.0, QColor("#FFD93D"))
        gradient.setColorAt(0.35, self._color)
        gradient.setColorAt(1.0, QColor(self._color.red(), self._color.green(), self._color.blue(), 0))
        pen = QPen(QBrush(gradient), width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.drawArc(rect, int((90 - self._angle) * 16), -110 * 16)


class LoadingOverlay(QWidget):
    """Semi-transparent overlay that blocks input while content is prepared."""

    def __init__(self, parent: QWidget, message: str = "Loading…"):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._card = QFrame()
        self._card.setObjectName("LoadingCard")
        self._card.setStyleSheet(
            "QFrame#LoadingCard {"
            "  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
            "                              stop:0 rgba(58, 66, 82, 235),"
            "                              stop:1 rgba(30, 36, 47, 242));"
            "  border: 1px solid rgba(255, 255, 255, 42);"
            "  border-top-color: rgba(255, 255, 255, 80);"
            "  border-radius: 16px;"
            "}"
        )
        card_layout = QVBoxLayout(self._card)
        card_layout.setContentsMargins(30, 22, 30, 22)
        card_layout.setSpacing(12)
        card_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.spinner = SpinnerWidget(38, "#88C0D0", 3, self._card)
        card_layout.addWidget(self.spinner, 0, Qt.AlignmentFlag.AlignCenter)

        self._label = QLabel(message)
        self._label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._label.setWordWrap(True)
        self._label.setMaximumWidth(360)
        self._label.setStyleSheet(
            "color: #D8DEE9; font-size: 12px; font-weight: 600; background: transparent;"
        )
        card_layout.addWidget(self._label)

        layout.addWidget(self._card)

        self._parent = parent
        if parent is not None:
            parent.installEventFilter(self)
        self.hide()

    # ------------------------------------------------------------------ paint
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(8, 12, 17, 150))

    # ----------------------------------------------------------------- layout
    def eventFilter(self, obj, event):
        if obj is self._parent and event.type() == QEvent.Type.Resize:
            self.setGeometry(self._parent.rect())
        return super().eventFilter(obj, event)

    # ------------------------------------------------------------------- API
    def show_message(self, message: str | None = None):
        if message:
            self._label.setText(message)
        parent = self._parent
        if parent is not None:
            self.setGeometry(parent.rect())
        self.spinner.start()
        self.raise_()
        self.show()

    def hide_overlay(self):
        self.spinner.stop()
        self.hide()
