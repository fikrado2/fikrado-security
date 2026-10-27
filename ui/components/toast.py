"""
Fikrado Security - Toast Notification Component
Renders smooth non-blocking popup alerts at the bottom right of the main window.
"""
from PySide6.QtCore import QPoint, Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget
)


class ToastNotification(QFrame):

    def __init__(self, parent: QWidget, title: str, message: str, level: str = "info", duration_ms: int = 4000):
        super().__init__(parent)
        self.setWindowFlags(Qt.SubWindow | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_ShowWithoutActivating)

        color_map = {
            "success": ("#A3BE8C", "✔"),
            "warning": ("#EBCB8B", "⚠"),
            "error": ("#BF616A", "✖"),
            "info": ("#88C0D0", "ℹ"),
        }
        accent_color, icon_symbol = color_map.get(level.lower(), ("#88C0D0", "ℹ"))

        self.setStyleSheet(f"""
            QFrame {{
                background-color: #3B4252;
                border: 1px solid #4C566A;
                border-left: 5px solid {accent_color};
                border-radius: 8px;
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(12)

        # Icon Label
        icon_lbl = QLabel(icon_symbol)
        icon_lbl.setStyleSheet(f"color: {accent_color}; font-size: 18px; font-weight: bold;")
        layout.addWidget(icon_lbl)

        # Text Layout
        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("color: #ECEFF4; font-weight: bold; font-size: 13px;")
        text_layout.addWidget(title_lbl)

        msg_lbl = QLabel(message)
        msg_lbl.setStyleSheet("color: #D8DEE9; font-size: 12px;")
        msg_lbl.setWordWrap(True)
        text_layout.addWidget(msg_lbl)

        layout.addLayout(text_layout)

        # Close button
        close_btn = QPushButton("×")
        close_btn.setStyleSheet("background: transparent; border: none; color: #9BA3AF; font-size: 16px;")
        close_btn.setFixedSize(20, 20)
        close_btn.clicked.connect(self.hide)
        layout.addWidget(close_btn)

        self.setFixedWidth(360)
        self.adjustSize()

        # Reposition to bottom-right of parent
        self._reposition()

        # Auto-dismiss timer
        if duration_ms > 0:
            QTimer.singleShot(duration_ms, self.hide)

        self.show()

    def _reposition(self):
        if self.parent():
            p_geom = self.parent().geometry()
            x = p_geom.width() - self.width() - 25
            y = p_geom.height() - self.height() - 25
            self.move(x, y)
