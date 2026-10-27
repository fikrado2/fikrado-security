"""
Fikrado Security - Toast Notification Component
Renders smooth non-blocking popup alerts at the bottom right of the main window.
"""
from PySide6.QtCore import QEasingCurve, QPoint, QPropertyAnimation, Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget
)
from ui.icons import icon_label, load_icon


class ToastNotification(QFrame):

    def __init__(self, parent: QWidget, title: str, message: str, level: str = "info", duration_ms: int = 4000):
        super().__init__(parent)
        self.setObjectName("ToastCard")
        self.setWindowFlags(Qt.SubWindow | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_ShowWithoutActivating)

        color_map = {
            "success": ("#A3BE8C", "check"),
            "warning": ("#EBCB8B", "warning"),
            "error": ("#BF616A", "cancel"),
            "info": ("#88C0D0", "info"),
        }
        accent_color, icon_name = color_map.get(level.lower(), ("#88C0D0", "info"))

        self.setStyleSheet(f"""
            QFrame#ToastCard {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                            stop:0 rgba(60, 68, 84, 246),
                                            stop:0.5 rgba(46, 53, 66, 246),
                                            stop:1 rgba(34, 40, 51, 248));
                border: 1px solid rgba(255, 255, 255, 30);
                border-top-color: rgba(255, 255, 255, 55);
                border-bottom-color: rgba(0, 0, 0, 120);
                border-left: 3px solid {accent_color};
                border-radius: 14px;
            }}
        """)

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(26)
        shadow.setColor(QColor(0, 0, 0, 165))
        shadow.setOffset(0, 7)
        self.setGraphicsEffect(shadow)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(12)

        # Icon Label
        icon_lbl = icon_label(icon_name, 22)
        layout.addWidget(icon_lbl)

        # Text Layout
        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("color: #ECEFF4; font-weight: 700; font-size: 13px; background: transparent;")
        text_layout.addWidget(title_lbl)

        msg_lbl = QLabel(message)
        msg_lbl.setStyleSheet("color: #D8DEE9; font-size: 12px; background: transparent;")
        msg_lbl.setWordWrap(True)
        text_layout.addWidget(msg_lbl)

        layout.addLayout(text_layout)

        # Close button
        close_btn = QPushButton()
        close_btn.setStyleSheet("background: transparent; border: none;")
        close_btn.setIcon(load_icon("close", 10, "#9BA3AF"))
        close_btn.setFixedSize(20, 20)
        close_btn.setCursor(Qt.PointingHandCursor)
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
        self._animate_in()

    def _animate_in(self):
        """Slides the toast in from the right for a smoother entrance."""
        final_pos = self.pos()
        start_pos = QPoint(final_pos.x() + 28, final_pos.y())
        self.move(start_pos)
        self._slide_anim = QPropertyAnimation(self, b"pos", self)
        self._slide_anim.setDuration(240)
        self._slide_anim.setStartValue(start_pos)
        self._slide_anim.setEndValue(final_pos)
        self._slide_anim.setEasingCurve(QEasingCurve.OutCubic)
        self._slide_anim.start()

    def _reposition(self):
        if self.parent():
            p_geom = self.parent().geometry()
            x = p_geom.width() - self.width() - 25
            y = p_geom.height() - self.height() - 25
            self.move(x, y)
