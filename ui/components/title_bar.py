"""
Fikrado Security - Native Windows 11 Style Title Bar
Replicates the native Windows 11 title bar appearance with proper dimensions,
hover behavior, and system integration.
"""
from PySide6.QtCore import QPoint, QSize, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QWidget,
)

from config.constants import APP_VERSION, LOGO_PNG
from core.system_info import is_admin


class NativeTitleButton(QPushButton):
    """A single window control button styled like native Windows 11."""

    def __init__(self, icon_name: str, parent=None):
        super().__init__(parent)
        self._icon_name = icon_name
        self._hover_color = QColor(255, 255, 255, 16)
        self._icon_color = QColor(236, 239, 244)
        self._is_close = icon_name == "close"

        if self._is_close:
            self._hover_color = QColor(196, 43, 28)  # Windows 11 close red

        self.setFixedSize(46, 32)
        self.setCursor(Qt.PointingHandCursor)
        self._render_icon()

    def _render_icon(self):
        """Render the icon as a pixmap with the current color."""
        size = 10
        pixmap = QPixmap(size * 2, size * 2)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(self._icon_color)
        painter.setBrush(Qt.BrushStyle.NoBrush)

        # Draw the icon based on type
        w, h = size, size
        if self._icon_name == "minimize":
            painter.drawLine(0, h // 2, w, h // 2)
        elif self._icon_name == "maximize":
            painter.drawRect(1, 1, w - 2, h - 2)
        elif self._icon_name == "restore":
            # Two overlapping rectangles
            painter.drawRect(3, 1, w - 3, h - 3)
            painter.drawRect(1, 3, w - 3, h - 3)
        elif self._icon_name == "close":
            painter.drawLine(1, 1, w - 1, h - 1)
            painter.drawLine(w - 1, 1, 1, h - 1)

        painter.end()
        pixmap.setDevicePixelRatio(2.0)
        self.setIcon(QIcon(pixmap))
        self.setIconSize(QSize(size, size))

    def enterEvent(self, event):
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {self._hover_color.name(QColor.NameFormat.HexArgb)};
                border: none;
                border-radius: 0px;
            }}
        """)
        if self._is_close:
            self._icon_color = QColor(255, 255, 255)
            self._render_icon()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
                border-radius: 0px;
            }
        """)
        if self._is_close:
            self._icon_color = QColor(236, 239, 244)
            self._render_icon()
        super().leaveEvent(event)


class CustomTitleBar(QFrame):
    """
    Native Windows 11 style title bar.
    Height: 48px (standard Windows 11 caption height)
    Buttons: 46x32px each (standard Windows 11 caption button size)
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.setObjectName("TitleBar")
        self.setFixedHeight(48)
        self.setStyleSheet("""
            QFrame#TitleBar {
                background: transparent;
                border-bottom: 1px solid rgba(255, 255, 255, 8);
            }
            QPushButton {
                background: transparent;
                border: none;
                border-radius: 0px;
                color: #ECEFF4;
            }
        """)
        self._drag_pos = QPoint()
        self._init_ui()

    def _init_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 0, 0, 0)
        layout.setSpacing(0)

        # 1. App icon (16x16 like native)
        self.icon_label = QLabel()
        if LOGO_PNG.exists():
            pixmap = QPixmap(str(LOGO_PNG)).scaled(16, 16, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.icon_label.setPixmap(pixmap)
        self.icon_label.setFixedSize(16, 16)
        self.icon_label.setStyleSheet("background: transparent; border: none;")
        layout.addWidget(self.icon_label)
        layout.addSpacing(8)

        # 2. Title text (Segoe UI, 12px like native)
        self.title_label = QLabel("Fikrado Security")
        self.title_label.setStyleSheet(
            "color: #ECEFF4; font-family: 'Segoe UI Variable Text', 'Segoe UI', sans-serif; "
            "font-size: 12px; font-weight: 400; background: transparent;"
        )
        layout.addWidget(self.title_label)
        layout.addSpacing(6)

        # 3. Version badge (small, subtle)
        version_lbl = QLabel(f"v{APP_VERSION}")
        version_lbl.setStyleSheet(
            "color: #7F8A99; font-family: 'Segoe UI Variable Text', 'Segoe UI', sans-serif; "
            "font-size: 10px; background: transparent;"
        )
        layout.addWidget(version_lbl)

        # 4. Admin badge
        admin_state = is_admin()
        if admin_state:
            badge = QLabel("ADMIN")
            badge.setStyleSheet("""
                color: #A3BE8C;
                background-color: rgba(163, 190, 140, 20);
                border: 1px solid rgba(163, 190, 140, 60);
                border-radius: 4px;
                padding: 1px 6px;
                font-size: 9px;
                font-weight: 600;
                font-family: 'Segoe UI Variable Text', 'Segoe UI', sans-serif;
            """)
            layout.addWidget(badge)
            layout.addSpacing(6)

        layout.addStretch()

        # 5. Window controls (native Windows 11 style)
        self.min_btn = NativeTitleButton("minimize", self)
        self.min_btn.setToolTip("Minimize")
        self.min_btn.clicked.connect(self._minimize_window)
        layout.addWidget(self.min_btn)

        self.max_btn = NativeTitleButton("maximize", self)
        self.max_btn.setToolTip("Maximize")
        self.max_btn.clicked.connect(self._toggle_maximize)
        layout.addWidget(self.max_btn)

        self.close_btn = NativeTitleButton("close", self)
        self.close_btn.setToolTip("Close")
        self.close_btn.clicked.connect(self._close_window)
        layout.addWidget(self.close_btn)

    def _minimize_window(self):
        if self.parent_window:
            self.parent_window.showMinimized()

    def _toggle_maximize(self):
        if not self.parent_window:
            return
        if self.parent_window.isMaximized():
            self.parent_window.showNormal()
            self._set_maximize_icon(False)
        else:
            self.parent_window.showMaximized()
            self._set_maximize_icon(True)

    def _set_maximize_icon(self, maximized: bool):
        self.max_btn._icon_name = "restore" if maximized else "maximize"
        self.max_btn._render_icon()
        self.max_btn.setToolTip("Restore" if maximized else "Maximize")

    def _close_window(self):
        if self.parent_window:
            self.parent_window.close()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.parent_window.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton and self.parent_window:
            if self.parent_window.isMaximized():
                self.parent_window.showNormal()
                self._set_maximize_icon(False)
            self.parent_window.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._toggle_maximize()
            event.accept()
