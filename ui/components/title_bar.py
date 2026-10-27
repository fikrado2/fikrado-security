"""
Fikrado Security - Custom Window Title Bar
Features logo, drag behavior, elevation badge, and window controls (min, max, close).
"""
from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QWidget
)
from config.constants import COLOR_BG_DARKEST, LOGO_PNG
from core.system_info import is_admin


class CustomTitleBar(QFrame):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.setFixedHeight(42)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {COLOR_BG_DARKEST};
                border-bottom: 1px solid #3B4252;
            }}
            QPushButton {{
                background: transparent;
                border: none;
                color: #D8DEE9;
                font-family: "Segoe MDL2 Assets", "Segoe UI", sans-serif;
                font-size: 13px;
                min-width: 44px;
                max-width: 44px;
                min-height: 40px;
                max-height: 40px;
            }}
            QPushButton:hover {{
                background-color: #3B4252;
                color: #ECEFF4;
            }}
            #CloseBtn:hover {{
                background-color: #BF616A;
                color: #FFFFFF;
            }}
        """)
        self._drag_pos = QPoint()
        self._init_ui()

    def _init_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 0, 0, 0)
        layout.setSpacing(10)

        # 1. Logo
        self.logo_label = QLabel()
        if LOGO_PNG.exists():
            pixmap = QPixmap(str(LOGO_PNG)).scaled(24, 24, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.logo_label.setPixmap(pixmap)
        self.logo_label.setFixedSize(24, 24)
        layout.addWidget(self.logo_label)

        # 2. App Title
        self.title_label = QLabel("Fikrado Security")
        self.title_label.setStyleSheet("color: #ECEFF4; font-weight: bold; font-size: 13px; letter-spacing: 0.5px;")
        layout.addWidget(self.title_label)

        # 3. UAC Admin Badge
        admin_state = is_admin()
        badge_text = "ADMINISTRATOR" if admin_state else "USER"
        badge_style = "background-color: rgba(163, 190, 140, 0.2); color: #A3BE8C; border: 1px solid #A3BE8C;" if admin_state else "background-color: rgba(235, 203, 139, 0.2); color: #EBCB8B; border: 1px solid #EBCB8B;"
        self.badge_label = QLabel(badge_text)
        self.badge_label.setStyleSheet(f"""
            {badge_style}
            font-size: 10px;
            font-weight: bold;
            padding: 2px 7px;
            border-radius: 4px;
        """)
        layout.addWidget(self.badge_label)

        layout.addStretch()

        # 4. Window Controls
        self.min_btn = QPushButton("—")
        self.min_btn.clicked.connect(self._minimize_window)
        layout.addWidget(self.min_btn)

        self.max_btn = QPushButton("⬜")
        self.max_btn.clicked.connect(self._toggle_maximize)
        layout.addWidget(self.max_btn)

        self.close_btn = QPushButton("✕")
        self.close_btn.setObjectName("CloseBtn")
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
            self.max_btn.setText("⬜")
        else:
            self.parent_window.showMaximized()
            self.max_btn.setText("❐")

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
                self.max_btn.setText("⬜")
            self.parent_window.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._toggle_maximize()
            event.accept()
