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
from ui.effects import apply_text_glow, pulse_glow


class CustomTitleBar(QFrame):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.setObjectName("TitleBar")
        self.setFixedHeight(44)
        self.setStyleSheet(f"""
            QFrame#TitleBar {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                            stop:0 #272D38, stop:1 #232830);
                border-bottom: 1px solid rgba(76, 86, 106, 115);
            }}
            QPushButton {{
                background: transparent;
                border: none;
                border-radius: 7px;
                color: #C9D2DE;
                font-family: "Segoe MDL2 Assets", "Segoe UI", sans-serif;
                font-size: 13px;
                min-width: 42px;
                max-width: 42px;
                min-height: 32px;
                max-height: 32px;
                margin: 0 2px;
            }}
            QPushButton:hover {{
                background-color: rgba(76, 86, 106, 166);
                color: #ECEFF4;
            }}
            QPushButton:pressed {{
                background-color: rgba(67, 76, 94, 230);
            }}
            #CloseBtn:hover {{
                background-color: #BF616A;
                color: #FFFFFF;
            }}
            #CloseBtn:pressed {{
                background-color: #A54F58;
            }}
        """)
        self._drag_pos = QPoint()
        self._init_ui()

    def _init_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 0, 8, 0)
        layout.setSpacing(9)

        # 1. Logo
        self.logo_label = QLabel()
        if LOGO_PNG.exists():
            pixmap = QPixmap(str(LOGO_PNG)).scaled(26, 26, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.logo_label.setPixmap(pixmap)
        self.logo_label.setFixedSize(26, 26)
        self.logo_label.setStyleSheet("background: transparent;")
        logo_glow = apply_text_glow(self.logo_label, "#FFD93D", blur=18, opacity=130)
        pulse_glow(logo_glow, min_blur=10, max_blur=20, duration=3000)
        layout.addWidget(self.logo_label)

        # 2. App Title
        self.title_label = QLabel("Fikrado Security")
        self.title_label.setStyleSheet(
            "color: #ECEFF4; font-weight: 700; font-size: 13px; "
            "letter-spacing: 0.5px; background: transparent;"
        )
        apply_text_glow(self.title_label, "#BFE6EF", blur=10, opacity=95)
        layout.addWidget(self.title_label)

        # 3. UAC Admin Badge
        admin_state = is_admin()
        badge_text = "ADMINISTRATOR" if admin_state else "USER"
        badge_style = (
            "background-color: rgba(163, 190, 140, 38); color: #A3BE8C; "
            "border: 1px solid rgba(163, 190, 140, 110);"
            if admin_state
            else "background-color: rgba(235, 203, 139, 28); color: #EBCB8B; "
                 "border: 1px solid rgba(235, 203, 139, 90);"
        )
        self.badge_label = QLabel(badge_text)
        self.badge_label.setStyleSheet(f"""
            {badge_style}
            font-size: 9px;
            font-weight: 700;
            letter-spacing: 0.8px;
            padding: 0 8px;
            border-radius: 9px;
        """)
        self.badge_label.setFixedHeight(20)
        self.badge_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.badge_label)

        layout.addStretch()

        # 4. Window Controls
        self.min_btn = QPushButton("—")
        self.min_btn.clicked.connect(self._minimize_window)
        layout.addWidget(self.min_btn)

        self.max_btn = QPushButton("□")
        self.max_btn.clicked.connect(self._toggle_maximize)
        layout.addWidget(self.max_btn)

        self.close_btn = QPushButton("✕")
        self.close_btn.setObjectName("CloseBtn")
        self.close_btn.clicked.connect(self._close_window)
        layout.addWidget(self.close_btn)

        for button in (self.min_btn, self.max_btn, self.close_btn):
            button.setCursor(Qt.PointingHandCursor)

    def _minimize_window(self):
        if self.parent_window:
            self.parent_window.showMinimized()

    def _toggle_maximize(self):
        if not self.parent_window:
            return
        if self.parent_window.isMaximized():
            self.parent_window.showNormal()
            self.max_btn.setText("□")
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
                self.max_btn.setText("□")
            self.parent_window.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._toggle_maximize()
            event.accept()
