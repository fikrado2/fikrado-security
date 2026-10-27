"""
Fikrado Security - Custom Window Title Bar
Glass title bar with branding, publisher, elevation badge and vector window controls.
"""
from PySide6.QtCore import QPoint, QSize, Qt
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QWidget,
)

from config.constants import APP_VERSION, LOGO_PNG
from core.system_info import is_admin
from ui.effects import apply_text_glow, pulse_glow
from ui.icons import load_icon


class CustomTitleBar(QFrame):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.setObjectName("TitleBar")
        self.setFixedHeight(46)
        self.setStyleSheet("""
            QFrame#TitleBar {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                            stop:0 rgba(255, 255, 255, 13),
                                            stop:0.08 rgba(255, 255, 255, 5),
                                            stop:1 rgba(16, 20, 27, 118));
                border-bottom: 1px solid rgba(255, 255, 255, 20);
                border-top: 1px solid rgba(255, 255, 255, 10);
            }
            QPushButton {
                background: transparent;
                border: 1px solid transparent;
                border-radius: 8px;
                min-width: 40px;
                max-width: 40px;
                min-height: 30px;
                max-height: 30px;
                margin: 0 2px;
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 18);
                border-color: rgba(255, 255, 255, 28);
            }
            QPushButton:pressed {
                background-color: rgba(255, 255, 255, 8);
            }
            #CloseBtn:hover {
                background-color: #BF616A;
                border-color: rgba(255, 255, 255, 70);
            }
            #CloseBtn:pressed {
                background-color: #A54F58;
            }
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
        self.logo_label.setStyleSheet("background: transparent; border: none;")
        logo_glow = apply_text_glow(self.logo_label, "#FFD93D", blur=18, opacity=130)
        pulse_glow(logo_glow, min_blur=10, max_blur=20, duration=3000)
        layout.addWidget(self.logo_label)

        # 2. App title + publisher
        title_box = QHBoxLayout()
        title_box.setSpacing(8)
        self.title_label = QLabel("Fikrado Security")
        self.title_label.setStyleSheet(
            "color: #ECEFF4; font-weight: 700; font-size: 13px; "
            "letter-spacing: 0.4px; background: transparent;"
        )
        apply_text_glow(self.title_label, "#BFE6EF", blur=10, opacity=95)
        title_box.addWidget(self.title_label)

        version_lbl = QLabel(f"v{APP_VERSION}")
        version_lbl.setStyleSheet(
            "color: #7F8A99; font-size: 10px; font-weight: 600; "
            "background: transparent;"
        )
        title_box.addWidget(version_lbl)
        layout.addLayout(title_box)

        # 3. UAC admin badge
        admin_state = is_admin()
        badge_text = "ADMINISTRATOR" if admin_state else "USER"
        badge_style = (
            "background-color: rgba(163, 190, 140, 40); color: #A3BE8C; "
            "border: 1px solid rgba(163, 190, 140, 120);"
            if admin_state
            else "background-color: rgba(235, 203, 139, 32); color: #EBCB8B; "
                 "border: 1px solid rgba(235, 203, 139, 100);"
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

        # 4. Window controls (vector icons, no glyph fonts)
        self.min_btn = QPushButton()
        self.min_btn.setIcon(load_icon("minimize", 12, "#D8DEE9"))
        self.min_btn.setIconSize(QSize(12, 12))
        self.min_btn.setToolTip("Minimize")
        self.min_btn.clicked.connect(self._minimize_window)
        layout.addWidget(self.min_btn)

        self.max_btn = QPushButton()
        self.max_btn.setIcon(load_icon("maximize", 12, "#D8DEE9"))
        self.max_btn.setIconSize(QSize(12, 12))
        self.max_btn.setToolTip("Maximize")
        self.max_btn.clicked.connect(self._toggle_maximize)
        layout.addWidget(self.max_btn)

        self.close_btn = QPushButton()
        self.close_btn.setObjectName("CloseBtn")
        self.close_btn.setIcon(load_icon("close", 12, "#ECEFF4"))
        self.close_btn.setIconSize(QSize(12, 12))
        self.close_btn.setToolTip("Close to tray")
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
            self._set_maximize_icon(False)
        else:
            self.parent_window.showMaximized()
            self._set_maximize_icon(True)

    def _set_maximize_icon(self, maximized: bool):
        name = "restore" if maximized else "maximize"
        self.max_btn.setIcon(load_icon(name, 12, "#D8DEE9"))
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
