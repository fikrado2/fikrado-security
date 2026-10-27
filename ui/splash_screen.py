"""
Fikrado Security - Modern Animated Splash Screen
Displays high-resolution branding, gradient glow, and real-time initialization steps.
"""
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont, QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsDropShadowEffect,
    QLabel,
    QProgressBar,
    QSplashScreen,
    QVBoxLayout,
    QWidget
)
from config.constants import COLOR_BG_DARK, LOGO_PNG


class FikradoSplashScreen(QSplashScreen):

    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(520, 360)

        # Central Container Frame
        self.container = QFrame(self)
        self.container.setGeometry(10, 10, 500, 340)
        self.container.setStyleSheet("""
            QFrame {
                background-color: #242933;
                border: 2px solid #434C5E;
                border-radius: 16px;
            }
        """)

        # Drop shadow for container
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(30)
        shadow.setColor(QColor(0, 0, 0, 180))
        shadow.setOffset(0, 8)
        self.container.setGraphicsEffect(shadow)

        layout = QVBoxLayout(self.container)
        layout.setContentsMargins(40, 30, 40, 30)
        layout.setSpacing(12)
        layout.setAlignment(Qt.AlignCenter)

        # 1. Logo
        self.logo_lbl = QLabel()
        if LOGO_PNG.exists():
            pix = QPixmap(str(LOGO_PNG)).scaled(96, 96, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.logo_lbl.setPixmap(pix)
        self.logo_lbl.setAlignment(Qt.AlignCenter)

        # Logo Glow Effect
        logo_glow = QGraphicsDropShadowEffect(self)
        logo_glow.setBlurRadius(25)
        logo_glow.setColor(QColor("#FFD93D"))
        logo_glow.setOffset(0, 0)
        self.logo_lbl.setGraphicsEffect(logo_glow)
        layout.addWidget(self.logo_lbl)

        # 2. App Title
        title_lbl = QLabel("Fikrado Security")
        title_lbl.setStyleSheet("""
            font-size: 26px;
            font-weight: 800;
            color: #ECEFF4;
            letter-spacing: 1px;
        """)
        title_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_lbl)

        # 3. Subtitle
        sub_lbl = QLabel("Enterprise Windows Endpoint Defense & Threat Intelligence")
        sub_lbl.setStyleSheet("color: #88C0D0; font-size: 12px; font-weight: 600;")
        sub_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(sub_lbl)

        layout.addSpacing(15)

        # 4. Status Message
        self.status_lbl = QLabel("Initializing engine...")
        self.status_lbl.setStyleSheet("color: #D8DEE9; font-size: 12px;")
        self.status_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_lbl)

        # 5. Progress Bar
        self.progress = QProgressBar()
        self.progress.setFixedHeight(8)
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(10)
        self.progress.setStyleSheet("""
            QProgressBar {
                background-color: #2E3440;
                border: 1px solid #434C5E;
                border-radius: 4px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #FFD93D, stop:1 #88C0D0);
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.progress)

    def set_progress(self, val: int, message: str):
        self.progress.setValue(val)
        self.status_lbl.setText(message)
        self.repaint()
