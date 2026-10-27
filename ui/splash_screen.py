"""
Fikrado Security - Modern Animated Splash Screen
Displays high-resolution branding, gradient glow, and real-time initialization steps.
"""
from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, QTimer
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
from config.constants import APP_VERSION, COLOR_BG_DARK, LOGO_PNG
from ui.effects import apply_text_glow, pulse_glow


class FikradoSplashScreen(QSplashScreen):

    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(520, 360)

        # Central Container Frame
        self.container = QFrame(self)
        self.container.setObjectName("SplashCard")
        self.container.setGeometry(10, 10, 500, 340)
        self.container.setStyleSheet("""
            QFrame#SplashCard {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                            stop:0 #272D38, stop:1 #1F242C);
                border: 1px solid rgba(136, 192, 208, 56);
                border-radius: 20px;
            }
        """)

        # Drop shadow for container
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(36)
        shadow.setColor(QColor(0, 0, 0, 190))
        shadow.setOffset(0, 10)
        self.container.setGraphicsEffect(shadow)

        layout = QVBoxLayout(self.container)
        layout.setContentsMargins(40, 30, 40, 30)
        layout.setSpacing(12)
        layout.setAlignment(Qt.AlignCenter)

        # 1. Logo
        self.logo_lbl = QLabel()
        if LOGO_PNG.exists():
            pix = QPixmap(str(LOGO_PNG)).scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.logo_lbl.setPixmap(pix)
        self.logo_lbl.setAlignment(Qt.AlignCenter)
        self.logo_lbl.setStyleSheet("background: transparent;")

        # Breathing logo glow
        logo_glow = apply_text_glow(self.logo_lbl, "#FFD93D", blur=26, opacity=160)
        pulse_glow(logo_glow, min_blur=16, max_blur=34, duration=2400)
        layout.addWidget(self.logo_lbl)

        # 2. App Title
        title_lbl = QLabel("Fikrado Security")
        title_lbl.setStyleSheet("""
            font-size: 26px;
            font-weight: 800;
            color: #ECEFF4;
            letter-spacing: 1px;
            background: transparent;
        """)
        title_lbl.setAlignment(Qt.AlignCenter)
        apply_text_glow(title_lbl, "#9FDFEA", blur=20, opacity=125)
        layout.addWidget(title_lbl)

        # 3. Subtitle
        sub_lbl = QLabel("Enterprise Windows Endpoint Defense & Threat Intelligence")
        sub_lbl.setStyleSheet("color: #88C0D0; font-size: 12px; font-weight: 600; background: transparent;")
        sub_lbl.setAlignment(Qt.AlignCenter)
        apply_text_glow(sub_lbl, "#88C0D0", blur=10, opacity=80)
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
                background-color: #20252E;
                border: none;
                border-radius: 4px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #FFD93D, stop:1 #88C0D0);
                border-radius: 4px;
            }
        """)
        layout.addWidget(self.progress)

        # 6. Version footer
        version_lbl = QLabel(f"FIKRADO CYBERDEFENSE  ·  v{APP_VERSION}")
        version_lbl.setStyleSheet("color: #6F7887; font-size: 9px; font-weight: 600; letter-spacing: 1.4px; background: transparent;")
        version_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(version_lbl)

    def showEvent(self, event):
        super().showEvent(event)
        if getattr(self, "_fade_started", False):
            return
        self._fade_started = True
        self.setWindowOpacity(0.0)
        self._fade_anim = QPropertyAnimation(self, b"windowOpacity", self)
        self._fade_anim.setDuration(320)
        self._fade_anim.setStartValue(0.0)
        self._fade_anim.setEndValue(1.0)
        self._fade_anim.setEasingCurve(QEasingCurve.OutCubic)
        self._fade_anim.start()

    def set_progress(self, val: int, message: str):
        self.progress.setValue(val)
        self.status_lbl.setText(message)
        self.repaint()
