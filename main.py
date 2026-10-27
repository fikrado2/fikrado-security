"""
Fikrado Security - Main Application Entrypoint
Initializes Qt runtime, loads custom QSS theme, presents splash screen,
seeds databases, starts the real-time guard, and displays the main window.
"""
import os
import sys
import time
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QFontDatabase, QGuiApplication, QIcon
from PySide6.QtWidgets import QApplication

from config.constants import ASSETS_DIR, LOGO_ICO, LOGO_PNG
from core.logger import logger
from core.updater import init_offline_signatures
from tools.realtime_guard import realtime_guard
from ui.app_window import FikradoMainWindow
from ui.splash_screen import FikradoSplashScreen


def configure_application(app: QApplication):
    """Applies a consistent, high-DPI friendly visual foundation."""
    app.setStyle("Fusion")

    families = set(QFontDatabase.families())
    family = next(
        (name for name in ("Segoe UI Variable Text", "Segoe UI", "Inter", "Arial") if name in families),
        "Segoe UI",
    )
    font = QFont(family)
    font.setPointSizeF(9.75)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    app.setFont(font)

    # Native menu/combo/tooltip animations for a softer, more fluid feel.
    for effect in (
        Qt.UIEffect.UI_AnimateMenu,
        Qt.UIEffect.UI_FadeMenu,
        Qt.UIEffect.UI_AnimateCombo,
        Qt.UIEffect.UI_AnimateTooltip,
    ):
        QApplication.setEffectEnabled(effect, True)


def load_stylesheet(app: QApplication):
    """Loads and compiles theme.qss into the global Qt application instance."""
    qss_file = ASSETS_DIR / "styles" / "theme.qss"
    if qss_file.exists():
        try:
            with open(qss_file, "r", encoding="utf-8") as f:
                stylesheet = f.read()
            app.setStyleSheet(stylesheet)
            logger.info("Custom Dark Nord stylesheet applied.")
        except Exception as e:
            logger.error(f"Failed to load stylesheet: {e}")


def main():
    # Set Windows Process AppUserModelID for crisp taskbar icon & notifications
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Fikrado.Security.Endpoint.1.0")
    except Exception:
        pass

    # Smooth fractional scaling on high-DPI Windows displays (must run pre-QApplication).
    try:
        QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )
    except Exception:
        pass

    app = QApplication(sys.argv)
    configure_application(app)
    app.setApplicationName("Fikrado Security")
    app.setOrganizationName("Fikrado CyberDefense")

    # App Icon
    if LOGO_ICO.exists():
        app.setWindowIcon(QIcon(str(LOGO_ICO)))
    elif LOGO_PNG.exists():
        app.setWindowIcon(QIcon(str(LOGO_PNG)))

    # Apply Nord QSS theme
    load_stylesheet(app)

    # 1. Show Animated Splash Screen
    splash = FikradoSplashScreen()
    splash.show()
    app.processEvents()

    # Step 1: Initialize local databases and signatures
    splash.set_progress(25, "Seeding malware signatures & CISA KEV feeds...")
    app.processEvents()
    init_offline_signatures()
    time.sleep(0.3)

    # Step 2: Initialize AI Plugins and DPAPI encryption
    splash.set_progress(55, "Loading AI plugins & DPAPI security credentials...")
    app.processEvents()
    from plugins.plugin_manager import plugin_manager
    time.sleep(0.3)

    # Step 3: Initialize Real-Time Protection Shield
    splash.set_progress(80, "Starting Real-Time Protection Shield...")
    app.processEvents()
    try:
        realtime_guard.start_guard()
    except Exception as e:
        logger.warning(f"Could not start real-time guard: {e}")
    time.sleep(0.3)

    # Step 4: Launch Main Window
    splash.set_progress(100, "Starting Fikrado Security...")
    app.processEvents()

    main_window = FikradoMainWindow()

    def show_main():
        splash.finish(main_window)
        main_window.show()

    QTimer.singleShot(400, show_main)

    exit_code = app.exec()

    # Clean shutdown
    try:
        realtime_guard.stop_guard()
    except Exception:
        pass

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
