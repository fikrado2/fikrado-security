"""
Fikrado Security - Main Application Window
Modern glass interface with an ambient painted backdrop, vector navigation icons,
social links, system-tray background operation and native Windows 11 chrome.
"""
from PySide6.QtCore import QSize, Qt, QTimer, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QPushButton,
    QStackedWidget,
    QSystemTrayIcon,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from config.constants import (
    APP_PUBLISHER,
    APP_VERSION,
    COLOR_AURORA_GREEN,
    COLOR_AURORA_YELLOW,
    ICONS_DIR,
    LOGO_ICO,
    LOGO_PNG,
    SOCIAL_LINKS,
)
from config.settings import SettingsManager
from core.logger import logger
from tools.realtime_guard import realtime_guard
from ui.components.ambient_background import AmbientBackground
from ui.components.loading_overlay import LoadingOverlay
from ui.components.title_bar import CustomTitleBar
from ui.components.toast import ToastNotification
from ui.effects import apply_text_glow, update_glow
from ui.icons import load_icon, refresh_icon_label, set_icon
from ui.win_effects import apply_window_effects


class FikradoMainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.settings = SettingsManager()
        self.setWindowTitle("Fikrado Security")
        self.resize(1280, 840)
        self.setMinimumSize(1100, 720)
        self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)

        self._force_quit = False
        self._tray_hint_shown = False
        self._native_chrome_applied = False
        self._navigating = False
        self._pending_nav_index: int | None = None
        self._pending_ai_threat: dict | None = None
        self._pages: dict[int, QWidget] = {}
        self._page_titles = {
            0: "Security Dashboard",
            1: "Quick Scan",
            2: "Full Scan",
            3: "Custom Scan",
            4: "Port Scanner",
            5: "Updates & Vulnerabilities",
            6: "AI Neural Scan",
            7: "Security Tools",
            8: "Quarantine Vault",
            9: "Audit Reports",
            10: "Settings",
            11: "Terminal",
            12: "Bootkit & Rootkit Scan",
        }
        self._page_factories = {
            0: self._create_dashboard_page,
            1: lambda: self._create_scan_page("Quick"),
            2: lambda: self._create_scan_page("Full"),
            3: lambda: self._create_scan_page("Custom"),
            4: self._create_ports_page,
            5: self._create_vuln_page,
            6: self._create_ai_page,
            7: self._create_tools_page,
            8: self._create_quarantine_page,
            9: self._create_reports_page,
            10: self._create_settings_page,
            11: self._create_terminal_page,
            12: self._create_threat_scan_page,
        }
        self.tray_icon: QSystemTrayIcon | None = None
        self._tray_menu: QMenu | None = None
        self._tray_protection_action: QAction | None = None

        if LOGO_ICO.exists():
            self.setWindowIcon(QIcon(str(LOGO_ICO)))
        elif LOGO_PNG.exists():
            self.setWindowIcon(QIcon(str(LOGO_PNG)))

        self._init_ui()
        self._init_tray()
        realtime_guard.signals.guard_status_changed.connect(self._on_guard_status)
        self._on_guard_status(realtime_guard.is_active, realtime_guard.scope_summary())
        QTimer.singleShot(0, lambda: self.navigate_to_page(0))

    # --------------------------------------------------------------------- UI
    def _init_ui(self):
        self.central_widget = AmbientBackground()
        self.central_widget.setObjectName("AppRoot")
        self.setCentralWidget(self.central_widget)

        root_layout = QVBoxLayout(self.central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 1. Custom glass title bar
        self.title_bar = CustomTitleBar(self)
        root_layout.addWidget(self.title_bar)

        # 2. Sidebar + stacked pages
        body_layout = QHBoxLayout()
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        self.sidebar = self._create_sidebar()
        body_layout.addWidget(self.sidebar)

        self.stacked_pages = QStackedWidget()
        self.stacked_pages.setObjectName("PageStack")
        self.loading_overlay = LoadingOverlay(self.stacked_pages, "Preparing workspace…")

        body_layout.addWidget(self.stacked_pages, 1)
        root_layout.addLayout(body_layout)

    # ------------------------------------------------------- lazy page loading
    def _create_dashboard_page(self):
        from ui.pages.dashboard_page import DashboardPage
        return DashboardPage(self)

    def _create_scan_page(self, mode: str):
        from ui.pages.scan_page import ScanPage
        return ScanPage(default_mode=mode, parent=self)

    def _create_ports_page(self):
        from ui.pages.port_scanner_page import PortScannerPage
        return PortScannerPage(self)

    def _create_vuln_page(self):
        from ui.pages.vuln_page import VulnPage
        return VulnPage(self)

    def _create_ai_page(self):
        from ui.pages.ai_scan_page import AIScanPage
        return AIScanPage(self)

    def _create_tools_page(self):
        from ui.pages.tools_hub_page import ToolsHubPage
        return ToolsHubPage(self)

    def _create_quarantine_page(self):
        from ui.pages.quarantine_page import QuarantinePage
        return QuarantinePage(self)

    def _create_reports_page(self):
        from ui.pages.reports_page import ReportsPage
        return ReportsPage(self)

    def _create_settings_page(self):
        from ui.pages.settings_page import SettingsPage
        return SettingsPage(self)

    def _create_terminal_page(self):
        from ui.pages.terminal_page import TerminalPage
        return TerminalPage(self)

    def _create_threat_scan_page(self):
        from ui.pages.threat_scan_page import ThreatScanPage
        return ThreatScanPage(self)

    def _create_page(self, index: int) -> QWidget | None:
        factory = self._page_factories.get(index)
        if factory is None:
            return None

        try:
            page = factory()
        except Exception as exc:
            logger.exception("Failed to create page %s", index)
            ToastNotification(self, "Unable to open page", str(exc), "error")
            return None

        self._pages[index] = page

        if index == 0:
            page.navigate_to_page.connect(self.navigate_to_page)
        elif index in (1, 2, 3):
            page.request_ai_explain.connect(self._on_ai_explain_requested)

        self.stacked_pages.addWidget(page)
        return page

    def _create_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("SidebarWidget")

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(14, 18, 14, 16)
        layout.setSpacing(6)

        # Branding
        brand_row = QHBoxLayout()
        brand_row.setSpacing(11)
        brand_row.setContentsMargins(6, 4, 6, 10)

        if LOGO_PNG.exists():
            logo_pix = QPixmap(str(LOGO_PNG)).scaled(38, 38, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo_lbl = QLabel()
            logo_lbl.setPixmap(logo_pix)
            logo_lbl.setFixedSize(38, 38)
            logo_lbl.setStyleSheet("background: transparent; border: none;")
            logo_glow = apply_text_glow(logo_lbl, "#FFD93D", blur=20, opacity=135)
            brand_row.addWidget(logo_lbl)

        brand_text_layout = QVBoxLayout()
        brand_text_layout.setSpacing(0)
        app_title = QLabel("FIKRADO")
        app_title.setStyleSheet(
            "font-size: 15px; font-weight: 800; color: #ECEFF4; "
            "letter-spacing: 1.5px; background: transparent;"
        )
        apply_text_glow(app_title, "#D9F1F7", blur=14, opacity=120)
        sub_title = QLabel("SECURITY")
        sub_title.setStyleSheet(
            "font-size: 11px; font-weight: 800; color: #FFD93D; "
            "letter-spacing: 2px; background: transparent;"
        )
        apply_text_glow(sub_title, "#FFD93D", blur=12, opacity=150)
        publisher = QLabel(f"by {APP_PUBLISHER}")
        publisher.setStyleSheet(
            "font-size: 9px; font-weight: 600; color: #7F8A99; "
            "letter-spacing: 0.4px; background: transparent;"
        )
        brand_text_layout.addWidget(app_title)
        brand_text_layout.addWidget(sub_title)
        brand_text_layout.addWidget(publisher)
        brand_row.addLayout(brand_text_layout)
        brand_row.addStretch()
        layout.addLayout(brand_row)

        # Brand divider
        divider = QFrame()
        divider.setFixedHeight(1)
        divider.setStyleSheet(
            "background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
            "stop:0 rgba(255, 217, 61, 140), stop:0.55 rgba(136, 192, 208, 40), "
            "stop:1 rgba(136, 192, 208, 0));"
            "border: none;"
        )
        layout.addWidget(divider)
        layout.addSpacing(8)

        # Navigation
        self.nav_btn_group = QButtonGroup(self)
        self.nav_btn_group.setExclusive(True)

        pages = [
            ("Dashboard", "dashboard", 0),
            ("Quick Scan", "quick_scan", 1),
            ("Full Scan", "full_scan", 2),
            ("Custom Scan", "custom_scan", 3),
            ("Port Scanner", "port_scanner", 4),
            ("Updates & Vulns", "vuln", 5),
            ("AI Neural Scan", "ai_scan", 6),
            ("Security Tools", "tools", 7),
            ("Quarantine", "quarantine", 8),
            ("Audit Reports", "reports", 9),
            ("Terminal", "terminal", 11),
            ("Bootkit & Rootkit", "threat_scan", 12),
            ("Settings", "settings", 10),
        ]

        self.nav_buttons = {}
        for title, icon_name, page_idx in pages:
            button_label = title.replace("&", "&&")
            btn = QPushButton(f"  {button_label}")
            btn.setProperty("sidebar", True)
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setMinimumHeight(42)
            btn.setToolTip(title)
            if (ICONS_DIR / f"{icon_name}.svg").exists():
                set_icon(btn, icon_name, 18)
            btn.clicked.connect(lambda _, idx=page_idx: self.navigate_to_page(idx))
            self.nav_btn_group.addButton(btn, page_idx)
            self.nav_buttons[page_idx] = btn
            layout.addWidget(btn)

        layout.addStretch()

        # Social presence
        connect_label = QLabel("CONNECT")
        connect_label.setStyleSheet(
            "color: #6F7887; font-size: 9px; font-weight: 700; "
            "letter-spacing: 1.6px; background: transparent; padding-left: 6px;"
        )
        layout.addWidget(connect_label)

        social_row = QHBoxLayout()
        social_row.setContentsMargins(4, 0, 4, 0)
        social_row.setSpacing(6)
        for icon_name, label, url in SOCIAL_LINKS:
            social_btn = QToolButton()
            social_btn.setProperty("social", True)
            social_btn.setToolButtonStyle(Qt.ToolButtonIconOnly)
            social_btn.setIcon(load_icon(icon_name, 18))
            social_btn.setIconSize(QSize(18, 18))
            social_btn.setFixedSize(32, 32)
            social_btn.setCursor(Qt.PointingHandCursor)
            social_btn.setToolTip(f"{label} — {url}")
            social_btn.clicked.connect(lambda _, target=url: QDesktopServices.openUrl(QUrl(target)))
            social_row.addWidget(social_btn)
        social_row.addStretch()
        layout.addLayout(social_row)
        layout.addSpacing(8)

        # Shield status pill
        shield_frame = QFrame()
        shield_frame.setProperty("subcard", True)
        sf_layout = QHBoxLayout(shield_frame)
        sf_layout.setContentsMargins(10, 8, 10, 8)
        sf_layout.setSpacing(7)

        self.status_icon = QLabel()
        self.status_icon.setFixedSize(16, 16)
        self.status_icon.setStyleSheet("background: transparent; border: none;")
        refresh_icon_label(self.status_icon, "shield", 16)
        self.status_glow = apply_text_glow(self.status_icon, COLOR_AURORA_GREEN, blur=14, opacity=210)
        sf_layout.addWidget(self.status_icon)

        self.status_text = QLabel("Shield Active")
        self.status_text.setStyleSheet("color: #ECEFF4; font-size: 11px; font-weight: bold; background: transparent;")
        sf_layout.addWidget(self.status_text)
        sf_layout.addStretch()

        ver_lbl = QLabel(f"v{APP_VERSION}")
        ver_lbl.setStyleSheet("color: #9BA3AF; font-size: 10px; background: transparent;")
        sf_layout.addWidget(ver_lbl)
        layout.addWidget(shield_frame)

        if 0 in self.nav_buttons:
            self.nav_buttons[0].setChecked(True)

        return sidebar

    # ------------------------------------------------------------------- tray
    def _init_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return

        tray_icon = QIcon(str(LOGO_ICO)) if LOGO_ICO.exists() else self.windowIcon()
        self.tray_icon = QSystemTrayIcon(tray_icon, self)
        self.tray_icon.setToolTip(f"Fikrado Security v{APP_VERSION} — Protection Active")

        menu = QMenu()
        open_action = menu.addAction("Open Fikrado Security")
        open_action.triggered.connect(self._restore_from_tray)

        quick_action = menu.addAction("Run Quick Scan")
        quick_action.triggered.connect(self._tray_quick_scan)

        menu.addSeparator()
        self._tray_protection_action = menu.addAction("Pause Protection")
        self._tray_protection_action.triggered.connect(self._toggle_protection)

        menu.addSeparator()
        quit_action = menu.addAction("Quit Fikrado Security")
        quit_action.triggered.connect(self._quit_application)

        self._tray_menu = menu
        self.tray_icon.setContextMenu(menu)
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.show()

    def _on_tray_activated(self, reason):
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self._restore_from_tray()

    def _restore_from_tray(self):
        self.show()
        if self.isMinimized():
            self.showNormal()
        self.raise_()
        self.activateWindow()

    def _tray_quick_scan(self):
        self._restore_from_tray()
        self.navigate_to_page(1)

    def _toggle_protection(self):
        if realtime_guard.is_active:
            realtime_guard.pause_guard()
        else:
            realtime_guard.start_guard()

    def _quit_application(self):
        self._force_quit = True
        try:
            realtime_guard.stop_guard()
        except Exception:
            pass
        if self.tray_icon is not None:
            self.tray_icon.hide()
        QApplication.quit()

    def _on_guard_status(self, active: bool, message: str):
        color = COLOR_AURORA_GREEN if active else COLOR_AURORA_YELLOW
        refresh_icon_label(self.status_icon, "shield" if active else "warning", 16)
        update_glow(self.status_icon, color, 210)
        self.status_text.setText("Shield Active" if active else "Shield Paused")
        self.status_text.setStyleSheet(
            f"color: {'#ECEFF4' if active else '#EBCB8B'}; font-size: 11px; "
            "font-weight: bold; background: transparent;"
        )
        if self.tray_icon is not None:
            state = "Protection Active" if active else "Protection Paused"
            self.tray_icon.setToolTip(f"Fikrado Security v{APP_VERSION} — {state}")
        if self._tray_protection_action is not None:
            self._tray_protection_action.setText(
                "Pause Protection" if active else "Resume Protection"
            )

    # --------------------------------------------------------------- navigation
    def _activate_page(self, index: int, page: QWidget):
        self.stacked_pages.setCurrentWidget(page)
        if index in self.nav_buttons:
            self.nav_buttons[index].setChecked(True)

        if index == 0:
            page.refresh_dashboard()
        elif index == 1:
            page.set_mode("Quick")
        elif index == 2:
            page.set_mode("Full")
        elif index == 3:
            page.set_mode("Custom")

    def navigate_to_page(self, index: int):
        if index not in self._page_factories:
            return

        if self._navigating:
            self._pending_nav_index = index
            return

        page = self._pages.get(index)
        if page is not None:
            self._activate_page(index, page)
            return

        # First visit: paint the spinner immediately, then build the page.
        self._navigating = True
        if index in self.nav_buttons:
            self.nav_buttons[index].setChecked(True)
        self.loading_overlay.show_message(
            f"Preparing {self._page_titles.get(index, 'workspace')}…"
        )
        QTimer.singleShot(16, lambda: self._finish_page_creation(index))

    def _finish_page_creation(self, index: int):
        page = self._create_page(index)
        try:
            if page is not None:
                self._activate_page(index, page)
                if index == 6 and self._pending_ai_threat is not None:
                    threat = self._pending_ai_threat
                    self._pending_ai_threat = None
                    page.explain_external_threat(threat)
        finally:
            self._navigating = False
            self.loading_overlay.hide_overlay()
            pending = self._pending_nav_index
            self._pending_nav_index = None
            if pending is not None and pending != index:
                QTimer.singleShot(0, lambda: self.navigate_to_page(pending))

    def _open_close_apps_page(self):
        page = self._pages.get(11)
        if page is not None:
            self._activate_page(11, page)
            return
        self._navigating = True
        if 11 in self.nav_buttons:
            self.nav_buttons[11].setChecked(True)
        self.loading_overlay.show_message("Preparing process manager…")
        QTimer.singleShot(16, lambda: self._finish_page_creation(11))
        self._pending_ai_threat = threat
        page = self._pages.get(6)
        if page is not None:
            self.navigate_to_page(6)
            page.explain_external_threat(threat)
            self._pending_ai_threat = None
        else:
            self.navigate_to_page(6)

    # ------------------------------------------------------------------ window
    def showEvent(self, event):
        super().showEvent(event)
        if not self._native_chrome_applied:
            self._native_chrome_applied = True
            # Center the window on screen
            screen = QApplication.primaryScreen()
            if screen:
                screen_geo = screen.availableGeometry()
                x = screen_geo.x() + (screen_geo.width() - self.width()) // 2
                y = screen_geo.y() + (screen_geo.height() - self.height()) // 2
                self.move(x, y)
            QTimer.singleShot(0, lambda: apply_window_effects(self))

    def closeEvent(self, event):
        app = QApplication.instance()
        if (
            not self._force_quit
            and self.tray_icon is not None
            and self.tray_icon.isVisible()
            and self.settings.get("app", "minimize_to_tray", True)
            and not (app is not None and app.closingDown())
        ):
            event.ignore()
            self.hide()
            if not self._tray_hint_shown:
                self.tray_icon.showMessage(
                    "Fikrado Security",
                    "Still protecting your PC in the background. "
                    "Right-click the tray icon to reopen or quit.",
                    QSystemTrayIcon.MessageIcon.Information,
                    4500,
                )
                self._tray_hint_shown = True
            return
        event.accept()
