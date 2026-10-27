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
from tools.realtime_guard import realtime_guard
from ui.components.ambient_background import AmbientBackground
from ui.components.title_bar import CustomTitleBar
from ui.components.toast import ToastNotification
from ui.effects import (
    apply_text_glow,
    decorate_text_glow,
    fade_in,
    pulse_glow,
    update_glow,
)
from ui.icons import load_icon, refresh_icon_label, set_icon
from ui.pages.ai_scan_page import AIScanPage
from ui.pages.dashboard_page import DashboardPage
from ui.pages.port_scanner_page import PortScannerPage
from ui.pages.quarantine_page import QuarantinePage
from ui.pages.reports_page import ReportsPage
from ui.pages.scan_page import ScanPage
from ui.pages.settings_page import SettingsPage
from ui.pages.tools_hub_page import ToolsHubPage
from ui.pages.vuln_page import VulnPage
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

        self.page_dashboard = DashboardPage(self)
        self.page_quick_scan = ScanPage(default_mode="Quick", parent=self)
        self.page_full_scan = ScanPage(default_mode="Full", parent=self)
        self.page_custom_scan = ScanPage(default_mode="Custom", parent=self)
        self.page_ports = PortScannerPage(self)
        self.page_vuln = VulnPage(self)
        self.page_ai = AIScanPage(self)
        self.page_tools = ToolsHubPage(self)
        self.page_quarantine = QuarantinePage(self)
        self.page_reports = ReportsPage(self)
        self.page_settings = SettingsPage(self)

        self.page_dashboard.navigate_to_page.connect(self.navigate_to_page)
        self.page_quick_scan.request_ai_explain.connect(self._on_ai_explain_requested)
        self.page_full_scan.request_ai_explain.connect(self._on_ai_explain_requested)
        self.page_custom_scan.request_ai_explain.connect(self._on_ai_explain_requested)

        for page in (
            self.page_dashboard, self.page_quick_scan, self.page_full_scan,
            self.page_custom_scan, self.page_ports, self.page_vuln, self.page_ai,
            self.page_tools, self.page_quarantine, self.page_reports, self.page_settings,
        ):
            self.stacked_pages.addWidget(page)

        body_layout.addWidget(self.stacked_pages, 1)
        root_layout.addLayout(body_layout)

        decorate_text_glow(self.central_widget)

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
            pulse_glow(logo_glow, min_blur=12, max_blur=24, duration=2800)
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
        pulse_glow(self.status_glow, min_blur=8, max_blur=18, duration=1800)
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
    def navigate_to_page(self, index: int):
        self.stacked_pages.setCurrentIndex(index)
        if index in self.nav_buttons:
            self.nav_buttons[index].setChecked(True)

        fade_in(self.stacked_pages.currentWidget(), 240)

        if index == 0:
            self.page_dashboard.refresh_dashboard()
        elif index == 1:
            self.page_quick_scan.set_mode("Quick")
        elif index == 2:
            self.page_full_scan.set_mode("Full")
        elif index == 3:
            self.page_custom_scan.set_mode("Custom")

    def _on_ai_explain_requested(self, threat: dict):
        self.navigate_to_page(6)
        self.page_ai.explain_external_threat(threat)

    # ------------------------------------------------------------------ window
    def showEvent(self, event):
        super().showEvent(event)
        if not self._native_chrome_applied:
            self._native_chrome_applied = True
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
