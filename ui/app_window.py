"""
Fikrado Security - Main Application Window
Modern Nord-themed interface featuring a custom title bar, branded sidebar,
11 dedicated security pages, and floating toast alert container.
"""
from pathlib import Path
from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget
)
from config.constants import (
    ASSETS_DIR,
    COLOR_BG_DARK,
    COLOR_BG_DARKEST,
    ICONS_DIR,
    LOGO_ICO,
    LOGO_PNG
)
from ui.components.title_bar import CustomTitleBar
from ui.components.toast import ToastNotification
from ui.pages.ai_scan_page import AIScanPage
from ui.pages.dashboard_page import DashboardPage
from ui.pages.port_scanner_page import PortScannerPage
from ui.pages.quarantine_page import QuarantinePage
from ui.pages.reports_page import ReportsPage
from ui.pages.scan_page import ScanPage
from ui.pages.settings_page import SettingsPage
from ui.pages.tools_hub_page import ToolsHubPage
from ui.pages.vuln_page import VulnPage


class FikradoMainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Fikrado Security")
        self.resize(1240, 820)
        self.setMinimumSize(1080, 700)
        self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)

        # Set Window Icon
        if LOGO_ICO.exists():
            self.setWindowIcon(QIcon(str(LOGO_ICO)))
        elif LOGO_PNG.exists():
            self.setWindowIcon(QIcon(str(LOGO_PNG)))

        self._init_ui()

    def _init_ui(self):
        # Central Main Widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        root_layout = QVBoxLayout(self.central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 1. Custom Title Bar
        self.title_bar = CustomTitleBar(self)
        root_layout.addWidget(self.title_bar)

        # 2. Main Body Layout (Sidebar + Stacked Pages)
        body_layout = QHBoxLayout()
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        # Sidebar
        self.sidebar = self._create_sidebar()
        body_layout.addWidget(self.sidebar)

        # Stacked Pages
        self.stacked_pages = QStackedWidget()
        self.stacked_pages.setStyleSheet(f"background-color: {COLOR_BG_DARK};")

        # Instantiate Pages (11 Pages)
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

        # Connect inter-page signals
        self.page_dashboard.navigate_to_page.connect(self.navigate_to_page)
        self.page_quick_scan.request_ai_explain.connect(self._on_ai_explain_requested)
        self.page_full_scan.request_ai_explain.connect(self._on_ai_explain_requested)
        self.page_custom_scan.request_ai_explain.connect(self._on_ai_explain_requested)

        self.stacked_pages.addWidget(self.page_dashboard)     # Index 0
        self.stacked_pages.addWidget(self.page_quick_scan)    # Index 1
        self.stacked_pages.addWidget(self.page_full_scan)     # Index 2
        self.stacked_pages.addWidget(self.page_custom_scan)   # Index 3
        self.stacked_pages.addWidget(self.page_ports)         # Index 4
        self.stacked_pages.addWidget(self.page_vuln)          # Index 5
        self.stacked_pages.addWidget(self.page_ai)            # Index 6
        self.stacked_pages.addWidget(self.page_tools)         # Index 7
        self.stacked_pages.addWidget(self.page_quarantine)    # Index 8
        self.stacked_pages.addWidget(self.page_reports)       # Index 9
        self.stacked_pages.addWidget(self.page_settings)      # Index 10

        body_layout.addWidget(self.stacked_pages, 1)
        root_layout.addLayout(body_layout)

    def _create_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("SidebarWidget")

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(14, 18, 14, 18)
        layout.setSpacing(6)

        # Sidebar Header Branding
        brand_row = QHBoxLayout()
        brand_row.setSpacing(10)
        brand_row.setContentsMargins(6, 4, 6, 14)

        if LOGO_PNG.exists():
            logo_pix = QPixmap(str(LOGO_PNG)).scaled(32, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo_lbl = QLabel()
            logo_lbl.setPixmap(logo_pix)
            brand_row.addWidget(logo_lbl)

        brand_text_layout = QVBoxLayout()
        brand_text_layout.setSpacing(0)
        app_title = QLabel("FIKRADO")
        app_title.setStyleSheet("font-size: 15px; font-weight: 800; color: #ECEFF4; letter-spacing: 1.5px;")
        sub_title = QLabel("SECURITY")
        sub_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #FFD93D; letter-spacing: 2px;")
        brand_text_layout.addWidget(app_title)
        brand_text_layout.addWidget(sub_title)
        brand_row.addLayout(brand_text_layout)
        brand_row.addStretch()
        layout.addLayout(brand_row)

        # Nav Buttons (11 Pages)
        self.nav_btn_group = QButtonGroup(self)
        self.nav_btn_group.setExclusive(True)

        pages = [
            ("Dashboard", "dashboard.svg", "📊", 0),
            ("Quick Scan", "quick_scan.svg", "⚡", 1),
            ("Full Scan", "full_scan.svg", "🔍", 2),
            ("Custom Scan", "custom_scan.svg", "📁", 3),
            ("Port Scanner", "port_scanner.svg", "🌐", 4),
            ("Updates & Vulns", "vuln.svg", "⚠️", 5),
            ("AI Neural Scan", "ai_scan.svg", "🤖", 6),
            ("Security Tools", "tools.svg", "🛠️", 7),
            ("Quarantine", "quarantine.svg", "🔒", 8),
            ("Audit Reports", "reports.svg", "📑", 9),
            ("Settings", "settings.svg", "⚙️", 10),
        ]

        self.nav_buttons = {}
        for title, icon_file, fallback_symbol, page_idx in pages:
            btn = QPushButton(f"  {fallback_symbol}  {title}")
            btn.setProperty("sidebar", True)
            btn.setCheckable(True)

            # Try loading SVG icon
            svg_path = ICONS_DIR / icon_file
            if svg_path.exists():
                btn.setIcon(QIcon(str(svg_path)))
                btn.setIconSize(QSize(18, 18))
                btn.setText(f"  {title}")

            btn.clicked.connect(lambda _, idx=page_idx: self.navigate_to_page(idx))
            self.nav_btn_group.addButton(btn, page_idx)
            self.nav_buttons[page_idx] = btn
            layout.addWidget(btn)

        layout.addStretch()

        # Bottom Shield Status Pill
        shield_frame = QFrame()
        shield_frame.setProperty("subcard", True)
        sf_layout = QHBoxLayout(shield_frame)
        sf_layout.setContentsMargins(10, 8, 10, 8)

        status_dot = QLabel("●")
        status_dot.setStyleSheet("color: #A3BE8C; font-size: 14px;")
        sf_layout.addWidget(status_dot)

        status_text = QLabel("Shield Active")
        status_text.setStyleSheet("color: #ECEFF4; font-size: 11px; font-weight: bold;")
        sf_layout.addWidget(status_text)
        sf_layout.addStretch()

        ver_lbl = QLabel("v1.0.0")
        ver_lbl.setStyleSheet("color: #9BA3AF; font-size: 10px;")
        sf_layout.addWidget(ver_lbl)
        layout.addWidget(shield_frame)

        # Set Dashboard as initial active
        if 0 in self.nav_buttons:
            self.nav_buttons[0].setChecked(True)

        return sidebar

    def navigate_to_page(self, index: int):
        self.stacked_pages.setCurrentIndex(index)
        if index in self.nav_buttons:
            self.nav_buttons[index].setChecked(True)

        # Refresh page state if needed
        if index == 0:
            self.page_dashboard.refresh_dashboard()
        elif index == 1:
            self.page_quick_scan.set_mode("Quick")
        elif index == 2:
            self.page_full_scan.set_mode("Full")
        elif index == 3:
            self.page_custom_scan.set_mode("Custom")

    def _on_ai_explain_requested(self, threat: dict):
        # Switch to AI Scan page (Index 6) and pass threat
        self.navigate_to_page(6)
        self.page_ai.explain_external_threat(threat)
