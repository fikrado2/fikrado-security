"""
Fikrado Security - Dashboard Page
Executive security overview with animated circular score gauge, KPI stat cards,
system hardening summary, and recent threat activity feed.
"""
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget
)
from config.settings import SettingsManager
from core.database import db
from core.system_info import audit_system_hardening
from tools.realtime_guard import realtime_guard
from ui.components.cards import StatCard, ThreatBadge
from ui.components.circular_gauge import CircularSecurityGauge


class DashboardPage(QWidget):
    navigate_to_page = Signal(int)  # Emits target page index

    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings = SettingsManager()
        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(30, 25, 30, 25)
        main_layout.setSpacing(20)

        # Title & Subtitle
        header_layout = QVBoxLayout()
        header_layout.setSpacing(4)
        title = QLabel("Security Dashboard")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #ECEFF4;")
        header_layout.addWidget(title)

        subtitle = QLabel("Real-time threat telemetry, security posture scoring, and endpoint status.")
        subtitle.setStyleSheet("color: #9BA3AF; font-size: 13px;")
        header_layout.addWidget(subtitle)
        main_layout.addLayout(header_layout)

        # Top Grid: Circular Score + System Status & Quick Actions
        top_grid = QHBoxLayout()
        top_grid.setSpacing(20)

        # 1. Circular Score Card
        score_card = QFrame()
        score_card.setProperty("card", True)
        score_layout = QVBoxLayout(score_card)
        score_layout.setContentsMargins(20, 20, 20, 20)
        score_layout.setAlignment(Qt.AlignCenter)

        self.gauge = CircularSecurityGauge(size=170)
        score_layout.addWidget(self.gauge)

        audit_btn = QPushButton("Re-audit Posture")
        audit_btn.setProperty("secondary", True)
        audit_btn.clicked.connect(self.refresh_dashboard)
        score_layout.addWidget(audit_btn)

        top_grid.addWidget(score_card, 1)

        # 2. Main Status & Quick Action Card
        status_card = QFrame()
        status_card.setProperty("card", True)
        status_layout = QVBoxLayout(status_card)
        status_layout.setContentsMargins(24, 20, 24, 20)
        status_layout.setSpacing(12)

        self.status_title = QLabel("🛡️ All Systems Protected")
        self.status_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #88C0D0;")
        status_layout.addWidget(self.status_title)

        self.status_desc = QLabel(
            "Fikrado real-time heuristic shield, YARA rules, and Windows Defender are actively monitoring "
            "filesystem activity, background processes, and network sockets."
        )
        self.status_desc.setWordWrap(True)
        self.status_desc.setStyleSheet("color: #D8DEE9; font-size: 13px; line-height: 1.4;")
        status_layout.addWidget(self.status_desc)

        status_layout.addStretch()

        # Action Buttons Row
        actions_row = QHBoxLayout()
        actions_row.setSpacing(12)

        quick_scan_btn = QPushButton("⚡ Run Quick Scan")
        quick_scan_btn.setProperty("primary", True)
        quick_scan_btn.clicked.connect(lambda: self.navigate_to_page.emit(1))
        actions_row.addWidget(quick_scan_btn)

        full_scan_btn = QPushButton("🔍 Deep Full Scan")
        full_scan_btn.setProperty("secondary", True)
        full_scan_btn.clicked.connect(lambda: self.navigate_to_page.emit(2))
        actions_row.addWidget(full_scan_btn)

        ports_btn = QPushButton("🌐 Scan Ports")
        ports_btn.setProperty("secondary", True)
        ports_btn.clicked.connect(lambda: self.navigate_to_page.emit(4))
        actions_row.addWidget(ports_btn)

        tools_btn = QPushButton("🛠️ Tools Hub")
        tools_btn.setProperty("secondary", True)
        tools_btn.clicked.connect(lambda: self.navigate_to_page.emit(7))
        actions_row.addWidget(tools_btn)

        status_layout.addLayout(actions_row)
        top_grid.addWidget(status_card, 2)
        main_layout.addLayout(top_grid)

        # Stats Cards Row
        stats_row = QHBoxLayout()
        stats_row.setSpacing(15)

        self.card_files = StatCard("Files Scanned", "0", "Total objects analyzed", "#88C0D0", "📂")
        self.card_threats = StatCard("Threats Neutralized", "0", "Malware & PUPs blocked", "#BF616A", "🛡️")
        self.card_realtime = StatCard("Real-Time Guard", "ACTIVE", "Monitoring Downloads & Temp", "#A3BE8C", "⚡")
        self.card_vulns = StatCard("Known CVEs Tracked", "0", "CISA KEV active exploits", "#EBCB8B", "⚠️")

        stats_row.addWidget(self.card_files)
        stats_row.addWidget(self.card_threats)
        stats_row.addWidget(self.card_realtime)
        stats_row.addWidget(self.card_vulns)
        main_layout.addLayout(stats_row)

        # Recent Threats Table Card
        threats_card = QFrame()
        threats_card.setProperty("card", True)
        threats_layout = QVBoxLayout(threats_card)
        threats_layout.setContentsMargins(20, 16, 20, 16)
        threats_layout.setSpacing(10)

        t_header = QHBoxLayout()
        t_title = QLabel("Recent Security Events & Interceptions")
        t_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #ECEFF4;")
        t_header.addWidget(t_title)
        t_header.addStretch()

        view_quarantine_btn = QPushButton("View Quarantine")
        view_quarantine_btn.setProperty("secondary", True)
        view_quarantine_btn.clicked.connect(lambda: self.navigate_to_page.emit(8))
        t_header.addWidget(view_quarantine_btn)
        threats_layout.addLayout(t_header)

        self.threat_table = QTableWidget(0, 5)
        self.threat_table.setHorizontalHeaderLabels(["Severity", "Threat Name", "Type", "Engine", "Target File / Path"])
        self.threat_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.threat_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.threat_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.threat_table.setFixedHeight(180)
        threats_layout.addWidget(self.threat_table)

        main_layout.addWidget(threats_card)

        # Load dynamic state
        self.refresh_dashboard()

    def refresh_dashboard(self):
        """Refreshes statistics, score, and threat history."""
        stats = db.count_stats()
        self.card_files.set_value(f"{stats.get('total_files', 0):,}")
        self.card_threats.set_value(f"{stats.get('total_threats', 0):,}")
        self.card_vulns.set_value(f"{stats.get('kev_count', 0):,}")

        # Real-time state
        rt_enabled = self.settings.get("realtime", "enabled", True)
        self.card_realtime.set_value("ACTIVE" if rt_enabled else "OFF")

        # System hardening audit
        checks, score = audit_system_hardening()
        self.gauge.set_score(score, animated=True)

        if score >= 80:
            self.status_title.setText("🛡️ All Systems Protected")
            self.status_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #88C0D0;")
        elif score >= 50:
            self.status_title.setText("⚠️ Security Posture Attention Required")
            self.status_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #EBCB8B;")
        else:
            self.status_title.setText("🚨 Critical Vulnerabilities Detected")
            self.status_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #BF616A;")

        # Populate recent threats table
        recent = db.get_recent_threats(limit=10)
        self.threat_table.setRowCount(0)
        for t in recent:
            row = self.threat_table.rowCount()
            self.threat_table.insertRow(row)

            badge = ThreatBadge(t.get("severity", "Medium"))
            self.threat_table.setCellWidget(row, 0, badge)

            name_item = QTableWidgetItem(t.get("threat_name", "N/A"))
            name_item.setForeground(Qt.white)
            self.threat_table.setItem(row, 1, name_item)

            self.threat_table.setItem(row, 2, QTableWidgetItem(t.get("threat_type", "Malware")))
            self.threat_table.setItem(row, 3, QTableWidgetItem(t.get("detection_engine", "Heuristic")))

            path_item = QTableWidgetItem(t.get("file_path", ""))
            path_item.setToolTip(t.get("file_path", ""))
            self.threat_table.setItem(row, 4, path_item)
