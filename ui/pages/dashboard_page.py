"""
Fikrado Security - Dashboard Page
Executive security overview with animated circular score gauge, KPI stat cards,
system hardening summary, and recent threat activity feed.
"""
import time

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
from core.system_info import get_hardening_audit
from tools.realtime_guard import realtime_guard
from ui.components.cards import StatCard, ThreatBadge
from ui.components.circular_gauge import CircularSecurityGauge
from ui.components.loading_overlay import LoadingOverlay
from ui.components.toast import ToastNotification
from ui.effects import apply_text_glow, update_glow
from ui.formatting import display_path
from ui.icons import icon_label, refresh_icon_label, set_icon
from ui.workers import FunctionWorker


class DashboardPage(QWidget):
    navigate_to_page = Signal(int)  # Emits target page index

    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings = SettingsManager()
        self._last_audit = None
        self._audit_worker = None
        self._last_refresh_at = 0.0
        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(30, 25, 30, 25)
        main_layout.setSpacing(20)

        # Title & Subtitle
        header_layout = QVBoxLayout()
        header_layout.setSpacing(4)
        title = QLabel("Security Dashboard")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #ECEFF4; background: transparent;")
        apply_text_glow(title, "#CFEAF1", blur=18, opacity=115)
        header_layout.addWidget(title)

        subtitle = QLabel("Real-time threat telemetry, security posture scoring, and endpoint status.")
        subtitle.setStyleSheet("color: #9BA3AF; font-size: 13px;")
        subtitle.setWordWrap(True)
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
        set_icon(audit_btn, "refresh", 16)
        audit_btn.clicked.connect(lambda: self.refresh_dashboard(force_audit=True))
        score_layout.addWidget(audit_btn)

        self.score_overlay = LoadingOverlay(score_card, "Auditing Windows security posture…")
        top_grid.addWidget(score_card, 1)

        # 2. Main Status & Quick Action Card
        status_card = QFrame()
        status_card.setProperty("card", True)
        status_layout = QVBoxLayout(status_card)
        status_layout.setContentsMargins(24, 20, 24, 20)
        status_layout.setSpacing(12)

        status_header = QHBoxLayout()
        status_header.setSpacing(10)
        self.status_icon = icon_label("shield", 24)
        status_header.addWidget(self.status_icon)
        self.status_title = QLabel("All Systems Protected")
        self.status_title.setStyleSheet(
            "font-size: 18px; font-weight: bold; color: #88C0D0; background: transparent;"
        )
        apply_text_glow(self.status_title, "#88C0D0", blur=15, opacity=130)
        status_header.addWidget(self.status_title)
        status_header.addStretch()
        status_layout.addLayout(status_header)

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

        quick_scan_btn = QPushButton("Run Quick Scan")
        quick_scan_btn.setProperty("primary", True)
        set_icon(quick_scan_btn, "quick_scan", 16)
        quick_scan_btn.clicked.connect(lambda: self.navigate_to_page.emit(1))
        actions_row.addWidget(quick_scan_btn)

        full_scan_btn = QPushButton("Deep Full Scan")
        full_scan_btn.setProperty("secondary", True)
        set_icon(full_scan_btn, "full_scan", 16)
        full_scan_btn.clicked.connect(lambda: self.navigate_to_page.emit(2))
        actions_row.addWidget(full_scan_btn)

        ports_btn = QPushButton("Scan Ports")
        ports_btn.setProperty("secondary", True)
        set_icon(ports_btn, "port_scanner", 16)
        ports_btn.clicked.connect(lambda: self.navigate_to_page.emit(4))
        actions_row.addWidget(ports_btn)

        tools_btn = QPushButton("Tools Hub")
        tools_btn.setProperty("secondary", True)
        set_icon(tools_btn, "tools", 16)
        tools_btn.clicked.connect(lambda: self.navigate_to_page.emit(7))
        actions_row.addWidget(tools_btn)

        status_layout.addLayout(actions_row)
        top_grid.addWidget(status_card, 2)
        main_layout.addLayout(top_grid)

        # Stats Cards Row
        stats_row = QHBoxLayout()
        stats_row.setSpacing(15)

        self.card_files = StatCard("Files Scanned", "0", "Total objects analyzed", "#88C0D0", "stat_files")
        self.card_threats = StatCard("Threats Blocked", "0", "Malware & PUPs blocked", "#BF616A", "stat_threats")
        self.card_realtime = StatCard("Real-Time Guard", "ACTIVE", "Processes, files, startup & network", "#A3BE8C", "stat_realtime")
        self.card_vulns = StatCard("Known CVEs", "0", "CISA KEV active exploits", "#EBCB8B", "stat_vulns")

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
        threat_header = self.threat_table.horizontalHeader()
        threat_header.setSectionResizeMode(0, QHeaderView.Fixed)
        threat_header.setSectionResizeMode(1, QHeaderView.Stretch)
        threat_header.setSectionResizeMode(2, QHeaderView.Fixed)
        threat_header.setSectionResizeMode(3, QHeaderView.Fixed)
        threat_header.setSectionResizeMode(4, QHeaderView.Stretch)
        self.threat_table.setColumnWidth(0, 92)
        self.threat_table.setColumnWidth(2, 112)
        self.threat_table.setColumnWidth(3, 152)
        self.threat_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.threat_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.threat_table.setFixedHeight(180)
        threats_layout.addWidget(self.threat_table)

        main_layout.addWidget(threats_card)

        # Load dynamic state
        self.refresh_dashboard()

    def _set_status(self, text: str, color: str, icon_name: str = "shield"):
        """Updates the posture headline, icon and glow color together."""
        self.status_title.setText(text)
        self.status_title.setStyleSheet(
            f"font-size: 18px; font-weight: bold; color: {color}; background: transparent;"
        )
        refresh_icon_label(self.status_icon, icon_name, 24)
        update_glow(self.status_title, color, 130)

    def refresh_dashboard(self, force_audit: bool = False):
        """Refreshes statistics, score, and threat history without blocking the UI."""
        now = time.monotonic()
        if (
            not force_audit
            and self._last_audit is not None
            and now - self._last_refresh_at < 2.0
        ):
            return

        stats = db.count_stats()
        self.card_files.set_value(f"{stats.get('total_files', 0):,}")
        self.card_threats.set_value(f"{stats.get('total_threats', 0):,}")
        self.card_vulns.set_value(f"{stats.get('kev_count', 0):,}")

        # Real-time state reflects the live guard, not just the saved preference.
        rt_active = realtime_guard.is_active
        self.card_realtime.set_value("ACTIVE" if rt_active else "PAUSED")
        self.card_realtime.set_accent("#A3BE8C" if rt_active else "#EBCB8B")

        if self._last_audit is not None and not force_audit:
            self._apply_audit(*self._last_audit)
        else:
            self._start_audit(force_audit)

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

            full_path = t.get("file_path", "")
            path_item = QTableWidgetItem(display_path(full_path))
            path_item.setToolTip(full_path)
            self.threat_table.setItem(row, 4, path_item)

        self._last_refresh_at = time.monotonic()

    def _start_audit(self, force: bool = False):
        if self._audit_worker is not None and self._audit_worker.isRunning():
            return

        self.score_overlay.show_message("Auditing Windows security posture…")
        if self._last_audit is None:
            self._set_status("Auditing Security Posture…", "#88C0D0", "shield")

        worker = FunctionWorker(
            lambda: get_hardening_audit(force=force, deep=force), self
        )
        self._audit_worker = worker
        worker.finished_ok.connect(self._on_audit_finished)
        worker.failed.connect(self._on_audit_failed)
        worker.finished.connect(lambda w=worker: self._release_audit_worker(w))
        worker.start()

    def _release_audit_worker(self, worker):
        if self._audit_worker is worker:
            self._audit_worker = None

    def _on_audit_finished(self, result):
        self.score_overlay.hide_overlay()
        checks, score = result
        self._last_audit = (checks, score)
        self._apply_audit(checks, score)

    def _on_audit_failed(self, message: str):
        self.score_overlay.hide_overlay()
        self._set_status("Security Audit Unavailable", "#EBCB8B", "warning")
        ToastNotification(
            self.window(), "Posture Audit", f"Could not complete the audit: {message}", "error"
        )

    def _apply_audit(self, checks, score: int):
        if self.gauge.get_score() != score:
            self.gauge.set_score(score, animated=True)

        if score >= 80:
            self._set_status("All Systems Protected", "#88C0D0", "shield")
        elif score >= 50:
            self._set_status("Security Posture Attention Required", "#EBCB8B", "warning")
        else:
            self._set_status("Critical Vulnerabilities Detected", "#BF616A", "vuln")
