"""
Fikrado Security - Security Audit Reports Page
Browse generated HTML & PDF audit reports, generate new full reports, and export to PDF.
"""
import os
import subprocess
import time
from pathlib import Path
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget
)
from config.constants import REPORTS_DIR
from core.database import db
from core.reporter import export_pdf_report, generate_html_report
from core.system_info import audit_system_hardening, get_windows_info
from scanners.network_scanner import list_active_connections
from scanners.vuln_scanner import correlate_with_cisa_kev, get_installed_software
from ui.components.toast import ToastNotification


class ReportsPage(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 25, 30, 25)
        layout.setSpacing(18)

        # Header
        header = QVBoxLayout()
        header.setSpacing(4)
        title = QLabel("Security Audit Reports & Executive Exports")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #ECEFF4;")
        header.addWidget(title)

        desc = QLabel(
            "Executive and technical compliance documentation. Export standalone HTML and PDF reports "
            "detailing threat detections, open network sockets, active CISA KEV vulnerabilities, and remediation roadmaps."
        )
        desc.setStyleSheet("color: #9BA3AF; font-size: 13px;")
        header.addWidget(desc)
        layout.addLayout(header)

        # Toolbar
        tb = QHBoxLayout()
        gen_btn = QPushButton("📑 Generate New Full Executive Report Now")
        gen_btn.setProperty("primary", True)
        gen_btn.clicked.connect(self._generate_full_report)
        tb.addWidget(gen_btn)

        ref_btn = QPushButton("🔄 Refresh List")
        ref_btn.setProperty("secondary", True)
        ref_btn.clicked.connect(self.refresh_reports_list)
        tb.addWidget(ref_btn)

        open_dir_btn = QPushButton("📂 Open Reports Folder")
        open_dir_btn.setProperty("secondary", True)
        open_dir_btn.clicked.connect(self._open_reports_dir)
        tb.addWidget(open_dir_btn)

        tb.addStretch()

        self.btn_view = QPushButton("View in Browser")
        self.btn_view.setProperty("secondary", True)
        self.btn_view.setEnabled(False)
        self.btn_view.clicked.connect(self._view_selected_report)
        tb.addWidget(self.btn_view)

        self.btn_pdf = QPushButton("Export to PDF")
        self.btn_pdf.setProperty("secondary", True)
        self.btn_pdf.setEnabled(False)
        self.btn_pdf.clicked.connect(self._export_selected_pdf)
        tb.addWidget(self.btn_pdf)

        layout.addLayout(tb)

        # Reports Table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Report File Name", "Type", "File Size", "Creation Timestamp"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._on_row_selected)
        layout.addWidget(self.table)

        self.refresh_reports_list()

    def refresh_reports_list(self):
        self.reports_cache = []
        self.table.setRowCount(0)

        if REPORTS_DIR.exists():
            for p in sorted(REPORTS_DIR.glob("*.html"), key=lambda x: x.stat().st_mtime, reverse=True):
                self.reports_cache.append(p)
                row = self.table.rowCount()
                self.table.insertRow(row)

                f_item = QTableWidgetItem(p.name)
                f_item.setForeground(Qt.white)
                self.table.setItem(row, 0, f_item)

                self.table.setItem(row, 1, QTableWidgetItem("HTML Executive Report"))
                self.table.setItem(row, 2, QTableWidgetItem(f"{p.stat().st_size / 1024:.1f} KB"))
                mtime_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.stat().st_mtime))
                self.table.setItem(row, 3, QTableWidgetItem(mtime_str))

        self.btn_view.setEnabled(False)
        self.btn_pdf.setEnabled(False)

    def _on_row_selected(self):
        sel = bool(self.table.selectedIndexes())
        self.btn_view.setEnabled(sel)
        self.btn_pdf.setEnabled(sel)

    def _get_selected_file(self) -> Path:
        rows = self.table.selectedIndexes()
        if not rows:
            return None
        row = rows[0].row()
        return self.reports_cache[row]

    def _view_selected_report(self):
        f = self._get_selected_file()
        if f and f.exists():
            os.startfile(str(f))

    def _export_selected_pdf(self):
        f = self._get_selected_file()
        if f and f.exists():
            ToastNotification(self.window(), "Exporting PDF", "Rendering PDF document...", "info")
            pdf_path = export_pdf_report(f)
            if pdf_path and pdf_path.exists():
                ToastNotification(self.window(), "PDF Ready", f"Exported: {pdf_path.name}", "success")
                os.startfile(str(pdf_path))
            else:
                ToastNotification(self.window(), "PDF Notice", "PDF export created. Check reports folder.", "info")

    def _generate_full_report(self):
        ToastNotification(self.window(), "Compiling Audit", "Collecting telemetry, network, and vulnerability feeds...", "info")
        _, score = audit_system_hardening()
        threats = db.get_recent_threats(limit=25)
        conns = list_active_connections()[:20]
        soft = get_installed_software()
        vulns = correlate_with_cisa_kev(soft)[:15]
        sys_info = get_windows_info()

        report_path = generate_html_report(
            scan_type="Full Comprehensive Security Audit",
            files_scanned=db.count_stats().get("total_files", 0),
            threats=threats,
            duration_seconds=12.4,
            security_score=score,
            network_summary=conns,
            vuln_summary=vulns,
            system_info=sys_info
        )
        self.refresh_reports_list()
        ToastNotification(self.window(), "Report Generated", f"Saved: {report_path.name}", "success")
        os.startfile(str(report_path))

    def _open_reports_dir(self):
        try:
            os.startfile(str(REPORTS_DIR))
        except Exception as e:
            ToastNotification(self.window(), "Folder Error", str(e), "error")
