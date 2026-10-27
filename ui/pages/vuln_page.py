"""
Fikrado Security - Known and Emerging Vulnerability Check Page
Audits installed applications against the CISA Known Exploited Vulnerabilities (KEV) catalog,
enumerates outdated packages via winget, and inspects Windows hotfixes.
"""
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget
)
from core.updater import update_cisa_kev_online
from scanners.vuln_scanner import (
    correlate_with_cisa_kev,
    execute_winget_upgrade,
    get_installed_software,
    get_windows_hotfixes,
    get_winget_upgrades
)
from ui.components.cards import ThreatBadge
from ui.components.toast import ToastNotification
from ui.icons import set_icon


class VulnAuditThread(QThread):
    finished = Signal(list, list, list, list)  # software, cisa_matches, winget_upgrades, hotfixes

    def run(self):
        software = get_installed_software()
        cisa_matches = correlate_with_cisa_kev(software)
        winget_upgrades = get_winget_upgrades()
        hotfixes = get_windows_hotfixes()
        self.finished.emit(software, cisa_matches, winget_upgrades, hotfixes)


class UpgradeWorkerThread(QThread):
    finished = Signal(bool, str)

    def __init__(self, app_id: str):
        super().__init__()
        self.app_id = app_id

    def run(self):
        ok, msg = execute_winget_upgrade(self.app_id)
        self.finished.emit(ok, msg)


class VulnPage(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 25, 30, 25)
        layout.setSpacing(18)

        # Header with Honest Labeling
        header = QVBoxLayout()
        header.setSpacing(4)
        title = QLabel("Known and Emerging Vulnerability Check")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #ECEFF4;")
        header.addWidget(title)

        disclaimer = QLabel(
            "<b>Transparency Notice:</b> True zero-day vulnerabilities unknown to the public cannot be detected by any software. "
            "This scanner audits your endpoint against actively exploited CVEs from the official <b>CISA KEV catalog</b> "
            "and identifies unpatched applications with available upstream fixes."
        )
        disclaimer.setWordWrap(True)
        disclaimer.setStyleSheet("color: #88C0D0; font-size: 12px; background-color: rgba(136, 192, 208, 26); padding: 8px 12px; border-radius: 6px; border-left: 4px solid #FFD93D;")
        header.addWidget(disclaimer)
        layout.addLayout(header)

        # Top Control Row
        ctrl_row = QHBoxLayout()
        self.refresh_btn = QPushButton("Scan for Vulnerabilities && Updates")
        self.refresh_btn.setProperty("primary", True)
        set_icon(self.refresh_btn, "search", 15, "#1A1F27")
        self.refresh_btn.clicked.connect(self.start_audit)
        ctrl_row.addWidget(self.refresh_btn)

        sync_kev_btn = QPushButton("Sync CISA KEV Feed")
        sync_kev_btn.setProperty("secondary", True)
        set_icon(sync_kev_btn, "cloud", 15)
        sync_kev_btn.clicked.connect(self.sync_cisa_catalog)
        ctrl_row.addWidget(sync_kev_btn)

        ctrl_row.addStretch()
        layout.addLayout(ctrl_row)

        # Tab Widget
        self.tabs = QTabWidget()

        # Tab 1: CISA KEV Exploited Vulnerabilities
        tab_kev = QWidget()
        tk_layout = QVBoxLayout(tab_kev)
        tk_layout.setContentsMargins(15, 15, 15, 15)

        self.kev_table = QTableWidget(0, 6)
        self.kev_table.setHorizontalHeaderLabels(["Status", "Advisory CVE", "Product", "Vulnerability Title", "Date Added", "Required Mitigation"])
        kev_header = self.kev_table.horizontalHeader()
        kev_header.setSectionResizeMode(0, QHeaderView.Fixed)
        kev_header.setSectionResizeMode(1, QHeaderView.Fixed)
        kev_header.setSectionResizeMode(2, QHeaderView.Fixed)
        kev_header.setSectionResizeMode(3, QHeaderView.Stretch)
        kev_header.setSectionResizeMode(4, QHeaderView.Fixed)
        kev_header.setSectionResizeMode(5, QHeaderView.Fixed)
        self.kev_table.setColumnWidth(0, 78)
        self.kev_table.setColumnWidth(1, 128)
        self.kev_table.setColumnWidth(2, 148)
        self.kev_table.setColumnWidth(4, 96)
        self.kev_table.setColumnWidth(5, 210)
        self.kev_table.setEditTriggers(QTableWidget.NoEditTriggers)
        tk_layout.addWidget(self.kev_table)
        self.tabs.addTab(tab_kev, "Actively Exploited (CISA KEV)")

        # Tab 2: Outdated Software (winget)
        tab_winget = QWidget()
        tw_layout = QVBoxLayout(tab_winget)
        tw_layout.setContentsMargins(15, 15, 15, 15)
        tw_layout.setSpacing(10)

        tw_header = QHBoxLayout()
        tw_desc = QLabel("Applications with available security and feature updates via winget:")
        tw_desc.setStyleSheet("color: #D8DEE9; font-size: 13px;")
        tw_header.addWidget(tw_desc)
        tw_header.addStretch()

        self.update_btn = QPushButton("Update Selected via winget")
        self.update_btn.setProperty("primary", True)
        set_icon(self.update_btn, "update", 15, "#1A1F27")
        self.update_btn.clicked.connect(self.update_selected_package)
        tw_header.addWidget(self.update_btn)
        tw_layout.addLayout(tw_header)

        self.winget_table = QTableWidget(0, 4)
        self.winget_table.setHorizontalHeaderLabels(["Application Name", "Package ID", "Installed Version", "Available Version"])
        winget_header = self.winget_table.horizontalHeader()
        winget_header.setSectionResizeMode(0, QHeaderView.Stretch)
        winget_header.setSectionResizeMode(1, QHeaderView.Stretch)
        winget_header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        winget_header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.winget_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.winget_table.setEditTriggers(QTableWidget.NoEditTriggers)
        tw_layout.addWidget(self.winget_table)
        self.tabs.addTab(tab_winget, "Outdated Software (winget)")

        # Tab 3: Installed Windows Hotfixes
        tab_hotfixes = QWidget()
        th_layout = QVBoxLayout(tab_hotfixes)
        th_layout.setContentsMargins(15, 15, 15, 15)

        self.hotfix_table = QTableWidget(0, 3)
        self.hotfix_table.setHorizontalHeaderLabels(["Hotfix KB Identifier", "Classification", "Installed Date"])
        hotfix_header = self.hotfix_table.horizontalHeader()
        hotfix_header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hotfix_header.setSectionResizeMode(1, QHeaderView.Stretch)
        hotfix_header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.hotfix_table.setEditTriggers(QTableWidget.NoEditTriggers)
        th_layout.addWidget(self.hotfix_table)
        self.tabs.addTab(tab_hotfixes, "Windows Security Hotfixes")

        # Tab 4: All Installed Software Inventory
        tab_all = QWidget()
        ta_layout = QVBoxLayout(tab_all)
        ta_layout.setContentsMargins(15, 15, 15, 15)

        self.all_software_table = QTableWidget(0, 3)
        self.all_software_table.setHorizontalHeaderLabels(["Application Name", "Version", "Publisher"])
        all_software_header = self.all_software_table.horizontalHeader()
        all_software_header.setSectionResizeMode(0, QHeaderView.Stretch)
        all_software_header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        all_software_header.setSectionResizeMode(2, QHeaderView.Stretch)
        self.all_software_table.setEditTriggers(QTableWidget.NoEditTriggers)
        ta_layout.addWidget(self.all_software_table)
        self.tabs.addTab(tab_all, "Software Inventory")

        layout.addWidget(self.tabs)

        # Start initial scan in background
        self.start_audit()

    def start_audit(self):
        self.refresh_btn.setEnabled(False)
        self.refresh_btn.setText("Auditing Installed Software...")
        self.worker = VulnAuditThread()
        self.worker.finished.connect(self._on_audit_finished)
        self.worker.start()

    def sync_cisa_catalog(self):
        ToastNotification(self.window(), "Syncing CISA KEV", "Connecting to CISA feeds...", "info")
        ok, msg = update_cisa_kev_online()
        if ok:
            ToastNotification(self.window(), "Sync Complete", msg, "success")
            self.start_audit()
        else:
            ToastNotification(self.window(), "Sync Notice", msg, "warning")

    def _on_audit_finished(self, software, cisa_matches, winget_upgrades, hotfixes):
        self.refresh_btn.setEnabled(True)
        self.refresh_btn.setText("Scan for Vulnerabilities && Updates")

        # 1. Populate CISA KEV Table
        self.kev_table.setRowCount(0)
        for m in cisa_matches:
            row = self.kev_table.rowCount()
            self.kev_table.insertRow(row)
            self.kev_table.setCellWidget(row, 0, ThreatBadge("CRITICAL"))

            cve_item = QTableWidgetItem(m.get("cve_id"))
            cve_item.setForeground(Qt.white)
            self.kev_table.setItem(row, 1, cve_item)
            self.kev_table.setItem(row, 2, QTableWidgetItem(f"{m.get('vendor')} {m.get('product')}"))
            self.kev_table.setItem(row, 3, QTableWidgetItem(m.get("vulnerability_name")))
            self.kev_table.setItem(row, 4, QTableWidgetItem(m.get("date_added")))
            self.kev_table.setItem(row, 5, QTableWidgetItem(m.get("required_action")))

        # 2. Populate Winget Table
        self.winget_table.setRowCount(0)
        for w in winget_upgrades:
            row = self.winget_table.rowCount()
            self.winget_table.insertRow(row)
            self.winget_table.setItem(row, 0, QTableWidgetItem(w.get("name")))
            self.winget_table.setItem(row, 1, QTableWidgetItem(w.get("id")))
            self.winget_table.setItem(row, 2, QTableWidgetItem(w.get("installed_version")))
            avail_item = QTableWidgetItem(w.get("available_version"))
            avail_item.setForeground(Qt.yellow)
            self.winget_table.setItem(row, 3, avail_item)

        # 3. Populate Hotfixes Table
        self.hotfix_table.setRowCount(0)
        for h in hotfixes:
            row = self.hotfix_table.rowCount()
            self.hotfix_table.insertRow(row)
            self.hotfix_table.setItem(row, 0, QTableWidgetItem(h.get("hotfix_id")))
            self.hotfix_table.setItem(row, 1, QTableWidgetItem(h.get("description")))
            self.hotfix_table.setItem(row, 2, QTableWidgetItem(h.get("installed_on")))

        # 4. Populate All Software Table
        self.all_software_table.setRowCount(0)
        for s in software:
            row = self.all_software_table.rowCount()
            self.all_software_table.insertRow(row)
            self.all_software_table.setItem(row, 0, QTableWidgetItem(s.get("name")))
            self.all_software_table.setItem(row, 1, QTableWidgetItem(s.get("version")))
            self.all_software_table.setItem(row, 2, QTableWidgetItem(s.get("publisher")))

        ToastNotification(
            self.window(),
            "Vulnerability Audit Completed",
            f"Audited {len(software)} software packages. Found {len(cisa_matches)} KEV advisories and {len(winget_upgrades)} upgrades.",
            "info"
        )

    def update_selected_package(self):
        selected_rows = self.winget_table.selectedIndexes()
        if not selected_rows:
            ToastNotification(self.window(), "Select Package", "Please select an outdated software package from the table.", "warning")
            return
        row = selected_rows[0].row()
        pkg_id = self.winget_table.item(row, 1).text()

        ToastNotification(self.window(), "Upgrade Initiated", f"Running winget upgrade for {pkg_id}...", "info")
        self.update_btn.setEnabled(False)
        self.up_thread = UpgradeWorkerThread(pkg_id)
        self.up_thread.finished.connect(self._on_upgrade_finished)
        self.up_thread.start()

    def _on_upgrade_finished(self, ok: bool, msg: str):
        self.update_btn.setEnabled(True)
        level = "success" if ok else "error"
        ToastNotification(self.window(), "Winget Upgrade Result", msg, level)
        if ok:
            self.start_audit()
