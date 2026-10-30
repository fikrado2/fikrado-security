"""
Fikrado Security - Threat Scan Page
Combined UI for Bootkit Scanner, Rootkit Scanner, and system-wide threat search.
"""
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from scanners.bootkit_scanner import scan_bootkit
from scanners.rootkit_scanner import scan_rootkit
from ui.components.cards import ThreatBadge
from ui.components.loading_overlay import LoadingOverlay
from ui.components.toast import ToastNotification
from ui.icons import set_icon
from ui.workers import FunctionWorker


class ThreatScanWorker(QThread):
    bootkit_done = Signal(list)
    rootkit_done = Signal(list)

    def run(self):
        bootkit = scan_bootkit()
        self.bootkit_done.emit(bootkit)
        rootkit = scan_rootkit()
        self.rootkit_done.emit(rootkit)


class ThreatScanPage(QWidget):
    """Bootkit & Rootkit scan UI with integrated search and system scan."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._bootkit_results: list = []
        self._rootkit_results: list = []
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 25, 30, 25)
        layout.setSpacing(18)

        # ── Header ──────────────────────────────────────────────────────────
        header = QVBoxLayout()
        header.setSpacing(4)
        title = QLabel("Advanced Threat Scanner")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #ECEFF4;")
        header.addWidget(title)

        desc = QLabel(
            "Deep integrity checks for bootkits and rootkits — pre-boot malware that hides "
            "below the OS. Also searches running processes, loaded modules, and startup items."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #9BA3AF; font-size: 13px;")
        header.addWidget(desc)
        layout.addLayout(header)

        # ── Search Bar ──────────────────────────────────────────────────────
        search_row = QHBoxLayout()
        search_row.setSpacing(10)
        self.global_search = QLineEdit()
        self.global_search.setPlaceholderText("🔍  Search threats by name, type, or indicator…")
        self.global_search.setStyleSheet("""
            QLineEdit {
                background: rgba(59, 66, 82, 180);
                border: 1px solid rgba(136, 192, 208, 60);
                border-radius: 8px;
                padding: 8px 14px;
                color: #ECEFF4;
                font-size: 13px;
            }
            QLineEdit:focus { border-color: #58A6FF; }
            QLineEdit::placeholder { color: #9BA3AF; }
        """)
        self.global_search.textChanged.connect(self._filter_results)
        search_row.addWidget(self.global_search, 1)

        self.global_status = QLabel("All Clear")
        self.global_status.setStyleSheet(
            "color: #A3BE8C; font-weight: bold; font-size: 13px; background: rgba(163, 190, 140, 30); "
            "padding: 6px 14px; border-radius: 20px;"
        )
        search_row.addWidget(self.global_status)
        layout.addLayout(search_row)

        # ── Control Row ─────────────────────────────────────────────────────
        ctrl = QHBoxLayout()
        ctrl.setSpacing(10)

        self.scan_btn = QPushButton("▶  Scan Bootkits & Rootkits")
        self.scan_btn.setProperty("primary", True)
        set_icon(self.scan_btn, "shield", 15, "#1A1F27")
        self.scan_btn.clicked.connect(self._start_scan)
        ctrl.addWidget(self.scan_btn)

        self.stop_btn = QPushButton("■  Stop Scan")
        self.stop_btn.setProperty("danger", True)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_scan)
        ctrl.addWidget(self.stop_btn)

        ctrl.addStretch()

        # Quick stats
        self.stat_bootkit = QLabel("Bootkit: —")
        self.stat_bootkit.setStyleSheet("color: #9BA3AF; font-size: 12px;")
        ctrl.addWidget(self.stat_bootkit)
        self.stat_rootkit = QLabel("Rootkit: —")
        self.stat_rootkit.setStyleSheet("color: #9BA3AF; font-size: 12px;")
        ctrl.addWidget(self.stat_rootkit)
        layout.addLayout(ctrl)

        # ── Results Tabs ───────────────────────────────────────────────────
        self.tabs = QTabWidget()

        # Tab 1: All Findings
        self.tabs.addTab(self._build_all_tab(), "⚠  All Findings")
        # Tab 2: Bootkit Results
        self.tabs.addTab(self._build_bootkit_tab(), "🔒  Bootkit Scan")
        # Tab 3: Rootkit Results
        self.tabs.addTab(self._build_rootkit_tab(), "🔓  Rootkit Scan")

        layout.addWidget(self.tabs, 1)

        # Loading overlay
        self.overlay = LoadingOverlay(self, "Scanning boot sectors and kernel modules…")

    def _build_all_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)

        self.all_table = QTableWidget(0, 5)
        self.all_table.setHorizontalHeaderLabels(["Severity", "Type", "Finding", "Indicator", "Recommendation"])
        h = self.all_table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.Fixed)
        h.setSectionResizeMode(1, QHeaderView.Fixed)
        h.setSectionResizeMode(2, QHeaderView.Stretch)
        h.setSectionResizeMode(3, QHeaderView.Stretch)
        h.setSectionResizeMode(4, QHeaderView.Stretch)
        self.all_table.setColumnWidth(0, 90)
        self.all_table.setColumnWidth(1, 140)
        self.all_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.all_table.setSelectionBehavior(QTableWidget.SelectRows)
        l.addWidget(self.all_table)
        return w

    def _build_bootkit_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)

        self.bootkit_table = QTableWidget(0, 5)
        self.bootkit_table.setHorizontalHeaderLabels(["Severity", "Type", "Finding", "Indicator", "Recommendation"])
        h = self.bootkit_table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.Fixed)
        h.setSectionResizeMode(1, QHeaderView.Fixed)
        h.setSectionResizeMode(2, QHeaderView.Stretch)
        h.setSectionResizeMode(3, QHeaderView.Stretch)
        h.setSectionResizeMode(4, QHeaderView.Stretch)
        self.bootkit_table.setColumnWidth(0, 90)
        self.bootkit_table.setColumnWidth(1, 150)
        self.bootkit_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.bootkit_table.setSelectionBehavior(QTableWidget.SelectRows)
        l.addWidget(self.bootkit_table)
        return w

    def _build_rootkit_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)

        self.rootkit_table = QTableWidget(0, 5)
        self.rootkit_table.setHorizontalHeaderLabels(["Severity", "Type", "Finding", "Indicator", "Recommendation"])
        h = self.rootkit_table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.Fixed)
        h.setSectionResizeMode(1, QHeaderView.Fixed)
        h.setSectionResizeMode(2, QHeaderView.Stretch)
        h.setSectionResizeMode(3, QHeaderView.Stretch)
        h.setSectionResizeMode(4, QHeaderView.Stretch)
        self.rootkit_table.setColumnWidth(0, 90)
        self.rootkit_table.setColumnWidth(1, 150)
        self.rootkit_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.rootkit_table.setSelectionBehavior(QTableWidget.SelectRows)
        l.addWidget(self.rootkit_table)
        return w

    def _populate_table(self, table: QTableWidget, results: list):
        table.setRowCount(0)
        for r in results:
            row = table.rowCount()
            table.insertRow(row)

            badge = ThreatBadge(r.get("severity", "Medium"))
            table.setCellWidget(row, 0, badge)

            type_item = QTableWidgetItem(r.get("type", "Unknown"))
            type_item.setForeground(Qt.white)
            table.setItem(row, 1, type_item)

            detail_item = QTableWidgetItem(r.get("detail", ""))
            detail_item.setToolTip(r.get("detail", ""))
            table.setItem(row, 2, detail_item)

            indicator_item = QTableWidgetItem(r.get("indicator", ""))
            indicator_item.setToolTip(r.get("indicator", ""))
            indicator_item.setForeground(Qt.lightGray)
            table.setItem(row, 3, indicator_item)

            rec_item = QTableWidgetItem(r.get("recommendation", ""))
            rec_item.setToolTip(r.get("recommendation", ""))
            table.setItem(row, 4, rec_item)

    def _apply_results(self):
        all_results = self._bootkit_results + self._rootkit_results

        # Update all findings tab
        self._populate_table(self.all_table, all_results)

        # Update bootkit tab
        self._populate_table(self.bootkit_table, self._bootkit_results)

        # Update rootkit tab
        self._populate_table(self.rootkit_table, self._rootkit_results)

        # Update stats
        bootkit_count = len(self._bootkit_results)
        rootkit_count = len(self._rootkit_results)

        self.stat_bootkit.setText(f"Bootkit: {bootkit_count} {'⚠' if bootkit_count > 0 else '✔'}")
        self.stat_rootkit.setText(f"Rootkit: {rootkit_count} {'⚠' if rootkit_count > 0 else '✔'}")

        # Update global status
        total = len(all_results)
        if total == 0:
            self.global_status.setText("All Clear")
            self.global_status.setStyleSheet(
                "color: #A3BE8C; font-weight: bold; font-size: 13px; "
                "background: rgba(163, 190, 140, 30); padding: 6px 14px; border-radius: 20px;"
            )
        elif any(r.get("severity") == "Critical" for r in all_results):
            self.global_status.setText(f"⚠ {total} Threat(s) — CRITICAL")
            self.global_status.setStyleSheet(
                "color: #BF616A; font-weight: bold; font-size: 13px; "
                "background: rgba(191, 97, 106, 40); padding: 6px 14px; border-radius: 20px;"
            )
        else:
            self.global_status.setText(f"⚠ {total} Finding(s)")
            self.global_status.setStyleSheet(
                "color: #EBCB8B; font-weight: bold; font-size: 13px; "
                "background: rgba(235, 203, 139, 30); padding: 6px 14px; border-radius: 20px;"
            )

    def _filter_results(self, query: str):
        q = query.lower().strip()
        # Filter all results
        all_results = self._bootkit_results + self._rootkit_results
        if not q:
            filtered = all_results
        else:
            filtered = [
                r for r in all_results
                if q in f"{r.get('type','')} {r.get('detail','')} {r.get('indicator','')}".lower()
            ]
        self._populate_table(self.all_table, filtered)

    def _start_scan(self):
        self.overlay.show_message("Scanning boot sectors and kernel modules…")
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        self.worker = ThreatScanWorker()
        self.worker.bootkit_done.connect(self._on_bootkit_done)
        self.worker.rootkit_done.connect(self._on_rootkit_done)
        self.worker.start()

    def _on_bootkit_done(self, results: list):
        self._bootkit_results = results
        self._populate_table(self.bootkit_table, results)
        # Check if rootkit also done
        if hasattr(self, '_rootkit_results_processed') and self._rootkit_results_processed:
            self._finalize_scan()

    def _on_rootkit_done(self, results: list):
        self._rootkit_results = results
        self._populate_table(self.rootkit_table, results)
        # Check if bootkit also done
        if hasattr(self, '_bootkit_results_processed') and self._bootkit_results_processed:
            self._finalize_scan()
        else:
            # Rootkit done first — wait for bootkit
            self._rootkit_results_processed = True

    def _finalize_scan(self):
        self._apply_results()
        self.overlay.hide_overlay()
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        total = len(self._bootkit_results) + len(self._rootkit_results)
        if total == 0:
            ToastNotification(self, "Scan Complete", "No bootkit or rootkit indicators found.", "success")
        else:
            ToastNotification(
                self, "Scan Complete",
                f"Found {total} potential indicator(s). Review the findings and apply recommendations.",
                "warning"
            )

    def _stop_scan(self):
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.terminate()
        self.overlay.hide_overlay()
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        ToastNotification(self, "Scan Stopped", "Threat scan was cancelled.", "warning")
