"""
Fikrado Security - Unified Malware Scan Page
Supports Quick Scan, Full Drive Scan, and Custom Path Scan with live progress,
ETA, cancellation, live threat mitigation (Quarantine, Whitelist, AI Explain).
"""
import os
import time
from pathlib import Path
from typing import Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget
)
from config.settings import SettingsManager
from core.quarantine import QuarantineManager
from scanners.malware_scanner import MalwareScannerThread
from ui.components.cards import StatCard, ThreatBadge
from ui.components.toast import ToastNotification
from ui.formatting import display_path
from ui.icons import set_icon


class ScanPage(QWidget):
    request_ai_explain = Signal(dict)  # Emitted when user clicks "AI Explain"

    def __init__(self, default_mode: str = "Quick", parent=None):
        super().__init__(parent)
        self.scan_mode = default_mode
        self.custom_target_path: Optional[str] = None
        self.scanner_thread: Optional[MalwareScannerThread] = None
        self.quarantine_mgr = QuarantineManager()
        self.settings = SettingsManager()
        self._init_ui()

    def set_mode(self, mode: str):
        self.scan_mode = mode
        self.title_lbl.setText(f"{self.scan_mode} Malware Scan")
        if mode == "Quick":
            self.desc_lbl.setText("Analyzes running processes, system startup hooks, registry persistence, and temp folders.")
            self.custom_path_frame.hide()
        elif mode == "Full":
            self.desc_lbl.setText("Comprehensive deep-scan across all mounted local drives, archives, and system files.")
            self.custom_path_frame.hide()
        elif mode == "Custom":
            self.desc_lbl.setText("Scan a specific file, directory, or external USB storage device.")
            self.custom_path_frame.show()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 25, 30, 25)
        layout.setSpacing(18)

        # Header
        header_layout = QVBoxLayout()
        header_layout.setSpacing(4)
        self.title_lbl = QLabel(f"{self.scan_mode} Malware Scan")
        self.title_lbl.setStyleSheet("font-size: 24px; font-weight: 800; color: #ECEFF4;")
        header_layout.addWidget(self.title_lbl)

        self.desc_lbl = QLabel("Multi-engine detection combining Signatures, YARA, PE Heuristics, and Persistence audit.")
        self.desc_lbl.setStyleSheet("color: #9BA3AF; font-size: 13px;")
        self.desc_lbl.setWordWrap(True)
        header_layout.addWidget(self.desc_lbl)
        layout.addLayout(header_layout)

        # Custom Path Picker (shown only in Custom mode)
        self.custom_path_frame = QFrame()
        self.custom_path_frame.setProperty("subcard", True)
        cpf_layout = QHBoxLayout(self.custom_path_frame)
        cpf_layout.setContentsMargins(12, 10, 12, 10)

        self.path_display = QLabel("No file or folder selected")
        self.path_display.setStyleSheet("color: #88C0D0; font-family: Consolas; font-size: 12px;")
        cpf_layout.addWidget(self.path_display, 1)

        browse_file_btn = QPushButton("Select File")
        browse_file_btn.setProperty("secondary", True)
        browse_file_btn.clicked.connect(self._browse_file)
        cpf_layout.addWidget(browse_file_btn)

        browse_folder_btn = QPushButton("Select Folder")
        browse_folder_btn.setProperty("secondary", True)
        browse_folder_btn.clicked.connect(self._browse_folder)
        cpf_layout.addWidget(browse_folder_btn)

        self.custom_path_frame.hide()
        layout.addWidget(self.custom_path_frame)

        # Status & Progress Card
        prog_card = QFrame()
        prog_card.setProperty("card", True)
        prog_layout = QVBoxLayout(prog_card)
        prog_layout.setContentsMargins(20, 16, 20, 16)
        prog_layout.setSpacing(12)

        # Metrics Row
        metrics_row = QHBoxLayout()
        self.stat_scanned = StatCard("Objects Scanned", "0", "Items evaluated", "#88C0D0", "stat_files")
        self.stat_threats = StatCard("Threats Found", "0", "Suspicious or malicious", "#BF616A", "stat_threats")
        self.stat_eta = StatCard("Estimated Time", "--", "Remaining calculation", "#EBCB8B", "clock")
        metrics_row.addWidget(self.stat_scanned)
        metrics_row.addWidget(self.stat_threats)
        metrics_row.addWidget(self.stat_eta)
        prog_layout.addLayout(metrics_row)

        # Progress Bar & Current File Label
        self.current_file_lbl = QLabel("Ready to start scan.")
        self.current_file_lbl.setStyleSheet("color: #D8DEE9; font-size: 12px; font-family: Consolas;")
        prog_layout.addWidget(self.current_file_lbl)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        prog_layout.addWidget(self.progress_bar)

        # Scan Buttons Row
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        self.start_btn = QPushButton("Start Scan")
        self.start_btn.setProperty("primary", True)
        set_icon(self.start_btn, "play", 15, "#1A1F27")
        self.start_btn.clicked.connect(self.start_scan)
        btn_row.addWidget(self.start_btn)

        self.pause_btn = QPushButton("Pause")
        self.pause_btn.setProperty("secondary", True)
        set_icon(self.pause_btn, "pause", 14)
        self.pause_btn.setEnabled(False)
        self.pause_btn.clicked.connect(self.toggle_pause)
        btn_row.addWidget(self.pause_btn)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setProperty("danger", True)
        set_icon(self.cancel_btn, "cancel", 14, "#FFFFFF")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.cancel_scan)
        btn_row.addWidget(self.cancel_btn)

        btn_row.addStretch()
        prog_layout.addLayout(btn_row)
        layout.addWidget(prog_card)

        # Threat Detection Table
        t_card = QFrame()
        t_card.setProperty("card", True)
        t_layout = QVBoxLayout(t_card)
        t_layout.setContentsMargins(20, 16, 20, 16)
        t_layout.setSpacing(10)

        t_lbl = QLabel("Detected Threats & Action Center")
        t_lbl.setStyleSheet("font-size: 15px; font-weight: bold; color: #ECEFF4;")
        t_layout.addWidget(t_lbl)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Severity", "Threat Name", "Type", "Engine", "Target File", "Actions"])
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        t_layout.addWidget(self.table)

        layout.addWidget(t_card, 1)

    def _browse_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select File to Scan")
        if f:
            self.custom_target_path = f
            self.path_display.setText(f)

    def _browse_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if d:
            self.custom_target_path = d
            self.path_display.setText(d)

    def start_scan(self):
        if self.scan_mode == "Custom" and not self.custom_target_path:
            ToastNotification(self.window(), "No Target Selected", "Please select a file or folder for custom scanning.", "warning")
            return

        self.table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.stat_scanned.set_value("0")
        self.stat_threats.set_value("0")
        self.stat_eta.set_value("Calculating...")

        self.start_btn.setEnabled(False)
        self.pause_btn.setEnabled(True)
        self.pause_btn.setText("Pause")
        set_icon(self.pause_btn, "pause", 14)
        self.cancel_btn.setEnabled(True)

        self.scanner_thread = MalwareScannerThread(
            scan_mode=self.scan_mode,
            custom_target=self.custom_target_path
        )
        self.scanner_thread.signals.progress.connect(self._on_progress)
        self.scanner_thread.signals.threat_found.connect(self._on_threat_found)
        self.scanner_thread.signals.status_message.connect(self._on_status)
        self.scanner_thread.signals.finished.connect(self._on_finished)
        self.scanner_thread.signals.paused.connect(self._on_paused)
        self.scanner_thread.start()

    def toggle_pause(self):
        if not self.scanner_thread:
            return
        if self.scanner_thread._is_paused:
            self.scanner_thread.resume()
            self.pause_btn.setText("Pause")
            set_icon(self.pause_btn, "pause", 14)
        else:
            self.scanner_thread.pause()
            self.pause_btn.setText("Resume")
            set_icon(self.pause_btn, "play", 14)

    def cancel_scan(self):
        if self.scanner_thread:
            self.scanner_thread.cancel()
            self.cancel_btn.setEnabled(False)

    def _on_progress(self, current: int, total: int, current_file: str, eta_seconds: float):
        self.stat_scanned.set_value(f"{current:,}")
        pct = int((current / total * 100)) if total > 0 else 0
        self.progress_bar.setValue(pct)

        # Truncate path for display
        display_str = current_file if len(current_file) < 85 else f"...{current_file[-80:]}"
        self.current_file_lbl.setText(f"Scanning ({current}/{total}): {display_str}")

        if eta_seconds > 60:
            self.stat_eta.set_value(f"{int(eta_seconds // 60)}m {int(eta_seconds % 60)}s")
        else:
            self.stat_eta.set_value(f"{int(eta_seconds)}s")

    def _on_status(self, msg: str):
        self.current_file_lbl.setText(msg)

    def _on_paused(self, is_paused: bool):
        if is_paused:
            self.current_file_lbl.setText("Scan paused by user.")
        else:
            self.current_file_lbl.setText("Resuming scan...")

    def _on_threat_found(self, threat: dict):
        self.stat_threats.set_value(str(len(self.scanner_thread.threats_found)))
        row = self.table.rowCount()
        self.table.insertRow(row)

        badge = ThreatBadge(threat.get("severity", "Medium"))
        self.table.setCellWidget(row, 0, badge)

        name_item = QTableWidgetItem(threat.get("threat_name", "N/A"))
        name_item.setForeground(Qt.white)
        self.table.setItem(row, 1, name_item)

        self.table.setItem(row, 2, QTableWidgetItem(threat.get("threat_type", "Malware")))
        self.table.setItem(row, 3, QTableWidgetItem(threat.get("engine", "Heuristic")))

        full_path = threat.get("file_path", "")
        path_item = QTableWidgetItem(display_path(full_path))
        path_item.setToolTip(full_path)
        self.table.setItem(row, 4, path_item)

        # Action Buttons Container
        act_widget = QWidget()
        act_layout = QHBoxLayout(act_widget)
        act_layout.setContentsMargins(4, 2, 4, 2)
        act_layout.setSpacing(6)

        quarantine_btn = QPushButton("Quarantine")
        quarantine_btn.setProperty("danger", True)
        quarantine_btn.setStyleSheet("padding: 3px 8px; font-size: 11px;")
        set_icon(quarantine_btn, "quarantine", 12, "#FFFFFF")
        quarantine_btn.clicked.connect(lambda _, t=threat, r=row: self._quarantine_threat(t, r))
        act_layout.addWidget(quarantine_btn)

        ai_btn = QPushButton("AI Explain")
        ai_btn.setProperty("secondary", True)
        ai_btn.setStyleSheet("padding: 3px 8px; font-size: 11px;")
        set_icon(ai_btn, "ai_scan", 12)
        ai_btn.clicked.connect(lambda _, t=threat: self.request_ai_explain.emit(t))
        act_layout.addWidget(ai_btn)

        whitelist_btn = QPushButton("Whitelist")
        whitelist_btn.setProperty("secondary", True)
        whitelist_btn.setStyleSheet("padding: 3px 8px; font-size: 11px;")
        set_icon(whitelist_btn, "shield", 12)
        whitelist_btn.clicked.connect(lambda _, t=threat, r=row: self._whitelist_threat(t, r))
        act_layout.addWidget(whitelist_btn)

        self.table.setCellWidget(row, 5, act_widget)

    def _quarantine_threat(self, threat: dict, row: int):
        fpath = threat.get("file_path", "")
        success = self.quarantine_mgr.quarantine_file(
            file_path=fpath,
            threat_name=threat.get("threat_name", "Suspicious Object"),
            threat_type=threat.get("threat_type", "Malware"),
            severity=threat.get("severity", "Medium"),
            detection_engine=threat.get("engine", "Heuristic"),
            notes=threat.get("description", "")
        )
        if success:
            ToastNotification(self.window(), "File Quarantined", f"Encrypted and safely isolated: {Path(fpath).name}", "success")
            self.table.removeRow(row)
        else:
            ToastNotification(self.window(), "Quarantine Notice", "Could not quarantine item (system file or in use).", "error")

    def _whitelist_threat(self, threat: dict, row: int):
        fpath = threat.get("file_path", "")
        sha256 = threat.get("sha256", "")
        if fpath:
            self.settings.add_to_whitelist("paths", fpath)
        if sha256:
            self.settings.add_to_whitelist("hashes", sha256)
        ToastNotification(self.window(), "Whitelisted", f"Object added to exclusion list.", "info")
        self.table.removeRow(row)

    def _on_finished(self, summary: dict):
        self.start_btn.setEnabled(True)
        self.pause_btn.setEnabled(False)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        self.stat_eta.set_value("Done")

        threats_count = summary.get("threats_count", 0)
        duration = summary.get("duration", 0)

        if threats_count > 0:
            ToastNotification(
                self.window(),
                "Scan Completed - Threats Found!",
                f"{threats_count} malicious or suspicious items detected in {duration:.1f}s.",
                "error"
            )
        else:
            ToastNotification(
                self.window(),
                "Scan Clean",
                f"Completed in {duration:.1f}s. No threats detected.",
                "success"
            )
