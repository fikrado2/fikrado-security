"""
Fikrado Security - Quarantine Management Page
Allows users to review encrypted quarantined objects, restore them to original paths,
or permanently delete them.
"""
import os
import subprocess
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
from config.constants import QUARANTINE_DIR
from config.settings import SettingsManager
from core.quarantine import QuarantineManager
from ui.components.cards import ThreatBadge
from ui.components.toast import ToastNotification


class QuarantinePage(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.quarantine_mgr = QuarantineManager()
        self.settings = SettingsManager()
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 25, 30, 25)
        layout.setSpacing(18)

        # Header
        header = QVBoxLayout()
        header.setSpacing(4)
        title = QLabel("Quarantine Vault")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #ECEFF4;")
        header.addWidget(title)

        desc = QLabel(
            "Safely encrypted file isolation chamber. Malicious payloads stored here cannot be executed, "
            "read, or unpacked by background malware processes. Files can be safely restored if whitelisted."
        )
        desc.setStyleSheet("color: #9BA3AF; font-size: 13px;")
        desc.setWordWrap(True)
        header.addWidget(desc)
        layout.addLayout(header)

        # Toolbar
        tb = QHBoxLayout()
        refresh_btn = QPushButton("🔄 Refresh Vault")
        refresh_btn.setProperty("primary", True)
        refresh_btn.clicked.connect(self.refresh_table)
        tb.addWidget(refresh_btn)

        open_folder_btn = QPushButton("📂 Open Vault Directory")
        open_folder_btn.setProperty("secondary", True)
        open_folder_btn.clicked.connect(self._open_vault_folder)
        tb.addWidget(open_folder_btn)

        tb.addStretch()

        self.btn_restore = QPushButton("Restore Selected File")
        self.btn_restore.setProperty("secondary", True)
        self.btn_restore.setEnabled(False)
        self.btn_restore.clicked.connect(self._restore_selected)
        tb.addWidget(self.btn_restore)

        self.btn_delete = QPushButton("Delete Permanently")
        self.btn_delete.setProperty("danger", True)
        self.btn_delete.setEnabled(False)
        self.btn_delete.clicked.connect(self._delete_selected)
        tb.addWidget(self.btn_delete)

        layout.addLayout(tb)

        # Table
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "Severity", "File Name", "Threat Name", "Type", "Engine", "Original Path", "Quarantined At"
        ])
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._on_row_selected)
        layout.addWidget(self.table)

        self.refresh_table()

    def refresh_table(self):
        items = self.quarantine_mgr.list_items()
        self.items_cache = items
        self.table.setRowCount(0)

        for it in items:
            row = self.table.rowCount()
            self.table.insertRow(row)

            badge = ThreatBadge(it.get("severity", "Medium"))
            self.table.setCellWidget(row, 0, badge)

            name_item = QTableWidgetItem(it.get("filename", "Unknown"))
            name_item.setForeground(Qt.white)
            self.table.setItem(row, 1, name_item)

            self.table.setItem(row, 2, QTableWidgetItem(it.get("threat_name", "Malware")))
            self.table.setItem(row, 3, QTableWidgetItem(it.get("threat_type", "General")))
            self.table.setItem(row, 4, QTableWidgetItem(it.get("detection_engine", "Heuristic")))
            self.table.setItem(row, 5, QTableWidgetItem(it.get("original_path", "")))
            self.table.setItem(row, 6, QTableWidgetItem(it.get("quarantine_time", "")))

        self.btn_restore.setEnabled(False)
        self.btn_delete.setEnabled(False)

    def _on_row_selected(self):
        selected = self.table.selectedIndexes()
        has_sel = bool(selected)
        self.btn_restore.setEnabled(has_sel)
        self.btn_delete.setEnabled(has_sel)

    def _get_selected_item(self):
        rows = self.table.selectedIndexes()
        if not rows:
            return None
        row = rows[0].row()
        if row < len(self.items_cache):
            return self.items_cache[row]
        return None

    def _restore_selected(self):
        item = self._get_selected_item()
        if not item:
            return
        qid = item.get("id")
        orig_path = item.get("original_path")
        ok = self.quarantine_mgr.restore_file(qid)
        if ok:
            ToastNotification(self.window(), "Restored Successfully", f"Restored {item.get('filename')} to {orig_path}", "success")
            self.refresh_table()
        else:
            ToastNotification(self.window(), "Restore Failed", "Failed to restore quarantined item.", "error")

    def _delete_selected(self):
        item = self._get_selected_item()
        if not item:
            return
        qid = item.get("id")
        ok = self.quarantine_mgr.delete_permanently(qid)
        if ok:
            ToastNotification(self.window(), "Deleted Permanently", f"Quarantined blob {item.get('filename')} deleted.", "info")
            self.refresh_table()
        else:
            ToastNotification(self.window(), "Delete Failed", "Failed to delete item.", "error")

    def _open_vault_folder(self):
        try:
            os.startfile(str(QUARANTINE_DIR))
        except Exception as e:
            ToastNotification(self.window(), "Folder Notice", str(e), "warning")
