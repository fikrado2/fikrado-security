"""
Fikrado Security - Settings & AI Credentials Management Page
Provides DPAPI-encrypted API key governance for Gemini, OpenAI, Claude, OpenRouter,
Ollama, and Custom endpoints with real-time connectivity testing and scanner customization.
"""
from PySide6.QtCore import Qt, QThread, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QPixmap
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget
)
from config.constants import (
    APP_COPYRIGHT,
    APP_NAME,
    APP_PUBLISHER,
    APP_VERSION,
    LOGO_PNG,
    SOCIAL_LINKS,
)
from config.settings import SettingsManager
from core.crypto import HAS_DPAPI
from core.system_info import get_windows_info, is_admin
from plugins.plugin_manager import plugin_manager
from tools.realtime_guard import realtime_guard
from ui.components.toast import ToastNotification
from ui.effects import apply_text_glow
from ui.icons import icon_label, load_icon, set_icon


class TestConnectionThread(QThread):
    finished = Signal(bool, str)

    def __init__(self, provider_id: str, api_key: str, model: str, endpoint: str):
        super().__init__()
        self.provider_id = provider_id
        self.api_key = api_key
        self.model = model
        self.endpoint = endpoint

    def run(self):
        plugin = plugin_manager.get_plugin(self.provider_id)
        if not plugin:
            self.finished.emit(False, "Provider not found.")
            return
        ok, msg = plugin.test_connection(self.api_key, self.model, self.endpoint)
        self.finished.emit(ok, msg)


class SettingsPage(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings = SettingsManager()
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 25, 30, 25)
        layout.setSpacing(18)

        # Header
        header = QVBoxLayout()
        header.setSpacing(4)
        title = QLabel("Application Settings & AI Governance")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #ECEFF4;")
        header.addWidget(title)

        desc = QLabel(
            "Manage hardware heuristic thresholds, threat exclusion whitelists, "
            "and DPAPI-encrypted AI intelligence provider credentials."
        )
        desc.setStyleSheet("color: #9BA3AF; font-size: 13px;")
        desc.setWordWrap(True)
        header.addWidget(desc)
        layout.addLayout(header)

        # Settings Tabs
        self.tabs = QTabWidget()

        # Tab 1: AI Provider Credentials & DPAPI
        self.tabs.addTab(self._build_ai_tab(), load_icon("ai_scan", 16), "AI Provider Credentials")
        # Tab 2: Malware Scanner Controls
        self.tabs.addTab(self._build_scanner_tab(), load_icon("full_scan", 16), "Threat Engine Controls")
        # Tab 3: Real-Time Protection Scope
        self.tabs.addTab(self._build_realtime_tab(), load_icon("realtime", 16), "Real-Time Shield")
        # Tab 4: Whitelist & Exclusions
        self.tabs.addTab(self._build_whitelist_tab(), load_icon("shield", 16), "Whitelist && Exclusions")
        # Tab 5: About Fikrado
        self.tabs.addTab(self._build_about_tab(), load_icon("info", 16), "About && System Status")

        layout.addWidget(self.tabs)

    # ==================== 1. AI CREDENTIALS ====================
    def _build_ai_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(
            "QScrollArea { background: transparent; border: none; }"
            "QScrollArea > QWidget > QWidget { background: transparent; }"
        )

        container = QWidget()
        l = QVBoxLayout(container)
        l.setContentsMargins(15, 15, 15, 15)
        l.setSpacing(16)

        # DPAPI Security Notice Banner
        dpapi_banner = QFrame()
        dpapi_banner.setProperty("subcard", True)
        dp_layout = QHBoxLayout(dpapi_banner)
        dp_layout.setContentsMargins(16, 12, 16, 12)

        dpapi_status = "ACTIVE (win32crypt DPAPI)" if HAS_DPAPI else "AES-GCM Machine Key Encryption"
        dp_layout.addWidget(icon_label("lock", 20))
        dp_lbl = QLabel(
            f"<b>Credential Security:</b> All API tokens are encrypted with <b>Windows {dpapi_status}</b>. "
            "Keys are decrypted only in-memory during authorized requests and never logged or written in plaintext."
        )
        dp_lbl.setStyleSheet("color: #88C0D0; font-size: 12px;")
        dp_lbl.setWordWrap(True)
        dp_layout.addWidget(dp_lbl, 1)
        l.addWidget(dpapi_banner)

        # Provider Cards
        self.ai_inputs = {}
        providers = [
            ("gemini", "Google Gemini", "gemini-2.5-flash", False, ""),
            ("openai", "OpenAI", "gpt-4o-mini", False, ""),
            ("openrouter", "OpenRouter", "google/gemini-2.5-flash", False, ""),
            ("anthropic", "Anthropic Claude", "claude-3-5-sonnet-20241022", False, ""),
            ("ollama", "Ollama (Local On-Device)", "llama3.2:latest", True, "http://localhost:11434"),
            ("custom", "Custom OpenAI-Compatible Endpoint", "default-model", True, "https://api.openai.com/v1"),
        ]

        for pid, pname, def_model, has_endpoint, def_endpoint in providers:
            card = QFrame()
            card.setProperty("card", True)
            c_layout = QVBoxLayout(card)
            c_layout.setContentsMargins(16, 14, 16, 14)
            c_layout.setSpacing(10)

            c_head = QHBoxLayout()
            t_lbl = QLabel(f"<b>{pname}</b>")
            t_lbl.setStyleSheet("font-size: 14px; color: #ECEFF4;")
            c_head.addWidget(t_lbl)
            c_head.addStretch()

            test_btn = QPushButton("Test Connection")
            test_btn.setProperty("secondary", True)
            set_icon(test_btn, "plug", 15)
            test_btn.clicked.connect(lambda _, p=pid: self._test_ai_connection(p))
            c_head.addWidget(test_btn)

            save_btn = QPushButton("Save")
            save_btn.setProperty("primary", True)
            set_icon(save_btn, "save", 15, "#1A1F27")
            save_btn.clicked.connect(lambda _, p=pid: self._save_ai_credentials(p))
            c_head.addWidget(save_btn)
            c_layout.addLayout(c_head)

            # Grid inputs
            grid = QGridLayout()
            grid.setSpacing(8)

            saved_key, saved_model, saved_endpoint = plugin_manager.get_credentials(pid)

            # API Key Input
            key_inp = QLineEdit(saved_key)
            key_inp.setEchoMode(QLineEdit.Password)
            key_inp.setPlaceholderText("Enter API Key (Encrypted via Windows DPAPI)...")
            grid.addWidget(QLabel("API Key:"), 0, 0)
            grid.addWidget(key_inp, 0, 1)

            # Model Input
            model_inp = QLineEdit(saved_model or def_model)
            model_inp.setPlaceholderText(f"Default: {def_model}")
            grid.addWidget(QLabel("Model:"), 0, 2)
            grid.addWidget(model_inp, 0, 3)

            endpoint_inp = None
            if has_endpoint:
                endpoint_inp = QLineEdit(saved_endpoint or def_endpoint)
                endpoint_inp.setPlaceholderText("e.g. http://localhost:11434")
                grid.addWidget(QLabel("Base URL:"), 1, 0)
                grid.addWidget(endpoint_inp, 1, 1, 1, 3)

            c_layout.addLayout(grid)

            # Result status label
            res_lbl = QLabel("")
            res_lbl.setStyleSheet("font-size: 11px;")
            c_layout.addWidget(res_lbl)

            self.ai_inputs[pid] = {
                "key": key_inp,
                "model": model_inp,
                "endpoint": endpoint_inp,
                "result_lbl": res_lbl
            }

            l.addWidget(card)

        l.addStretch()
        scroll.setWidget(container)
        return scroll

    def _save_ai_credentials(self, pid: str):
        data = self.ai_inputs[pid]
        key = data["key"].text().strip()
        model = data["model"].text().strip()
        endpoint = data["endpoint"].text().strip() if data["endpoint"] else ""

        plugin_manager.set_credentials(pid, key, model, endpoint)
        ToastNotification(self.window(), "Credentials Stored", f"Encrypted and saved {pid.upper()} configuration.", "success")

    def _test_ai_connection(self, pid: str):
        data = self.ai_inputs[pid]
        key = data["key"].text().strip()
        model = data["model"].text().strip()
        endpoint = data["endpoint"].text().strip() if data["endpoint"] else ""

        data["result_lbl"].setText("Testing connection...")
        data["result_lbl"].setStyleSheet("color: #88C0D0;")

        self.test_thread = TestConnectionThread(pid, key, model, endpoint)
        self.test_thread.finished.connect(lambda ok, msg, p=pid: self._on_test_finished(p, ok, msg))
        self.test_thread.start()

    def _on_test_finished(self, pid: str, ok: bool, msg: str):
        data = self.ai_inputs[pid]
        color = "#A3BE8C" if ok else "#BF616A"
        prefix = "Success" if ok else "Failed"
        data["result_lbl"].setText(f"{prefix} — {msg}")
        data["result_lbl"].setStyleSheet(f"color: {color}; font-weight: bold;")
        ToastNotification(self.window(), f"{pid.upper()} Test", msg, "success" if ok else "error")

    # ==================== 2. SCANNER CONTROLS ====================
    def _build_scanner_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(20, 20, 20, 20)
        l.setSpacing(14)

        card = QFrame()
        card.setProperty("card", True)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(20, 18, 20, 18)
        cl.setSpacing(14)

        t = QLabel("Malware Detection Engines & Heuristics Tuning")
        t.setStyleSheet("font-size: 16px; font-weight: bold; color: #88C0D0;")
        cl.addWidget(t)

        self.chk_yara = QCheckBox("Enable YARA Signature Pattern Engine (Covers Trojans, Ransomware, Keyloggers, RATs)")
        self.chk_yara.setChecked(self.settings.get("scanner", "enable_yara", True))
        cl.addWidget(self.chk_yara)

        self.chk_clam = QCheckBox("Enable ClamAV Engine (Optional ClamScan executable integration)")
        self.chk_clam.setChecked(self.settings.get("scanner", "enable_clamav", False))
        cl.addWidget(self.chk_clam)

        # Heuristics Level
        h_row = QHBoxLayout()
        h_row.addWidget(QLabel("Heuristic Sensitivity Level:"))
        self.heur_combo = QComboBox()
        self.heur_combo.addItems(["Low", "Medium", "High (Recommended)", "Aggressive"])
        curr_heur = self.settings.get("scanner", "heuristic_level", "High")
        self.heur_combo.setCurrentText(f"{curr_heur} (Recommended)" if curr_heur == "High" else curr_heur)
        h_row.addWidget(self.heur_combo)
        h_row.addStretch()
        cl.addLayout(h_row)

        # Entropy Threshold
        ent_row = QHBoxLayout()
        ent_row.addWidget(QLabel("Shannon Entropy Packing Threshold:"))
        self.ent_input = QLineEdit(str(self.settings.get("scanner", "entropy_threshold", 7.2)))
        self.ent_input.setFixedWidth(80)
        ent_row.addWidget(self.ent_input)
        ent_row.addWidget(QLabel("(7.0 - 8.0 bits; values above indicate packed or encrypted payloads)"))
        ent_row.addStretch()
        cl.addLayout(ent_row)

        # VirusTotal Key
        vt_row = QHBoxLayout()
        vt_row.addWidget(QLabel("VirusTotal API Key (Optional):"))
        self.vt_key_input = QLineEdit(self.settings.get("scanner", "virustotal_api_key", ""))
        self.vt_key_input.setEchoMode(QLineEdit.Password)
        self.vt_key_input.setPlaceholderText("Enter 64-character VirusTotal v3 API key...")
        vt_row.addWidget(self.vt_key_input, 1)
        cl.addLayout(vt_row)

        save_scanner_btn = QPushButton("Save Scanner Settings")
        save_scanner_btn.setProperty("primary", True)
        set_icon(save_scanner_btn, "save", 15, "#1A1F27")
        save_scanner_btn.clicked.connect(self._save_scanner_settings)
        cl.addWidget(save_scanner_btn)

        l.addWidget(card)
        l.addStretch()
        return w

    def _save_scanner_settings(self):
        self.settings.set("scanner", "enable_yara", self.chk_yara.isChecked(), auto_save=False)
        self.settings.set("scanner", "enable_clamav", self.chk_clam.isChecked(), auto_save=False)
        self.settings.set("scanner", "heuristic_level", self.heur_combo.currentText().split()[0], auto_save=False)
        try:
            ent = float(self.ent_input.text().strip())
            self.settings.set("scanner", "entropy_threshold", ent, auto_save=False)
        except ValueError:
            pass
        self.settings.set("scanner", "virustotal_api_key", self.vt_key_input.text().strip(), auto_save=True)
        ToastNotification(self.window(), "Settings Saved", "Malware scanner configuration updated.", "success")

    # ==================== 3. REAL-TIME SCOPE ====================
    def _build_realtime_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(
            "QScrollArea { background: transparent; border: none; }"
            "QScrollArea > QWidget > QWidget { background: transparent; }"
        )

        container = QWidget()
        l = QVBoxLayout(container)
        l.setContentsMargins(15, 15, 15, 15)
        l.setSpacing(16)

        card = QFrame()
        card.setProperty("card", True)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(20, 18, 20, 18)
        cl.setSpacing(12)

        header = QHBoxLayout()
        header.setSpacing(9)
        header.addWidget(icon_label("realtime", 22))
        title = QLabel("Continuous Protection Scope")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #88C0D0;")
        header.addWidget(title)
        header.addStretch()
        cl.addLayout(header)

        desc = QLabel(
            "Fikrado can watch the places malware actually uses: user drop folders, running processes, "
            "startup hooks, network listeners, USB media and local drive roots. Toggle any layer below."
        )
        desc.setStyleSheet("color: #D8DEE9; font-size: 12px;")
        desc.setWordWrap(True)
        cl.addWidget(desc)

        self.chk_rt_enabled = QCheckBox("Enable real-time protection while Fikrado Security is running")
        self.chk_rt_processes = QCheckBox("Monitor newly launched processes and obfuscated command lines")
        self.chk_rt_downloads = QCheckBox("Watch Downloads and Public Downloads for new executable files")
        self.chk_rt_temp = QCheckBox("Watch Windows Temp folders for dropped payloads")
        self.chk_rt_user_folders = QCheckBox("Watch Desktop, Documents and Public user folders")
        self.chk_rt_startup = QCheckBox("Watch registry Run/RunOnce keys and Startup folders for persistence")
        self.chk_rt_network = QCheckBox("Alert on new network listeners opened by non-system processes")
        self.chk_rt_removable = QCheckBox("Watch removable drives (USB) and scan their executables")
        self.chk_rt_all_drives = QCheckBox("Also watch every local drive root (higher coverage, more disk activity)")

        toggles = (
            (self.chk_rt_enabled, "enabled"),
            (self.chk_rt_processes, "monitor_processes"),
            (self.chk_rt_downloads, "scan_downloads"),
            (self.chk_rt_temp, "scan_temp"),
            (self.chk_rt_user_folders, "monitor_user_folders"),
            (self.chk_rt_startup, "monitor_startup"),
            (self.chk_rt_network, "monitor_network"),
            (self.chk_rt_removable, "monitor_removable"),
            (self.chk_rt_all_drives, "monitor_all_drives"),
        )
        for checkbox, key in toggles:
            checkbox.setChecked(bool(self.settings.get("realtime", key, True)))
            cl.addWidget(checkbox)

        interval_row = QHBoxLayout()
        interval_row.addWidget(QLabel("Scan interval:"))
        self.rt_interval = QComboBox()
        for seconds in (2, 3, 5, 10, 30):
            self.rt_interval.addItem(f"{seconds} seconds", seconds)
        current_interval = int(self.settings.get("realtime", "check_interval_seconds", 3))
        index = self.rt_interval.findData(current_interval)
        self.rt_interval.setCurrentIndex(index if index >= 0 else 1)
        interval_row.addWidget(self.rt_interval)
        interval_row.addStretch()
        cl.addLayout(interval_row)

        self.rt_scope_lbl = QLabel(f"Current scope: {realtime_guard.scope_summary()}")
        self.rt_scope_lbl.setStyleSheet("color: #A3BE8C; font-size: 11px; font-weight: 600;")
        cl.addWidget(self.rt_scope_lbl)

        save_btn = QPushButton("Save Protection Settings")
        save_btn.setProperty("primary", True)
        set_icon(save_btn, "realtime", 15, "#1A1F27")
        save_btn.clicked.connect(self._save_realtime_settings)
        cl.addWidget(save_btn)
        l.addWidget(card)

        note = QFrame()
        note.setProperty("subcard", True)
        note_layout = QHBoxLayout(note)
        note_layout.setContentsMargins(16, 12, 16, 12)
        note_layout.setSpacing(10)
        note_layout.addWidget(icon_label("info", 18))
        note_lbl = QLabel(
            "Real-time protection runs locally and never uploads your files. "
            "Detections appear on the Dashboard and can be quarantined from the scan page."
        )
        note_lbl.setWordWrap(True)
        note_lbl.setStyleSheet("color: #C9D2DE; font-size: 12px;")
        note_layout.addWidget(note_lbl, 1)
        l.addWidget(note)
        l.addStretch()

        scroll.setWidget(container)
        return scroll

    def _save_realtime_settings(self):
        mapping = {
            "enabled": self.chk_rt_enabled,
            "monitor_processes": self.chk_rt_processes,
            "scan_downloads": self.chk_rt_downloads,
            "scan_temp": self.chk_rt_temp,
            "monitor_user_folders": self.chk_rt_user_folders,
            "monitor_startup": self.chk_rt_startup,
            "monitor_network": self.chk_rt_network,
            "monitor_removable": self.chk_rt_removable,
            "monitor_all_drives": self.chk_rt_all_drives,
        }
        for key, checkbox in mapping.items():
            self.settings.set("realtime", key, checkbox.isChecked(), auto_save=False)
        self.settings.set(
            "realtime", "check_interval_seconds",
            int(self.rt_interval.currentData()), auto_save=True,
        )

        if self.chk_rt_enabled.isChecked():
            if not realtime_guard.is_active:
                realtime_guard.start_guard()
        else:
            realtime_guard.pause_guard()

        self.rt_scope_lbl.setText(f"Current scope: {realtime_guard.scope_summary()}")
        ToastNotification(
            self.window(), "Protection Updated",
            "Real-time monitoring scope saved and applied.", "success",
        )

    # ==================== 4. WHITELIST ====================
    def _build_whitelist_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(20, 20, 20, 20)
        l.setSpacing(14)

        card = QFrame()
        card.setProperty("card", True)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(18, 16, 18, 16)
        cl.setSpacing(12)

        t = QLabel("Trusted File Paths & SHA-256 Hash Exclusions")
        t.setStyleSheet("font-size: 16px; font-weight: bold; color: #88C0D0;")
        cl.addWidget(t)

        add_row = QHBoxLayout()
        self.wl_input = QLineEdit()
        self.wl_input.setPlaceholderText("Enter file path or 64-char SHA-256 hash to exclude...")
        add_row.addWidget(self.wl_input, 1)

        add_path_btn = QPushButton("+ Add Path")
        add_path_btn.setProperty("secondary", True)
        add_path_btn.clicked.connect(self._add_whitelist_path)
        add_row.addWidget(add_path_btn)

        browse_btn = QPushButton("Browse File")
        browse_btn.setProperty("secondary", True)
        browse_btn.clicked.connect(self._browse_whitelist_file)
        add_row.addWidget(browse_btn)

        cl.addLayout(add_row)
        l.addWidget(card)

        # Whitelist Table
        self.wl_table = QTableWidget(0, 3)
        self.wl_table.setHorizontalHeaderLabels(["Type", "Exclusion Value", "Action"])
        self.wl_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.wl_table.setEditTriggers(QTableWidget.NoEditTriggers)
        l.addWidget(self.wl_table)

        self._refresh_whitelist()
        return w

    def _browse_whitelist_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select File to Whitelist")
        if f:
            self.wl_input.setText(f)

    def _add_whitelist_path(self):
        val = self.wl_input.text().strip()
        if not val:
            return
        if len(val) == 64 and all(c in "0123456789abcdefABCDEF" for c in val):
            self.settings.add_to_whitelist("hashes", val)
        else:
            self.settings.add_to_whitelist("paths", val)
        self.wl_input.clear()
        self._refresh_whitelist()
        ToastNotification(self.window(), "Added to Whitelist", f"Excluded: {val}", "success")

    def _refresh_whitelist(self):
        self.wl_table.setRowCount(0)
        paths = self.settings.get("whitelist", "paths", [])
        for p in paths:
            row = self.wl_table.rowCount()
            self.wl_table.insertRow(row)
            self.wl_table.setItem(row, 0, QTableWidgetItem("Path Exclusion"))
            self.wl_table.setItem(row, 1, QTableWidgetItem(p))
            del_btn = QPushButton("Remove")
            del_btn.setProperty("danger", True)
            del_btn.clicked.connect(lambda _, val=p: self._remove_whitelist("paths", val))
            self.wl_table.setCellWidget(row, 2, del_btn)

        hashes = self.settings.get("whitelist", "hashes", [])
        for h in hashes:
            row = self.wl_table.rowCount()
            self.wl_table.insertRow(row)
            self.wl_table.setItem(row, 0, QTableWidgetItem("Hash Exclusion"))
            self.wl_table.setItem(row, 1, QTableWidgetItem(h))
            del_btn = QPushButton("Remove")
            del_btn.setProperty("danger", True)
            del_btn.clicked.connect(lambda _, val=h: self._remove_whitelist("hashes", val))
            self.wl_table.setCellWidget(row, 2, del_btn)

    def _remove_whitelist(self, itype: str, val: str):
        self.settings.remove_from_whitelist(itype, val)
        self._refresh_whitelist()
        ToastNotification(self.window(), "Removed", f"Exclusion removed.", "info")

    # ==================== 5. ABOUT ====================
    def _build_about_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(
            "QScrollArea { background: transparent; border: none; }"
            "QScrollArea > QWidget > QWidget { background: transparent; }"
        )

        container = QWidget()
        l = QVBoxLayout(container)
        l.setContentsMargins(15, 15, 15, 15)
        l.setSpacing(16)

        # 1. Brand & publisher card
        brand_card = QFrame()
        brand_card.setProperty("card", True)
        bl = QVBoxLayout(brand_card)
        bl.setContentsMargins(24, 22, 24, 22)
        bl.setSpacing(12)

        header = QHBoxLayout()
        header.setSpacing(16)

        if LOGO_PNG.exists():
            logo_lbl = QLabel()
            logo_lbl.setPixmap(
                QPixmap(str(LOGO_PNG)).scaled(
                    64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation
                )
            )
            logo_lbl.setFixedSize(64, 64)
            logo_lbl.setStyleSheet("background: transparent; border: none;")
            logo_glow = apply_text_glow(logo_lbl, "#FFD93D", blur=22, opacity=135)
            header.addWidget(logo_lbl)

        title_box = QVBoxLayout()
        title_box.setSpacing(3)
        title = QLabel(APP_NAME)
        title.setStyleSheet(
            "font-size: 22px; font-weight: 800; color: #ECEFF4; "
            "letter-spacing: 0.4px; background: transparent;"
        )
        apply_text_glow(title, "#BFE6EF", blur=16, opacity=110)
        title_box.addWidget(title)

        publisher = QLabel(f"Publisher: {APP_PUBLISHER}")
        publisher.setStyleSheet(
            "font-size: 12px; font-weight: 700; color: #FFD93D; "
            "background: transparent;"
        )
        title_box.addWidget(publisher)

        tagline = QLabel(
            "Next-generation Windows endpoint defense, threat intelligence and "
            "real-time protection."
        )
        tagline.setStyleSheet("font-size: 12px; color: #C9D2DE; background: transparent;")
        tagline.setWordWrap(True)
        title_box.addWidget(tagline)

        header.addLayout(title_box, 1)

        version_pill = QLabel(f"v{APP_VERSION}")
        version_pill.setStyleSheet(
            "background-color: rgba(136, 192, 208, 38); color: #88C0D0; "
            "border: 1px solid rgba(136, 192, 208, 120); border-radius: 10px; "
            "padding: 4px 12px; font-size: 11px; font-weight: 800;"
        )
        version_pill.setAlignment(Qt.AlignCenter)
        header.addWidget(version_pill, 0, Qt.AlignTop)
        bl.addLayout(header)

        divider = QFrame()
        divider.setFixedHeight(1)
        divider.setStyleSheet(
            "background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
            "stop:0 rgba(255, 217, 61, 120), stop:0.6 rgba(136, 192, 208, 35), "
            "stop:1 rgba(136, 192, 208, 0)); border: none;"
        )
        bl.addWidget(divider)

        # 2. Social presence
        social_label = QLabel("CONNECT WITH FIKRADO")
        social_label.setStyleSheet(
            "color: #7F8A99; font-size: 9px; font-weight: 800; "
            "letter-spacing: 1.6px; background: transparent;"
        )
        bl.addWidget(social_label)

        social_row = QHBoxLayout()
        social_row.setSpacing(9)
        for icon_name, label, url in SOCIAL_LINKS:
            btn = QPushButton(label)
            btn.setProperty("secondary", True)
            set_icon(btn, icon_name, 16)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setToolTip(url)
            btn.clicked.connect(
                lambda _, target=url: QDesktopServices.openUrl(QUrl(target))
            )
            social_row.addWidget(btn)
        social_row.addStretch()
        bl.addLayout(social_row)
        l.addWidget(brand_card)

        # 3. System status card
        system_card = QFrame()
        system_card.setProperty("subcard", True)
        sl = QVBoxLayout(system_card)
        sl.setContentsMargins(22, 18, 22, 18)
        sl.setSpacing(10)

        system_header = QHBoxLayout()
        system_header.setSpacing(9)
        system_header.addWidget(icon_label("monitor", 20))
        system_title = QLabel("System Status")
        system_title.setStyleSheet(
            "font-size: 14px; font-weight: 800; color: #88C0D0; "
            "background: transparent;"
        )
        system_header.addWidget(system_title)
        system_header.addStretch()
        sl.addLayout(system_header)

        info = get_windows_info()
        admin_text = (
            "Elevated (Administrator)"
            if info.get("is_admin")
            else "Standard User (Not Elevated)"
        )
        shield_state = "Active" if realtime_guard.is_active else "Paused"

        details = f"""
        <table style="color: #D8DEE9; font-size: 12px; line-height: 1.9;">
            <tr><td style="padding-right:18px;"><b>Platform</b></td><td>{info.get('os_name')} {info.get('os_version')} (Build {info.get('os_build')})</td></tr>
            <tr><td><b>Architecture</b></td><td>{info.get('architecture')}</td></tr>
            <tr><td><b>Computer Name</b></td><td>{info.get('computer_name')}</td></tr>
            <tr><td><b>Active User</b></td><td>{info.get('username')}</td></tr>
            <tr><td><b>Privilege State</b></td><td>{admin_text}</td></tr>
            <tr><td><b>Python Runtime</b></td><td>CPython {info.get('python_version')}</td></tr>
            <tr><td><b>Real-Time Shield</b></td><td>{shield_state} — {realtime_guard.scope_summary()}</td></tr>
        </table>
        """
        detail_lbl = QLabel(details)
        detail_lbl.setTextFormat(Qt.RichText)
        detail_lbl.setWordWrap(True)
        sl.addWidget(detail_lbl)
        l.addWidget(system_card)

        copyright_lbl = QLabel(APP_COPYRIGHT)
        copyright_lbl.setAlignment(Qt.AlignCenter)
        copyright_lbl.setStyleSheet(
            "color: #6F7887; font-size: 10px; letter-spacing: 0.4px; "
            "background: transparent;"
        )
        l.addWidget(copyright_lbl)
        l.addStretch()

        scroll.setWidget(container)
        return scroll
