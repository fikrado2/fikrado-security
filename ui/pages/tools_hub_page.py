"""
Fikrado Security - All-In-One Security Tools Hub
Integrates 10 essential security modules into a single unified management station.
"""
from pathlib import Path
from PySide6.QtCore import QSize, Qt, QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget
)
from core.system_info import audit_system_hardening
from tools.browser_hosts_check import browser_hosts_checker
from tools.defender_control import defender_control
from tools.dns_leak_test import dns_leak_tester
from tools.file_shredder import shred_file
from tools.firewall_manager import firewall_manager
from tools.password_checker import calculate_password_strength, check_haveibeenpwned
from tools.process_manager import process_manager
from tools.realtime_guard import realtime_guard
from tools.startup_manager import startup_manager
from ui.components.cards import ThreatBadge
from ui.components.toast import ToastNotification


class ShredderWorker(QThread):
    progress = Signal(int, int, str)
    finished = Signal(bool, str)

    def __init__(self, file_path: str, passes: int):
        super().__init__()
        self.file_path = file_path
        self.passes = passes

    def run(self):
        def cb(cur, tot, desc):
            self.progress.emit(cur, tot, desc)
        ok, msg = shred_file(self.file_path, passes=self.passes, progress_callback=cb)
        self.finished.emit(ok, msg)


class ToolsHubPage(QWidget):

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
        title = QLabel("All-In-One Security Tools Hub")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #ECEFF4;")
        header.addWidget(title)

        desc = QLabel(
            "Centralized tactical control center for endpoint hardening, firewall governance, "
            "process surveillance, DoD file destruction, and credential integrity testing."
        )
        desc.setStyleSheet("color: #9BA3AF; font-size: 13px;")
        desc.setWordWrap(True)
        header.addWidget(desc)
        layout.addLayout(header)

        # Vertical tool navigator + stacked panels (scales cleanly to 10+ tools)
        tools_split = QHBoxLayout()
        tools_split.setSpacing(14)

        self.tool_list = QListWidget()
        self.tool_list.setObjectName("ToolsNav")
        self.tool_list.setFixedWidth(212)
        self.tool_list.setFocusPolicy(Qt.NoFocus)
        self.tool_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.tool_list.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        self.tool_stack = QStackedWidget()

        tools = [
            ("⚡  Real-Time & Defender", self._build_realtime_tab()),
            ("🔥  Firewall Manager", self._build_firewall_tab()),
            ("🚀  Startup Manager", self._build_startup_tab()),
            ("⚙️  Process Manager", self._build_process_tab()),
            ("🌐  Browser & Hosts", self._build_browser_hosts_tab()),
            ("🗑️  Secure Shredder", self._build_shredder_tab()),
            ("🔑  Password & Breach", self._build_password_tab()),
            ("🛡️  Hardening Audit", self._build_hardening_tab()),
            ("📡  Network & DNS", self._build_dns_tab()),
        ]

        for label, panel in tools:
            item = QListWidgetItem(label)
            item.setSizeHint(QSize(0, 40))
            self.tool_list.addItem(item)
            self.tool_stack.addWidget(panel)

        self.tool_list.currentRowChanged.connect(self.tool_stack.setCurrentIndex)
        self.tool_list.setCurrentRow(0)

        tools_split.addWidget(self.tool_list)
        tools_split.addWidget(self.tool_stack, 1)
        layout.addLayout(tools_split)

    # ==================== 1. REALTIME & DEFENDER ====================
    def _build_realtime_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(20, 20, 20, 20)
        l.setSpacing(15)

        card1 = QFrame()
        card1.setProperty("card", True)
        c1_layout = QVBoxLayout(card1)
        c1_layout.setContentsMargins(18, 16, 18, 16)

        c1_title = QLabel("Fikrado Real-Time Protection Shield")
        c1_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #88C0D0;")
        c1_layout.addWidget(c1_title)

        self.rt_status_lbl = QLabel("Shield Status: Active (Monitoring Downloads, Temp, and New Processes)")
        self.rt_status_lbl.setStyleSheet("color: #A3BE8C; font-weight: bold; font-size: 13px;")
        c1_layout.addWidget(self.rt_status_lbl)

        btn_row = QHBoxLayout()
        self.btn_toggle_rt = QPushButton("Pause Real-Time Shield")
        self.btn_toggle_rt.setProperty("secondary", True)
        self.btn_toggle_rt.clicked.connect(self._toggle_realtime_shield)
        btn_row.addWidget(self.btn_toggle_rt)
        btn_row.addStretch()
        c1_layout.addLayout(btn_row)
        l.addWidget(card1)

        card2 = QFrame()
        card2.setProperty("card", True)
        c2_layout = QVBoxLayout(card2)
        c2_layout.setContentsMargins(18, 16, 18, 16)

        c2_title = QLabel("Microsoft Windows Defender Controls")
        c2_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #88C0D0;")
        c2_layout.addWidget(c2_title)

        def_stat = defender_control.get_status()
        def_lbl = QLabel(f"Defender Real-Time Protection: {'ENABLED' if def_stat.get('realtime_protection') else 'DISABLED'}")
        def_lbl.setStyleSheet("color: #ECEFF4; font-size: 13px;")
        c2_layout.addWidget(def_lbl)

        def_btns = QHBoxLayout()
        btn_def_scan = QPushButton("Launch Defender Quick Scan")
        btn_def_scan.setProperty("primary", True)
        btn_def_scan.clicked.connect(self._run_defender_quick_scan)
        def_btns.addWidget(btn_def_scan)

        btn_def_up = QPushButton("Update Defender Signatures")
        btn_def_up.setProperty("secondary", True)
        btn_def_up.clicked.connect(self._update_defender_sigs)
        def_btns.addWidget(btn_def_up)
        def_btns.addStretch()
        c2_layout.addLayout(def_btns)
        l.addWidget(card2)
        l.addStretch()
        return w

    def _toggle_realtime_shield(self):
        if realtime_guard._running:
            realtime_guard.stop_guard()
            self.rt_status_lbl.setText("Shield Status: Paused")
            self.rt_status_lbl.setStyleSheet("color: #BF616A; font-weight: bold;")
            self.btn_toggle_rt.setText("Activate Real-Time Shield")
        else:
            realtime_guard.start_guard()
            self.rt_status_lbl.setText("Shield Status: Active (Monitoring Downloads, Temp, and New Processes)")
            self.rt_status_lbl.setStyleSheet("color: #A3BE8C; font-weight: bold;")
            self.btn_toggle_rt.setText("Pause Real-Time Shield")

    def _run_defender_quick_scan(self):
        ToastNotification(self.window(), "Windows Defender", "Initiating Defender scan...", "info")
        ok, msg = defender_control.trigger_quick_scan()
        ToastNotification(self.window(), "Defender Scan", msg, "success" if ok else "error")

    def _update_defender_sigs(self):
        ToastNotification(self.window(), "Windows Defender", "Downloading latest virus definitions...", "info")
        ok, msg = defender_control.update_signatures()
        ToastNotification(self.window(), "Signature Update", msg, "success" if ok else "error")

    # ==================== 2. FIREWALL ====================
    def _build_firewall_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(20, 20, 20, 20)
        l.setSpacing(12)

        # Profiles State Card
        top_c = QFrame()
        top_c.setProperty("card", True)
        tc_l = QHBoxLayout(top_c)
        tc_l.setContentsMargins(16, 12, 16, 12)

        self.fw_status_lbl = QLabel("Checking firewall profiles...")
        tc_l.addWidget(self.fw_status_lbl, 1)

        btn_enable_all = QPushButton("Enable All Profiles (netsh)")
        btn_enable_all.setProperty("primary", True)
        btn_enable_all.clicked.connect(lambda: self._toggle_firewall("all", True))
        tc_l.addWidget(btn_enable_all)

        btn_refresh_fw = QPushButton("🔄 Refresh")
        btn_refresh_fw.setProperty("secondary", True)
        btn_refresh_fw.clicked.connect(self._refresh_firewall_status)
        tc_l.addWidget(btn_refresh_fw)

        l.addWidget(top_c)

        # Add Rule Row
        add_c = QFrame()
        add_c.setProperty("card", True)
        ac_l = QHBoxLayout(add_c)
        ac_l.setContentsMargins(16, 12, 16, 12)

        self.rule_name_inp = QLineEdit("Fikrado_Custom_Block")
        self.rule_port_inp = QLineEdit("445")
        self.rule_proto_combo = QComboBox()
        self.rule_proto_combo.addItems(["TCP", "UDP"])

        ac_l.addWidget(QLabel("Rule Name:"))
        ac_l.addWidget(self.rule_name_inp, 1)
        ac_l.addWidget(QLabel("Port:"))
        ac_l.addWidget(self.rule_port_inp)
        ac_l.addWidget(self.rule_proto_combo)

        btn_add_rule = QPushButton("Add Inbound Block Rule")
        btn_add_rule.setProperty("danger", True)
        btn_add_rule.clicked.connect(self._add_firewall_rule)
        ac_l.addWidget(btn_add_rule)

        l.addWidget(add_c)

        # Recent Rules Table
        self.fw_table = QTableWidget(0, 4)
        self.fw_table.setHorizontalHeaderLabels(["Rule Name", "Direction", "Action", "Profiles"])
        self.fw_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.fw_table.setEditTriggers(QTableWidget.NoEditTriggers)
        l.addWidget(self.fw_table)

        self._refresh_firewall_status()
        return w

    def _refresh_firewall_status(self):
        status = firewall_manager.get_profiles_status()
        dom = "ON" if status.get("Domain") else "OFF"
        pri = "ON" if status.get("Private") else "OFF"
        pub = "ON" if status.get("Public") else "OFF"
        self.fw_status_lbl.setText(f"Firewall Profiles: Domain ({dom}) | Private ({pri}) | Public ({pub})")

        rules = firewall_manager.get_recent_rules(limit=30)
        self.fw_table.setRowCount(0)
        for r in rules:
            row = self.fw_table.rowCount()
            self.fw_table.insertRow(row)
            self.fw_table.setItem(row, 0, QTableWidgetItem(r.get("Rule Name", "Unknown")))
            self.fw_table.setItem(row, 1, QTableWidgetItem(r.get("Direction", "In")))
            self.fw_table.setItem(row, 2, QTableWidgetItem(r.get("Action", "Allow")))
            self.fw_table.setItem(row, 3, QTableWidgetItem(r.get("Profiles", "All")))

    def _toggle_firewall(self, prof: str, enable: bool):
        ok, msg = firewall_manager.toggle_profile(prof, enable)
        ToastNotification(self.window(), "Firewall Updated", msg, "success" if ok else "error")
        self._refresh_firewall_status()

    def _add_firewall_rule(self):
        rname = self.rule_name_inp.text().strip()
        port_s = self.rule_port_inp.text().strip()
        proto = self.rule_proto_combo.currentText()
        if not rname or not port_s.isdigit():
            ToastNotification(self.window(), "Input Error", "Please provide a valid rule name and numeric port.", "warning")
            return
        ok, msg = firewall_manager.add_block_rule(rname, int(port_s), proto)
        ToastNotification(self.window(), "Rule Result", msg, "success" if ok else "error")
        self._refresh_firewall_status()

    # ==================== 3. STARTUP MANAGER ====================
    def _build_startup_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(20, 20, 20, 20)
        l.setSpacing(12)

        tb = QHBoxLayout()
        ref_btn = QPushButton("🔄 Refresh Startup Entries")
        ref_btn.setProperty("secondary", True)
        ref_btn.clicked.connect(self._refresh_startup_items)
        tb.addWidget(ref_btn)
        tb.addStretch()
        l.addLayout(tb)

        self.startup_table = QTableWidget(0, 5)
        self.startup_table.setHorizontalHeaderLabels(["Status", "Name", "Location", "Command / Target", "Toggle"])
        self.startup_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.startup_table.setEditTriggers(QTableWidget.NoEditTriggers)
        l.addWidget(self.startup_table)

        self._refresh_startup_items()
        return w

    def _refresh_startup_items(self):
        items = startup_manager.list_startup_items()
        self.startup_items_cache = items
        self.startup_table.setRowCount(0)
        for idx, it in enumerate(items):
            row = self.startup_table.rowCount()
            self.startup_table.insertRow(row)

            enabled = it.get("enabled", True)
            badge = ThreatBadge("SAFE" if enabled else "CRITICAL")
            badge.setText("ENABLED" if enabled else "DISABLED")
            self.startup_table.setCellWidget(row, 0, badge)

            self.startup_table.setItem(row, 1, QTableWidgetItem(it.get("name", "")))
            self.startup_table.setItem(row, 2, QTableWidgetItem(it.get("location", "")))
            self.startup_table.setItem(row, 3, QTableWidgetItem(it.get("command", "")))

            t_btn = QPushButton("Disable" if enabled else "Enable")
            t_btn.setProperty("secondary", True)
            t_btn.clicked.connect(lambda _, item=it: self._toggle_startup(item))
            self.startup_table.setCellWidget(row, 4, t_btn)

    def _toggle_startup(self, item: dict):
        new_state = not item.get("enabled", True)
        ok, msg = startup_manager.toggle_item(item, new_state)
        ToastNotification(self.window(), "Startup Modified", msg, "success" if ok else "error")
        self._refresh_startup_items()

    # ==================== 4. PROCESS MANAGER ====================
    def _build_process_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(20, 20, 20, 20)
        l.setSpacing(12)

        tb = QHBoxLayout()
        ref_btn = QPushButton("🔄 Refresh Processes")
        ref_btn.setProperty("primary", True)
        ref_btn.clicked.connect(self._refresh_processes)
        tb.addWidget(ref_btn)

        self.proc_filter = QLineEdit()
        self.proc_filter.setPlaceholderText("Search process name or PID...")
        self.proc_filter.textChanged.connect(self._filter_processes)
        tb.addWidget(self.proc_filter, 1)

        kill_btn = QPushButton("Kill Selected Process")
        kill_btn.setProperty("danger", True)
        kill_btn.clicked.connect(self._kill_selected_proc)
        tb.addWidget(kill_btn)

        l.addLayout(tb)

        self.proc_table = QTableWidget(0, 7)
        self.proc_table.setHorizontalHeaderLabels(["Reputation", "PID", "Process Name", "CPU %", "RAM (MB)", "Security Hints", "Executable Path"])
        self.proc_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.proc_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.proc_table.setEditTriggers(QTableWidget.NoEditTriggers)
        l.addWidget(self.proc_table)

        self._refresh_processes()
        return w

    def _refresh_processes(self):
        self.proc_cache = process_manager.list_processes()
        self._populate_proc_table(self.proc_cache)

    def _populate_proc_table(self, data: list):
        self.proc_table.setRowCount(0)
        for p in data:
            row = self.proc_table.rowCount()
            self.proc_table.insertRow(row)

            rep = p.get("reputation", "Normal")
            badge = ThreatBadge("SAFE" if rep == "Normal" else "CRITICAL")
            badge.setText(rep.upper())
            self.proc_table.setCellWidget(row, 0, badge)

            self.proc_table.setItem(row, 1, QTableWidgetItem(str(p.get("pid"))))
            self.proc_table.setItem(row, 2, QTableWidgetItem(p.get("name")))
            self.proc_table.setItem(row, 3, QTableWidgetItem(f"{p.get('cpu')}%"))
            self.proc_table.setItem(row, 4, QTableWidgetItem(f"{p.get('mem_mb')} MB"))
            self.proc_table.setItem(row, 5, QTableWidgetItem(p.get("reputation_reason")))
            self.proc_table.setItem(row, 6, QTableWidgetItem(p.get("exe")))

    def _filter_processes(self, text: str):
        q = text.strip().lower()
        if not q:
            self._populate_proc_table(self.proc_cache)
            return
        filtered = [p for p in self.proc_cache if q in p.get("name", "").lower() or q in str(p.get("pid"))]
        self._populate_proc_table(filtered)

    def _kill_selected_proc(self):
        rows = self.proc_table.selectedIndexes()
        if not rows:
            return
        row = rows[0].row()
        pid = int(self.proc_table.item(row, 1).text())
        ok, msg = process_manager.terminate_process(pid)
        ToastNotification(self.window(), "Process Termination", msg, "success" if ok else "error")
        self._refresh_processes()

    # ==================== 5. BROWSER & HOSTS ====================
    def _build_browser_hosts_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(20, 20, 20, 20)
        l.setSpacing(14)

        # Hosts Card
        h_card = QFrame()
        h_card.setProperty("card", True)
        hc_l = QVBoxLayout(h_card)
        hc_l.setContentsMargins(16, 14, 16, 14)

        h_title = QLabel("Windows Hosts File Integrity (C:\\Windows\\System32\\drivers\\etc\\hosts)")
        h_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #88C0D0;")
        hc_l.addWidget(h_title)

        is_clean, lines, flagged = browser_hosts_checker.check_hosts_file()
        status_text = "✔ Hosts file is clean and uncorrupted." if is_clean else f"⚠️ Flagged {len(flagged)} suspicious domain redirects!"
        h_status = QLabel(status_text)
        h_status.setStyleSheet(f"color: {'#A3BE8C' if is_clean else '#BF616A'}; font-weight: bold;")
        hc_l.addWidget(h_status)

        h_btns = QHBoxLayout()
        btn_clean_hosts = QPushButton("Restore Clean Default Hosts File")
        btn_clean_hosts.setProperty("secondary", True)
        btn_clean_hosts.clicked.connect(self._restore_hosts)
        h_btns.addWidget(btn_clean_hosts)
        h_btns.addStretch()
        hc_l.addLayout(h_btns)
        l.addWidget(h_card)

        # Browser Extensions Card
        ext_card = QFrame()
        ext_card.setProperty("card", True)
        ec_l = QVBoxLayout(ext_card)
        ec_l.setContentsMargins(16, 14, 16, 14)

        e_title = QLabel("Installed Browser Extensions & Elevated Permissions Audit")
        e_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #88C0D0;")
        ec_l.addWidget(e_title)

        self.ext_table = QTableWidget(0, 5)
        self.ext_table.setHorizontalHeaderLabels(["Risk", "Browser", "Extension Name", "Version", "High-Risk Permissions"])
        self.ext_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.ext_table.setEditTriggers(QTableWidget.NoEditTriggers)
        ec_l.addWidget(self.ext_table)

        l.addWidget(ext_card)

        self._refresh_extensions()
        return w

    def _restore_hosts(self):
        ok, msg = browser_hosts_checker.restore_default_hosts()
        ToastNotification(self.window(), "Hosts File", msg, "success" if ok else "error")

    def _refresh_extensions(self):
        exts = browser_hosts_checker.check_browser_extensions()
        self.ext_table.setRowCount(0)
        for e in exts:
            row = self.ext_table.rowCount()
            self.ext_table.insertRow(row)

            badge = ThreatBadge(e.get("severity", "Low"))
            self.ext_table.setCellWidget(row, 0, badge)

            self.ext_table.setItem(row, 1, QTableWidgetItem(e.get("browser")))
            self.ext_table.setItem(row, 2, QTableWidgetItem(e.get("name")))
            self.ext_table.setItem(row, 3, QTableWidgetItem(e.get("version")))

            perms_str = ", ".join(e.get("risky_permissions", [])) or "Standard Permissions"
            self.ext_table.setItem(row, 4, QTableWidgetItem(perms_str))

    # ==================== 6. FILE SHREDDER ====================
    def _build_shredder_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(20, 20, 20, 20)
        l.setSpacing(14)

        card = QFrame()
        card.setProperty("card", True)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(20, 18, 20, 18)
        cl.setSpacing(12)

        t = QLabel("DoD 5220.22-M Military-Grade File Shredder")
        t.setStyleSheet("font-size: 16px; font-weight: bold; color: #BF616A;")
        cl.addWidget(t)

        d = QLabel(
            "Permanently destroys sensitive files by overwriting data blocks with zeros (0x00), ones (0xFF), "
            "and cryptographic pseudo-random sequences, followed by MFT metadata obfuscation and unlinking. "
            "Once shredded, data cannot be recovered by forensic software."
        )
        d.setWordWrap(True)
        d.setStyleSheet("color: #D8DEE9; font-size: 12px;")
        cl.addWidget(d)

        pick_row = QHBoxLayout()
        self.shred_path_lbl = QLabel("No file selected for destruction.")
        self.shred_path_lbl.setStyleSheet("color: #ECEFF4; font-family: Consolas; font-size: 12px;")
        pick_row.addWidget(self.shred_path_lbl, 1)

        pick_btn = QPushButton("Select File to Shred")
        pick_btn.setProperty("secondary", True)
        pick_btn.clicked.connect(self._browse_shred_file)
        pick_row.addWidget(pick_btn)
        cl.addLayout(pick_row)

        opt_row = QHBoxLayout()
        opt_row.addWidget(QLabel("Overwriting Standard:"))
        self.shred_passes_combo = QComboBox()
        self.shred_passes_combo.addItem("DoD 5220.22-M (3 Passes) - High Security", 3)
        self.shred_passes_combo.addItem("DoD 5220.22-M ECE (7 Passes) - Maximum Paranoia", 7)
        opt_row.addWidget(self.shred_passes_combo)
        opt_row.addStretch()
        cl.addLayout(opt_row)

        self.shred_status_lbl = QLabel("Ready.")
        self.shred_status_lbl.setStyleSheet("color: #9BA3AF; font-size: 12px;")
        cl.addWidget(self.shred_status_lbl)

        self.shred_progress = QProgressBar()
        self.shred_progress.setRange(0, 100)
        self.shred_progress.setValue(0)
        cl.addWidget(self.shred_progress)

        self.btn_shred_now = QPushButton("🔥 Permanently Shred File Now")
        self.btn_shred_now.setProperty("danger", True)
        self.btn_shred_now.clicked.connect(self._start_shredding)
        cl.addWidget(self.btn_shred_now)

        l.addWidget(card)
        l.addStretch()
        return w

    def _browse_shred_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select File to Permanently Shred")
        if f:
            self.shred_target_file = f
            self.shred_path_lbl.setText(f)

    def _start_shredding(self):
        if not hasattr(self, "shred_target_file") or not self.shred_target_file:
            ToastNotification(self.window(), "No File", "Please select a file to shred.", "warning")
            return
        passes = self.shred_passes_combo.currentData()
        self.btn_shred_now.setEnabled(False)
        self.shred_thread = ShredderWorker(self.shred_target_file, passes)
        self.shred_thread.progress.connect(self._on_shred_progress)
        self.shred_thread.finished.connect(self._on_shred_finished)
        self.shred_thread.start()

    def _on_shred_progress(self, cur, tot, desc):
        pct = int((cur / tot) * 100)
        self.shred_progress.setValue(pct)
        self.shred_status_lbl.setText(desc)

    def _on_shred_finished(self, ok, msg):
        self.btn_shred_now.setEnabled(True)
        self.shred_progress.setValue(100 if ok else 0)
        self.shred_status_lbl.setText(msg)
        ToastNotification(self.window(), "File Shredder", msg, "success" if ok else "error")

    # ==================== 7. PASSWORD & BREACH ====================
    def _build_password_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(20, 20, 20, 20)
        l.setSpacing(14)

        card = QFrame()
        card.setProperty("card", True)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(20, 18, 20, 18)
        cl.setSpacing(12)

        t = QLabel("Password Complexity & Data Breach Auditor")
        t.setStyleSheet("font-size: 16px; font-weight: bold; color: #88C0D0;")
        cl.addWidget(t)

        d = QLabel(
            "Tests password entropy locally and verifies against 800+ million known breached credentials "
            "using the <b>HaveIBeenPwned k-anonymity protocol</b> (zero plaintext or full hash is ever sent)."
        )
        d.setWordWrap(True)
        d.setStyleSheet("color: #D8DEE9; font-size: 12px;")
        cl.addWidget(d)

        inp_row = QHBoxLayout()
        self.pwd_input = QLineEdit()
        self.pwd_input.setPlaceholderText("Enter password to audit...")
        self.pwd_input.setEchoMode(QLineEdit.Password)
        self.pwd_input.textChanged.connect(self._on_pwd_typed)
        inp_row.addWidget(self.pwd_input, 1)

        self.btn_show_pwd = QPushButton("👁️ Show")
        self.btn_show_pwd.setProperty("secondary", True)
        self.btn_show_pwd.clicked.connect(self._toggle_pwd_visibility)
        inp_row.addWidget(self.btn_show_pwd)
        cl.addLayout(inp_row)

        # Strength Bar
        self.pwd_strength_bar = QProgressBar()
        self.pwd_strength_bar.setRange(0, 100)
        self.pwd_strength_bar.setValue(0)
        cl.addWidget(self.pwd_strength_bar)

        self.pwd_verdict_lbl = QLabel("Enter a password above to evaluate.")
        self.pwd_verdict_lbl.setStyleSheet("color: #9BA3AF; font-size: 13px; font-weight: bold;")
        cl.addWidget(self.pwd_verdict_lbl)

        btn_check_hibp = QPushButton("🌐 Check Against Public Breach Databases (HaveIBeenPwned)")
        btn_check_hibp.setProperty("primary", True)
        btn_check_hibp.clicked.connect(self._check_hibp)
        cl.addWidget(btn_check_hibp)

        self.breach_result_box = QTextEdit()
        self.breach_result_box.setReadOnly(True)
        self.breach_result_box.setFixedHeight(90)
        self.breach_result_box.setStyleSheet("background-color: #2E3440; border: 1px solid #4C566A; font-size: 12px;")
        cl.addWidget(self.breach_result_box)

        l.addWidget(card)
        l.addStretch()
        return w

    def _toggle_pwd_visibility(self):
        if self.pwd_input.echoMode() == QLineEdit.Password:
            self.pwd_input.setEchoMode(QLineEdit.Normal)
            self.btn_show_pwd.setText("🙈 Hide")
        else:
            self.pwd_input.setEchoMode(QLineEdit.Password)
            self.btn_show_pwd.setText("👁️ Show")

    def _on_pwd_typed(self, text: str):
        res = calculate_password_strength(text)
        self.pwd_strength_bar.setValue(res["score"])
        self.pwd_verdict_lbl.setText(f"Strength: {res['verdict']} ({res['entropy_bits']} bits entropy)")
        self.pwd_verdict_lbl.setStyleSheet(f"color: {res['color']}; font-weight: bold;")

    def _check_hibp(self):
        pwd = self.pwd_input.text()
        if not pwd:
            ToastNotification(self.window(), "Empty Password", "Enter a password to check against breach records.", "warning")
            return
        is_pwned, count, msg = check_haveibeenpwned(pwd)
        color = "#BF616A" if is_pwned else "#A3BE8C"
        self.breach_result_box.setHtml(f"<p style='color: {color}; font-weight: bold; margin: 0;'>{msg}</p>")
        ToastNotification(self.window(), "Breach Audit", msg, "error" if is_pwned else "success")

    # ==================== 8. HARDENING AUDIT ====================
    def _build_hardening_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(20, 20, 20, 20)
        l.setSpacing(12)

        tb = QHBoxLayout()
        t_lbl = QLabel("Windows Security Posture & Hardening Controls")
        t_lbl.setStyleSheet("font-size: 16px; font-weight: bold; color: #88C0D0;")
        tb.addWidget(t_lbl)
        tb.addStretch()

        ref_btn = QPushButton("🔄 Re-run Audit")
        ref_btn.setProperty("secondary", True)
        ref_btn.clicked.connect(self._refresh_hardening)
        tb.addWidget(ref_btn)
        l.addLayout(tb)

        self.hard_table = QTableWidget(0, 5)
        self.hard_table.setHorizontalHeaderLabels(["Status", "Category", "Security Control", "Audit Evaluation", "Remediation"])
        self.hard_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.hard_table.setEditTriggers(QTableWidget.NoEditTriggers)
        l.addWidget(self.hard_table)

        self._refresh_hardening()
        return w

    def _refresh_hardening(self):
        checks, score = audit_system_hardening()
        self.hard_table.setRowCount(0)
        for c in checks:
            row = self.hard_table.rowCount()
            self.hard_table.insertRow(row)

            badge = ThreatBadge(c.get("status", "Warning"))
            self.hard_table.setCellWidget(row, 0, badge)

            self.hard_table.setItem(row, 1, QTableWidgetItem(c.get("category", "")))
            self.hard_table.setItem(row, 2, QTableWidgetItem(c.get("name", "")))
            self.hard_table.setItem(row, 3, QTableWidgetItem(c.get("detail", "")))
            self.hard_table.setItem(row, 4, QTableWidgetItem(c.get("remediation", "")))

    # ==================== 9. NETWORK & DNS ====================
    def _build_dns_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(20, 20, 20, 20)
        l.setSpacing(14)

        card = QFrame()
        card.setProperty("card", True)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(20, 18, 20, 18)
        cl.setSpacing(10)

        t = QLabel("Network Interfaces, Gateways, and DNS Leak Diagnostic")
        t.setStyleSheet("font-size: 16px; font-weight: bold; color: #88C0D0;")
        cl.addWidget(t)

        self.dns_summary_lbl = QLabel("Click 'Run Diagnostic' to resolve active routing, DNS servers, and external IP.")
        self.dns_summary_lbl.setStyleSheet("color: #D8DEE9; font-size: 12px;")
        cl.addWidget(self.dns_summary_lbl)

        btn_run = QPushButton("📡 Run Network && DNS Diagnostic")
        btn_run.setProperty("primary", True)
        btn_run.clicked.connect(self._run_dns_diagnostic)
        cl.addWidget(btn_run)
        l.addWidget(card)

        self.iface_table = QTableWidget(0, 5)
        self.iface_table.setHorizontalHeaderLabels(["Interface", "Status", "Speed", "IPv4 Address", "MAC Address"])
        self.iface_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.iface_table.setEditTriggers(QTableWidget.NoEditTriggers)
        l.addWidget(self.iface_table)

        return w

    def _run_dns_diagnostic(self):
        ifaces = dns_leak_tester.get_network_interfaces()
        dns_servers = dns_leak_tester.get_configured_dns_servers()
        ext_info = dns_leak_tester.check_public_ip_and_leak()

        dns_str = ", ".join(dns_servers) if dns_servers else "None (DHCP Auto)"
        summary = (
            f"<b>Public IP:</b> {ext_info.get('public_ip')} | "
            f"<b>ISP:</b> {ext_info.get('isp')} | "
            f"<b>Location:</b> {ext_info.get('city')}, {ext_info.get('country')}<br>"
            f"<b>Configured DNS Servers:</b> {dns_str}"
        )
        self.dns_summary_lbl.setText(summary)

        self.iface_table.setRowCount(0)
        for i in ifaces:
            row = self.iface_table.rowCount()
            self.iface_table.insertRow(row)
            self.iface_table.setItem(row, 0, QTableWidgetItem(i.get("interface")))
            self.iface_table.setItem(row, 1, QTableWidgetItem("UP" if i.get("is_up") else "DOWN"))
            self.iface_table.setItem(row, 2, QTableWidgetItem(f"{i.get('speed_mbps')} Mbps"))
            self.iface_table.setItem(row, 3, QTableWidgetItem(i.get("ipv4")))
            self.iface_table.setItem(row, 4, QTableWidgetItem(i.get("mac")))

        ToastNotification(self.window(), "Diagnostic Finished", f"Public IP: {ext_info.get('public_ip')}", "success")
