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
from core.logger import logger
from core.system_info import get_hardening_audit
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
from ui.components.loading_overlay import LoadingOverlay
from ui.components.toast import ToastNotification
from ui.icons import icon_label, load_icon, set_icon
from ui.workers import FunctionWorker


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
        self._workers = set()
        self._active_tasks = set()
        self._tab_overlays = {}
        self._loaded_tabs = set()
        self._loading_tabs = set()
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
            ("Real-Time & Defender", "realtime", self._build_realtime_tab()),
            ("Firewall Manager", "firewall", self._build_firewall_tab()),
            ("Startup Manager", "startup", self._build_startup_tab()),
            ("Process Manager", "process", self._build_process_tab()),
            ("Browser & Hosts", "browser", self._build_browser_hosts_tab()),
            ("Secure Shredder", "shredder", self._build_shredder_tab()),
            ("Password & Breach", "password", self._build_password_tab()),
            ("Hardening Audit", "hardening", self._build_hardening_tab()),
            ("Network & DNS", "dns", self._build_dns_tab()),
        ]

        for index, (label, icon_name, panel) in enumerate(tools):
            item = QListWidgetItem(label)
            item.setIcon(load_icon(icon_name, 18))
            item.setSizeHint(QSize(0, 40))
            self.tool_list.addItem(item)
            self.tool_stack.addWidget(panel)
            self._tab_overlays[index] = LoadingOverlay(panel, "Loading tool data…")

        self.tool_list.currentRowChanged.connect(self._on_tool_selected)
        self.tool_list.setCurrentRow(0)

        tools_split.addWidget(self.tool_list)
        tools_split.addWidget(self.tool_stack, 1)
        layout.addLayout(tools_split)

    # --------------------------------------------------------- async plumbing
    def _on_tool_selected(self, index: int):
        if index < 0:
            return
        self.tool_stack.setCurrentIndex(index)
        if index in self._loaded_tabs or index in self._loading_tabs:
            return
        self._load_tab(index)

    def _load_tab(self, index: int):
        loaders = {
            0: self._load_defender_status,
            1: self._load_firewall_status,
            2: self._load_startup_items,
            3: self._load_processes,
            4: self._load_browser_data,
            7: self._load_hardening_audit,
        }
        loader = loaders.get(index)
        if loader is None:
            self._loaded_tabs.add(index)
            return

        self._loading_tabs.add(index)
        loader(index)

    def _start_task(self, key, overlay, message, fn, on_success, tab_index=None):
        """Run a slow query off the UI thread and refresh the matching panel."""
        if key in self._active_tasks:
            return

        self._active_tasks.add(key)
        if overlay is not None:
            overlay.show_message(message)

        worker = FunctionWorker(fn, self)
        self._workers.add(worker)

        def finish():
            self._workers.discard(worker)
            self._active_tasks.discard(key)
            if overlay is not None:
                overlay.hide_overlay()
            if tab_index is not None:
                self._loading_tabs.discard(tab_index)

        def on_ok(result):
            finish()
            try:
                on_success(result)
            except Exception as exc:
                logger.exception("Tools Hub panel update failed")
                ToastNotification(self.window(), "Tools Hub", str(exc), "error")
                return
            if tab_index is not None:
                self._loaded_tabs.add(tab_index)

        def on_error(message):
            finish()
            ToastNotification(self.window(), "Tools Hub", message, "error")

        worker.finished_ok.connect(on_ok)
        worker.failed.connect(on_error)
        worker.start()

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

        status_row = QHBoxLayout()
        status_row.setSpacing(8)
        self.rt_status_icon = icon_label("shield", 18)
        status_row.addWidget(self.rt_status_icon)
        self.rt_status_lbl = QLabel("Shield Status: Active")
        self.rt_status_lbl.setStyleSheet("color: #A3BE8C; font-weight: bold; font-size: 13px;")
        status_row.addWidget(self.rt_status_lbl, 1)
        c1_layout.addLayout(status_row)

        btn_row = QHBoxLayout()
        self.btn_toggle_rt = QPushButton("Pause Real-Time Shield")
        self.btn_toggle_rt.setProperty("secondary", True)
        set_icon(self.btn_toggle_rt, "pause", 15)
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

        self.def_status_lbl = QLabel("Defender Real-Time Protection: Checking…")
        self.def_status_lbl.setStyleSheet("color: #D8DEE9; font-size: 13px;")
        c2_layout.addWidget(self.def_status_lbl)

        def_btns = QHBoxLayout()
        btn_def_scan = QPushButton("Launch Defender Quick Scan")
        btn_def_scan.setProperty("primary", True)
        set_icon(btn_def_scan, "search", 15, "#1A1F27")
        btn_def_scan.clicked.connect(self._run_defender_quick_scan)
        def_btns.addWidget(btn_def_scan)

        btn_def_up = QPushButton("Update Defender Signatures")
        btn_def_up.setProperty("secondary", True)
        set_icon(btn_def_up, "update", 15)
        btn_def_up.clicked.connect(self._update_defender_sigs)
        def_btns.addWidget(btn_def_up)
        def_btns.addStretch()
        c2_layout.addLayout(def_btns)
        l.addWidget(card2)
        l.addStretch()

        self.defender_overlay = LoadingOverlay(card2, "Querying Windows Defender…")
        self._refresh_realtime_status()
        return w

    def _refresh_realtime_status(self):
        if realtime_guard.is_active:
            self.rt_status_lbl.setText(
                f"Shield Status: Active — {realtime_guard.scope_summary()}"
            )
            self.rt_status_lbl.setStyleSheet(
                "color: #A3BE8C; font-weight: bold; font-size: 13px;"
            )
            self.btn_toggle_rt.setText("Pause Real-Time Shield")
            set_icon(self.btn_toggle_rt, "pause", 15)
        else:
            self.rt_status_lbl.setText(
                "Shield Status: Paused — no real-time checks are running"
            )
            self.rt_status_lbl.setStyleSheet(
                "color: #EBCB8B; font-weight: bold; font-size: 13px;"
            )
            self.btn_toggle_rt.setText("Resume Real-Time Shield")
            set_icon(self.btn_toggle_rt, "play", 15)

    def _toggle_realtime_shield(self):
        if realtime_guard.is_active:
            realtime_guard.pause_guard()
        else:
            realtime_guard.start_guard()
        self._refresh_realtime_status()

    def _load_defender_status(self, tab_index=0):
        self._start_task(
            "defender_status",
            getattr(self, "defender_overlay", None),
            "Querying Windows Defender status…",
            defender_control.get_status,
            self._apply_defender_status,
            tab_index,
        )

    def _apply_defender_status(self, status: dict):
        enabled = bool(status.get("realtime_protection"))
        self.def_status_lbl.setText(
            f"Defender Real-Time Protection: {'ENABLED' if enabled else 'DISABLED'}"
        )
        self.def_status_lbl.setStyleSheet(
            f"color: {'#A3BE8C' if enabled else '#BF616A'}; font-size: 13px; font-weight: bold;"
        )

    def _run_defender_quick_scan(self):
        ToastNotification(self.window(), "Windows Defender", "Initiating Defender scan...", "info")
        self._start_task(
            "defender_scan",
            getattr(self, "defender_overlay", None),
            "Launching Windows Defender quick scan…",
            defender_control.trigger_quick_scan,
            lambda result: ToastNotification(
                self.window(), "Defender Scan", result[1], "success" if result[0] else "error"
            ),
        )

    def _update_defender_sigs(self):
        ToastNotification(self.window(), "Windows Defender", "Downloading latest virus definitions...", "info")
        self._start_task(
            "defender_update",
            getattr(self, "defender_overlay", None),
            "Updating Windows Defender signatures…",
            defender_control.update_signatures,
            lambda result: ToastNotification(
                self.window(), "Signature Update", result[1], "success" if result[0] else "error"
            ),
        )

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

        btn_refresh_fw = QPushButton("Refresh")
        btn_refresh_fw.setProperty("secondary", True)
        set_icon(btn_refresh_fw, "refresh", 15)
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

        return w

    def _load_firewall_status(self, tab_index=1):
        self._start_task(
            "firewall_status",
            self._tab_overlays.get(1),
            "Reading firewall profiles and rules…",
            lambda: (
                firewall_manager.get_profiles_status(),
                firewall_manager.get_recent_rules(limit=30),
            ),
            self._apply_firewall_status,
            tab_index,
        )

    def _apply_firewall_status(self, result):
        status, rules = result
        dom = "ON" if status.get("Domain") else "OFF"
        pri = "ON" if status.get("Private") else "OFF"
        pub = "ON" if status.get("Public") else "OFF"
        self.fw_status_lbl.setText(f"Firewall Profiles: Domain ({dom}) | Private ({pri}) | Public ({pub})")

        self.fw_table.setRowCount(0)
        for r in rules:
            row = self.fw_table.rowCount()
            self.fw_table.insertRow(row)
            self.fw_table.setItem(row, 0, QTableWidgetItem(r.get("Rule Name", "Unknown")))
            self.fw_table.setItem(row, 1, QTableWidgetItem(r.get("Direction", "In")))
            self.fw_table.setItem(row, 2, QTableWidgetItem(r.get("Action", "Allow")))
            self.fw_table.setItem(row, 3, QTableWidgetItem(r.get("Profiles", "All")))

    def _refresh_firewall_status(self):
        self._load_firewall_status(tab_index=1)

    def _toggle_firewall(self, prof: str, enable: bool):
        self._start_task(
            "firewall_toggle",
            self._tab_overlays.get(1),
            "Updating Windows Firewall…",
            lambda: firewall_manager.toggle_profile(prof, enable),
            self._on_firewall_action_done,
            tab_index=1,
        )

    def _add_firewall_rule(self):
        rname = self.rule_name_inp.text().strip()
        port_s = self.rule_port_inp.text().strip()
        proto = self.rule_proto_combo.currentText()
        if not rname or not port_s.isdigit():
            ToastNotification(self.window(), "Input Error", "Please provide a valid rule name and numeric port.", "warning")
            return
        self._start_task(
            "firewall_add",
            self._tab_overlays.get(1),
            "Creating inbound block rule…",
            lambda: firewall_manager.add_block_rule(rname, int(port_s), proto),
            self._on_firewall_action_done,
            tab_index=1,
        )

    def _on_firewall_action_done(self, result):
        ok, msg = result
        ToastNotification(self.window(), "Firewall Updated", msg, "success" if ok else "error")
        self._refresh_firewall_status()

    # ==================== 3. STARTUP MANAGER ====================
    def _build_startup_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(20, 20, 20, 20)
        l.setSpacing(12)

        tb = QHBoxLayout()
        ref_btn = QPushButton("Refresh Startup Entries")
        ref_btn.setProperty("secondary", True)
        set_icon(ref_btn, "refresh", 15)
        ref_btn.clicked.connect(self._refresh_startup_items)
        tb.addWidget(ref_btn)
        tb.addStretch()
        l.addLayout(tb)

        self.startup_table = QTableWidget(0, 5)
        self.startup_table.setHorizontalHeaderLabels(["Status", "Name", "Location", "Command / Target", "Toggle"])
        self.startup_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.startup_table.setEditTriggers(QTableWidget.NoEditTriggers)
        l.addWidget(self.startup_table)

        return w

    def _load_startup_items(self, tab_index=2):
        self._start_task(
            "startup_items",
            self._tab_overlays.get(2),
            "Reading startup entries…",
            startup_manager.list_startup_items,
            self._apply_startup_items,
            tab_index,
        )

    def _apply_startup_items(self, items):
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

    def _refresh_startup_items(self):
        self._load_startup_items(tab_index=2)

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
        ref_btn = QPushButton("Refresh Processes")
        ref_btn.setProperty("primary", True)
        set_icon(ref_btn, "refresh", 15, "#1A1F27")
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

        self.proc_cache = []
        return w

    def _load_processes(self, tab_index=3):
        self._start_task(
            "processes",
            self._tab_overlays.get(3),
            "Enumerating running processes…",
            process_manager.list_processes,
            self._apply_processes,
            tab_index,
        )

    def _apply_processes(self, data):
        self.proc_cache = data
        self._populate_proc_table(data)

    def _refresh_processes(self):
        self._load_processes(tab_index=3)

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

        self.hosts_status_lbl = QLabel("Checking hosts file integrity…")
        self.hosts_status_lbl.setStyleSheet("color: #D8DEE9; font-weight: bold;")
        hc_l.addWidget(self.hosts_status_lbl)

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

        return w

    def _restore_hosts(self):
        ok, msg = browser_hosts_checker.restore_default_hosts()
        ToastNotification(self.window(), "Hosts File", msg, "success" if ok else "error")

    def _load_browser_data(self, tab_index=4):
        self._start_task(
            "browser_data",
            self._tab_overlays.get(4),
            "Auditing hosts file and browser extensions…",
            lambda: (
                browser_hosts_checker.check_hosts_file(),
                browser_hosts_checker.check_browser_extensions(),
            ),
            self._apply_browser_data,
            tab_index,
        )

    def _apply_browser_data(self, result):
        hosts, extensions = result
        is_clean, lines, flagged = hosts
        if is_clean:
            self.hosts_status_lbl.setText("OK — Hosts file is clean and uncorrupted.")
            self.hosts_status_lbl.setStyleSheet("color: #A3BE8C; font-weight: bold;")
        else:
            self.hosts_status_lbl.setText(
                f"Warning — {len(flagged)} suspicious domain redirects flagged!"
            )
            self.hosts_status_lbl.setStyleSheet("color: #BF616A; font-weight: bold;")
        self._populate_extensions(extensions)

    def _populate_extensions(self, exts):
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

    def _refresh_extensions(self):
        self._load_browser_data(tab_index=4)

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

        self.btn_shred_now = QPushButton("Permanently Shred File Now")
        self.btn_shred_now.setProperty("danger", True)
        set_icon(self.btn_shred_now, "shredder", 15, "#FFFFFF")
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

        self.btn_show_pwd = QPushButton("Show")
        self.btn_show_pwd.setProperty("secondary", True)
        set_icon(self.btn_show_pwd, "eye", 15)
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

        btn_check_hibp = QPushButton("Check Against Public Breach Databases (HaveIBeenPwned)")
        btn_check_hibp.setProperty("primary", True)
        set_icon(btn_check_hibp, "globe", 15, "#1A1F27")
        btn_check_hibp.clicked.connect(self._check_hibp)
        cl.addWidget(btn_check_hibp)

        self.breach_result_box = QTextEdit()
        self.breach_result_box.setReadOnly(True)
        self.breach_result_box.setFixedHeight(90)
        self.breach_result_box.setStyleSheet("background-color: rgba(12, 16, 21, 175); border: 1px solid rgba(255, 255, 255, 20); border-radius: 9px; font-size: 12px;")
        cl.addWidget(self.breach_result_box)

        l.addWidget(card)
        l.addStretch()
        return w

    def _toggle_pwd_visibility(self):
        if self.pwd_input.echoMode() == QLineEdit.Password:
            self.pwd_input.setEchoMode(QLineEdit.Normal)
            self.btn_show_pwd.setText("Hide")
            set_icon(self.btn_show_pwd, "eye_off", 15)
        else:
            self.pwd_input.setEchoMode(QLineEdit.Password)
            self.btn_show_pwd.setText("Show")
            set_icon(self.btn_show_pwd, "eye", 15)

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
        self._start_task(
            "hibp_check",
            self._tab_overlays.get(6),
            "Checking breach databases via k-anonymity…",
            lambda: check_haveibeenpwned(pwd),
            self._apply_hibp_result,
        )

    def _apply_hibp_result(self, result):
        is_pwned, count, msg = result
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

        ref_btn = QPushButton("Re-run Audit")
        ref_btn.setProperty("secondary", True)
        set_icon(ref_btn, "refresh", 15)
        ref_btn.clicked.connect(self._refresh_hardening)
        tb.addWidget(ref_btn)
        l.addLayout(tb)

        self.hard_table = QTableWidget(0, 5)
        self.hard_table.setHorizontalHeaderLabels(["Status", "Category", "Security Control", "Audit Evaluation", "Remediation"])
        self.hard_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.hard_table.setEditTriggers(QTableWidget.NoEditTriggers)
        l.addWidget(self.hard_table)

        return w

    def _load_hardening_audit(self, tab_index=7):
        self._start_task(
            "hardening_audit",
            self._tab_overlays.get(7),
            "Running Windows hardening audit…",
            lambda: get_hardening_audit(max_age_seconds=300),
            self._apply_hardening_audit,
            tab_index,
        )

    def _apply_hardening_audit(self, result):
        checks, score = result
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

    def _refresh_hardening(self):
        self._load_hardening_audit(tab_index=7)

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

        btn_run = QPushButton("Run Network && DNS Diagnostic")
        btn_run.setProperty("primary", True)
        set_icon(btn_run, "dns", 15, "#1A1F27")
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
        self._start_task(
            "dns_diagnostic",
            self._tab_overlays.get(8),
            "Resolving interfaces, DNS servers and public IP…",
            lambda: (
                dns_leak_tester.get_network_interfaces(),
                dns_leak_tester.get_configured_dns_servers(),
                dns_leak_tester.check_public_ip_and_leak(),
            ),
            self._apply_dns_diagnostic,
        )

    def _apply_dns_diagnostic(self, result):
        ifaces, dns_servers, ext_info = result

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
