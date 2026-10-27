"""
Fikrado Security - Open Port & Network Scanner Page
Visualizes listening ports, maps PIDs and processes, flags risky ports with plain-language alerts,
and provides one-click remediation (Kill Process, Add Firewall Block Rule).
"""
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget
)
from scanners.network_scanner import (
    add_firewall_block_rule,
    kill_process,
    list_active_connections,
    scan_port_range
)
from ui.components.cards import ThreatBadge
from ui.components.dialogs import NetworkConsentDialog
from ui.components.toast import ToastNotification
from ui.icons import set_icon


class RemoteScanThread(QThread):
    finished_scan = Signal(list)

    def __init__(self, target_ip: str, ports: list):
        super().__init__()
        self.target_ip = target_ip
        self.ports = ports

    def run(self):
        results = scan_port_range(self.target_ip, self.ports)
        self.finished_scan.emit(results)


class PortScannerPage(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.active_connections_data = []
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 25, 30, 25)
        layout.setSpacing(18)

        # Header
        header = QVBoxLayout()
        header.setSpacing(4)
        title = QLabel("Open Port & Network Security Scanner")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #ECEFF4;")
        header.addWidget(title)

        desc = QLabel(
            "Monitors active TCP/UDP sockets, exposes open listening ports, and identifies high-risk services "
            "vulnerable to external exploit chains."
        )
        desc.setStyleSheet("color: #9BA3AF; font-size: 13px;")
        desc.setWordWrap(True)
        header.addWidget(desc)
        layout.addLayout(header)

        # Tabs for Local Host vs Remote IP Scan
        self.tabs = QTabWidget()

        # Tab 1: Local Endpoint Active Connections
        tab_local = QWidget()
        tl_layout = QVBoxLayout(tab_local)
        tl_layout.setContentsMargins(15, 15, 15, 15)
        tl_layout.setSpacing(12)

        # Toolbar
        tb_row = QHBoxLayout()
        refresh_btn = QPushButton("Refresh Local Connections")
        refresh_btn.setProperty("primary", True)
        set_icon(refresh_btn, "refresh", 15, "#1A1F27")
        refresh_btn.clicked.connect(self.refresh_connections)
        tb_row.addWidget(refresh_btn)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter by port, process name, or PID...")
        self.filter_input.textChanged.connect(self._filter_table)
        tb_row.addWidget(self.filter_input, 1)

        tl_layout.addLayout(tb_row)

        # Splitter: Table on left, Plain-Language detail panel on right
        splitter = QSplitter(Qt.Horizontal)

        # Table
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Risk", "Port", "Proto", "Service", "Process (PID)", "Status"])
        port_header = self.table.horizontalHeader()
        port_header.setSectionResizeMode(0, QHeaderView.Fixed)
        port_header.setSectionResizeMode(1, QHeaderView.Fixed)
        port_header.setSectionResizeMode(2, QHeaderView.Fixed)
        port_header.setSectionResizeMode(3, QHeaderView.Stretch)
        port_header.setSectionResizeMode(4, QHeaderView.Stretch)
        port_header.setSectionResizeMode(5, QHeaderView.Fixed)
        self.table.setColumnWidth(0, 78)
        self.table.setColumnWidth(1, 64)
        self.table.setColumnWidth(2, 62)
        self.table.setColumnWidth(5, 80)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._on_row_selected)
        splitter.addWidget(self.table)

        # Detail & Remediation Card
        detail_card = QFrame()
        detail_card.setProperty("card", True)
        detail_layout = QVBoxLayout(detail_card)
        detail_layout.setContentsMargins(16, 16, 16, 16)
        detail_layout.setSpacing(12)

        det_title = QLabel("Port Risk & Intelligence")
        det_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #88C0D0;")
        detail_layout.addWidget(det_title)

        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setStyleSheet("background-color: rgba(12, 16, 21, 150); border: 1px solid rgba(255, 255, 255, 18); border-radius: 9px; font-size: 12px;")
        self.detail_text.setHtml("<p style='color: #9BA3AF;'>Select any row on the left to view plain-language analysis, potential threat impact, and one-click remediation.</p>")
        detail_layout.addWidget(self.detail_text)

        # Remediation Action Buttons
        self.btn_kill = QPushButton("Kill Owning Process")
        self.btn_kill.setProperty("danger", True)
        self.btn_kill.setEnabled(False)
        self.btn_kill.clicked.connect(self._kill_selected_process)
        detail_layout.addWidget(self.btn_kill)

        self.btn_firewall = QPushButton("Add Firewall Block Rule (netsh)")
        self.btn_firewall.setProperty("secondary", True)
        self.btn_firewall.setEnabled(False)
        self.btn_firewall.clicked.connect(self._block_selected_port)
        detail_layout.addWidget(self.btn_firewall)

        splitter.addWidget(detail_card)
        splitter.setSizes([650, 350])
        tl_layout.addWidget(splitter)
        self.tabs.addTab(tab_local, "Local Listening Ports && Connections")

        # Tab 2: Remote / Subnet Scanner
        tab_remote = QWidget()
        tr_layout = QVBoxLayout(tab_remote)
        tr_layout.setContentsMargins(15, 15, 15, 15)
        tr_layout.setSpacing(12)

        # Warning Header
        warn_box = QFrame()
        warn_box.setProperty("subcard", True)
        wb_layout = QHBoxLayout(warn_box)
        w_lbl = QLabel(
            "<b>Authorization Required:</b> Only scan IP addresses or subnets that you own or have explicit authorization to audit. "
            "A consent verification check is required before initiating network probes."
        )
        w_lbl.setStyleSheet("color: #EBCB8B; font-size: 12px;")
        w_lbl.setWordWrap(True)
        wb_layout.addWidget(w_lbl)
        tr_layout.addWidget(warn_box)

        input_row = QHBoxLayout()
        self.target_ip_input = QLineEdit("127.0.0.1")
        self.target_ip_input.setPlaceholderText("Enter Target IPv4 (e.g. 192.168.1.1)")
        input_row.addWidget(self.target_ip_input, 1)

        self.remote_scan_btn = QPushButton("Start Authorized Remote Probe")
        self.remote_scan_btn.setProperty("primary", True)
        self.remote_scan_btn.clicked.connect(self._start_remote_scan)
        input_row.addWidget(self.remote_scan_btn)
        tr_layout.addLayout(input_row)

        self.remote_table = QTableWidget(0, 5)
        self.remote_table.setHorizontalHeaderLabels(["Target IP", "Port", "Service", "Risk Severity", "Status"])
        self.remote_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.remote_table.setEditTriggers(QTableWidget.NoEditTriggers)
        tr_layout.addWidget(self.remote_table)

        self.tabs.addTab(tab_remote, "Authorized Network Range Probe")

        layout.addWidget(self.tabs)

        # Initial Load
        self.refresh_connections()

    def refresh_connections(self):
        self.active_connections_data = list_active_connections()
        self._populate_table(self.active_connections_data)
        ToastNotification(self.window(), "Network Scan Refreshed", f"Loaded {len(self.active_connections_data)} active sockets.", "info")

    def _populate_table(self, data: list):
        self.table.setRowCount(0)
        for conn in data:
            row = self.table.rowCount()
            self.table.insertRow(row)

            # Risk Badge
            is_risky = conn.get("is_risky", False)
            badge = ThreatBadge(conn.get("severity", "Low") if is_risky else "SAFE")
            self.table.setCellWidget(row, 0, badge)

            # Port
            port_item = QTableWidgetItem(str(conn.get("port")))
            port_item.setForeground(Qt.white)
            self.table.setItem(row, 1, port_item)

            self.table.setItem(row, 2, QTableWidgetItem(conn.get("protocol", "TCP")))
            self.table.setItem(row, 3, QTableWidgetItem(conn.get("service_name", "Unknown")))

            pname = conn.get("process_name", "System")
            pid = conn.get("pid", 0)
            self.table.setItem(row, 4, QTableWidgetItem(f"{pname} ({pid})"))

            self.table.setItem(row, 5, QTableWidgetItem(conn.get("status", "LISTEN")))

    def _filter_table(self, query: str):
        q = query.strip().lower()
        if not q:
            self._populate_table(self.active_connections_data)
            return
        filtered = [
            c for c in self.active_connections_data
            if q in str(c.get("port")) or q in c.get("process_name", "").lower() or q in str(c.get("pid"))
        ]
        self._populate_table(filtered)

    def _on_row_selected(self):
        selected_rows = self.table.selectedIndexes()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        port_item = self.table.item(row, 1)
        if not port_item:
            return

        port = int(port_item.text())
        matching = [c for c in self.active_connections_data if c.get("port") == port]
        if not matching:
            return
        conn = matching[0]

        is_risky = conn.get("is_risky", False)
        sev_color = "#BF616A" if conn.get("severity") in ("Critical", "High") else "#88C0D0"

        html = f"""
        <div style="font-family: Segoe UI, sans-serif; color: #ECEFF4;">
            <h3 style="color: {sev_color}; margin-top: 0;">Port {conn.get('port')} / {conn.get('protocol')}</h3>
            <p><b>Service:</b> {conn.get('service_name')}</p>
            <p><b>Owning Process:</b> {conn.get('process_name')} (PID: {conn.get('pid')})</p>
            <p><b>Executable Path:</b> <code>{conn.get('exe_path') or 'System Protected'}</code></p>
            <p><b>State:</b> {conn.get('status')}</p>
            <hr style="border: 1px solid #434C5E;">
            <h4 style="color: #FFD93D; margin-bottom: 5px;">Security Assessment</h4>
            <p style="color: #D8DEE9;">{conn.get('description')}</p>
        """
        if is_risky:
            html += f"""
            <h4 style="color: #A3BE8C; margin-bottom: 5px;">Recommended Action</h4>
            <p style="color: #D8DEE9;">{conn.get('recommendation')}</p>
            """
        html += "</div>"

        self.detail_text.setHtml(html)
        self.btn_kill.setEnabled(bool(conn.get("pid") and conn.get("pid") > 4))
        self.btn_firewall.setEnabled(True)
        self.selected_conn = conn

    def _kill_selected_process(self):
        if hasattr(self, "selected_conn"):
            pid = self.selected_conn.get("pid")
            ok, msg = kill_process(pid)
            if ok:
                ToastNotification(self.window(), "Process Terminated", msg, "success")
                self.refresh_connections()
            else:
                ToastNotification(self.window(), "Termination Failed", msg, "error")

    def _block_selected_port(self):
        if hasattr(self, "selected_conn"):
            port = self.selected_conn.get("port")
            proto = self.selected_conn.get("protocol", "TCP")
            rule_name = f"Fikrado_Block_Port_{port}_{proto}"
            ok, msg = add_firewall_block_rule(rule_name, port, proto)
            if ok:
                ToastNotification(self.window(), "Firewall Rule Added", msg, "success")
            else:
                ToastNotification(self.window(), "Firewall Action Failed", msg, "error")

    def _start_remote_scan(self):
        target = self.target_ip_input.text().strip()
        if not target:
            ToastNotification(self.window(), "Input Error", "Please provide a valid IP address.", "warning")
            return

        # Show authorization consent modal
        consent_dlg = NetworkConsentDialog(target, self)
        if consent_dlg.exec() != NetworkConsentDialog.Accepted:
            return

        self.remote_scan_btn.setEnabled(False)
        self.remote_table.setRowCount(0)
        ToastNotification(self.window(), "Probe Started", f"Scanning common ports on {target}...", "info")

        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080, 8443]
        self.remote_thread = RemoteScanThread(target, common_ports)
        self.remote_thread.finished_scan.connect(self._on_remote_scan_finished)
        self.remote_thread.start()

    def _on_remote_scan_finished(self, results: list):
        self.remote_scan_btn.setEnabled(True)
        for r in results:
            row = self.remote_table.rowCount()
            self.remote_table.insertRow(row)

            self.remote_table.setItem(row, 0, QTableWidgetItem(r.get("ip")))
            self.remote_table.setItem(row, 1, QTableWidgetItem(str(r.get("port"))))
            self.remote_table.setItem(row, 2, QTableWidgetItem(r.get("service")))

            badge = ThreatBadge(r.get("severity", "Low") if r.get("is_risky") else "SAFE")
            self.remote_table.setCellWidget(row, 3, badge)

            self.remote_table.setItem(row, 4, QTableWidgetItem("OPEN"))

        ToastNotification(self.window(), "Probe Completed", f"Found {len(results)} open ports on remote target.", "success")
