"""
Fikrado Security - Blue Team Terminal
Integrated command-line interface for security tools with pre-built command shortcuts.
Supports: nmap, netstat, ss, chkrootkit, rkhunter, curl, whois, nslookup, dig, and more.
"""
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

from PySide6.QtCore import QSize, Qt, QThread, Signal, QTimer
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QCompleter,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from core.logger import logger
from core.platforms import IS_WINDOWS, IS_LINUX, IS_MAC
from ui.components.cards import ThreatBadge
from ui.components.loading_overlay import LoadingOverlay
from ui.components.toast import ToastNotification
from ui.icons import icon_label, load_icon, set_icon
from ui.workers import FunctionWorker


# ─── BLUETEAMING COMMANDS LIBRARY ───────────────────────────────────────────
BLUETEAM_COMMANDS: List[Dict] = [
    # ── Network Recon ──────────────────────────────────────────────────────
    {
        "category": "Network Recon",
        "name": "Port Scan (nmap - top 100)",
        "cmd": "nmap -sV -O --top-ports 100 {host}",
        "desc": "Scan top 100 ports with version detection and OS fingerprinting",
        "platforms": ["linux", "mac", "windows"],
        "tags": ["network", "ports", "nmap"],
        "example": "nmap -sV -O --top-ports 100 192.168.1.1",
    },
    {
        "category": "Network Recon",
        "name": "Quick SYN Scan",
        "cmd": "nmap -sS -T4 {host}",
        "desc": "Fast half-open SYN scan — stealthier than full connect scan",
        "platforms": ["linux", "mac", "windows"],
        "tags": ["network", "stealth", "nmap"],
        "example": "nmap -sS -T4 10.0.0.1",
    },
    {
        "category": "Network Recon",
        "name": "Full Port Scan",
        "cmd": "nmap -p- -sV -sC -T4 -oA full_scan_{host} {host}",
        "desc": "All 65535 ports with scripts, version detection, save all formats",
        "platforms": ["linux", "mac", "windows"],
        "tags": ["network", "full", "nmap"],
        "example": "nmap -p- -sV -sC -T4 -oA full_scan_10.0.0.1 10.0.0.1",
    },
    {
        "category": "Network Recon",
        "name": "UDP Port Scan",
        "cmd": "nmap -sU -T4 --top-ports 50 {host}",
        "desc": "Scan top UDP ports (slow — consider firewall limits)",
        "platforms": ["linux", "mac", "windows"],
        "tags": ["network", "udp", "nmap"],
        "example": "nmap -sU -T4 --top-ports 50 10.0.0.1",
    },
    {
        "category": "Network Recon",
        "name": "Subnet Discovery",
        "cmd": "nmap -sn {subnet}",
        "desc": "Ping sweep — discover live hosts without port scan",
        "platforms": ["linux", "mac", "windows"],
        "tags": ["network", "discovery", "nmap"],
        "example": "nmap -sn 192.168.1.0/24",
    },
    {
        "category": "Network Recon",
        "name": "SSL/TLS Audit",
        "cmd": "nmap -p 443 --script ssl-enum-ciphers,ssl-cert,ssl-date {host}",
        "desc": "Enumerate SSL/TLS cipher suites and certificate details",
        "platforms": ["linux", "mac", "windows"],
        "tags": ["ssl", "tls", "nmap"],
        "example": "nmap -p 443 --script ssl-enum-ciphers,ssl-cert example.com",
    },
    {
        "category": "Network Recon",
        "name": "Vulnerability Scan (nmap scripts)",
        "cmd": "nmap -sV --script vuln {host}",
        "desc": "Run nmap vuln scripts (CVE detection for common services)",
        "platforms": ["linux", "mac", "windows"],
        "tags": ["network", "vuln", "nmap"],
        "example": "nmap -sV --script vuln 10.0.0.1",
    },

    # ── Network Status ──────────────────────────────────────────────────────
    {
        "category": "Network Status",
        "name": "Active Connections (netstat)",
        "cmd": "netstat -tulanp 2>/dev/null || netstat -ano",
        "desc": "All TCP/UDP connections with process IDs (requires sudo on Linux)",
        "platforms": ["linux", "mac", "windows"],
        "tags": ["network", "connections", "netstat"],
    },
    {
        "category": "Network Status",
        "name": "Listening Ports (ss)",
        "cmd": "ss -tulnp",
        "desc": "Modern replacement for netstat — shows listening sockets with process",
        "platforms": ["linux"],
        "tags": ["network", "ss", "sockets"],
    },
    {
        "category": "Network Status",
        "name": "Network Interface Stats",
        "cmd": "ip -s link show && ip addr",
        "desc": "Show all interfaces, statistics, and IP addresses",
        "platforms": ["linux"],
        "tags": ["network", "interface", "ip"],
    },
    {
        "category": "Network Status",
        "name": "ARP Table",
        "cmd": "arp -a",
        "desc": "Display ARP cache — reveals devices on local network",
        "platforms": ["linux", "mac", "windows"],
        "tags": ["network", "arp", "discovery"],
    },
    {
        "category": "Network Status",
        "name": "Routing Table",
        "cmd": "route -n && ip route",
        "desc": "Show kernel routing table — check for unexpected gateways",
        "platforms": ["linux", "mac", "windows"],
        "tags": ["network", "routing", "gateway"],
    },
    {
        "category": "Network Status",
        "name": "DNS Lookup",
        "cmd": "nslookup {host} && dig {host} ANY +short",
        "desc": "DNS resolution via nslookup and dig with ALL record types",
        "platforms": ["linux", "mac", "windows"],
        "tags": ["dns", "lookup", "nslookup"],
        "example": "nslookup example.com && dig example.com ANY +short",
    },
    {
        "category": "Network Status",
        "name": "WHOIS Lookup",
        "cmd": "whois {host}",
        "desc": "Domain/IP registration data, registrar, and expiry date",
        "platforms": ["linux", "mac", "windows"],
        "tags": ["dns", "whois", "domain"],
        "example": "whois example.com",
    },
    {
        "category": "Network Status",
        "name": "Traceroute",
        "cmd": "traceroute -I {host}",
        "desc": "Trace packet path to destination with ICMP probes",
        "platforms": ["linux", "mac"],
        "tags": ["network", "traceroute", "path"],
        "example": "traceroute -I example.com",
    },
    {
        "category": "Network Status",
        "name": "Traceroute (Windows)",
        "cmd": "tracert {host}",
        "desc": "Windows traceroute using ICMP",
        "platforms": ["windows"],
        "tags": ["network", "traceroute", "windows"],
        "example": "tracert example.com",
    },

    # ── Host Recon ──────────────────────────────────────────────────────────
    {
        "category": "Host Recon",
        "name": "System Info",
        "cmd": "uname -a && hostname && cat /etc/os-release",
        "desc": "OS name, kernel version, hostname, and distribution info",
        "platforms": ["linux", "mac"],
        "tags": ["system", "info", "os"],
    },
    {
        "category": "Host Recon",
        "name": "System Info (Windows)",
        "cmd": "systeminfo",
        "desc": "Full Windows system information",
        "platforms": ["windows"],
        "tags": ["system", "info", "windows"],
    },
    {
        "category": "Host Recon",
        "name": "Logged-In Users",
        "cmd": "who && w && last -20",
        "desc": "Currently logged-in users and recent session history",
        "platforms": ["linux", "mac"],
        "tags": ["users", "session", "recon"],
    },
    {
        "category": "Host Recon",
        "name": "Logged-In Users (Windows)",
        "cmd": "query user",
        "desc": "Logged-in users on Windows server/workstation",
        "platforms": ["windows"],
        "tags": ["users", "session", "windows"],
    },
    {
        "category": "Host Recon",
        "name": "Scheduled Tasks",
        "cmd": "crontab -l && cat /etc/crontab && ls -la /etc/cron.d/",
        "desc": "List all scheduled cron jobs — common persistence mechanism",
        "platforms": ["linux"],
        "tags": ["persistence", "cron", "scheduled"],
    },
    {
        "category": "Host Recon",
        "name": "Scheduled Tasks (Windows)",
        "cmd": "schtasks /query /fo LIST /v",
        "desc": "List all Windows scheduled tasks with full details",
        "platforms": ["windows"],
        "tags": ["persistence", "scheduled", "windows"],
    },
    {
        "category": "Host Recon",
        "name": "Open Sessions & Shares",
        "cmd": "net sessions 2>/dev/null && net share",
        "desc": "SMB sessions and file shares — look for lateral movement",
        "platforms": ["windows"],
        "tags": ["smb", "shares", "lateral"],
    },

    # ── Rootkit Detection ────────────────────────────────────────────────────
    {
        "category": "Rootkit Detection",
        "name": "Run chkrootkit",
        "cmd": "sudo chkrootkit -q 2>&1",
        "desc": "Run chkrootkit if installed — checks for common rootkit signatures",
        "platforms": ["linux"],
        "tags": ["rootkit", "linux", "chkrootkit"],
    },
    {
        "category": "Rootkit Detection",
        "name": "Run rkhunter",
        "cmd": "sudo rkhunter --check --skip-keypress --quiet 2>&1",
        "desc": "Run rkhunter if installed — comprehensive rootkit hunter",
        "platforms": ["linux"],
        "tags": ["rootkit", "linux", "rkhunter"],
    },
    {
        "category": "Rootkit Detection",
        "name": "Check Hidden Processes",
        "cmd": "cat /proc/*/stat 2>/dev/null | awk '{print $1,$2}' | diff - <(ps aux | awk 'NR>1 {print $2}')",
        "desc": "Find processes in /proc not visible to ps — rootkit indicator",
        "platforms": ["linux"],
        "tags": ["rootkit", "hidden", "process"],
    },
    {
        "category": "Rootkit Detection",
        "name": "Check LKM Rootkits",
        "cmd": "lsmod | grep -v '^Module' && cat /proc/modules",
        "desc": "List loaded kernel modules — check for unknown LKMs",
        "platforms": ["linux"],
        "tags": ["rootkit", "lkm", "kernel"],
    },
    {
        "category": "Rootkit Detection",
        "name": "Check Sudoers",
        "cmd": "cat /etc/sudoers && ls -la /etc/sudoers.d/",
        "desc": "Review sudo permissions — privilege escalation risk",
        "platforms": ["linux"],
        "tags": ["privilege", "sudo", "escalation"],
    },
    {
        "category": "Rootkit Detection",
        "name": "Check LD_PRELOAD",
        "cmd": "grep -r 'LD_PRELOAD' /etc/ld.so.preload 2>/dev/null",
        "desc": "LD_PRELOAD in /etc/ld.so.preload is a known rootkit indicator",
        "platforms": ["linux"],
        "tags": ["rootkit", "ld_preload", "linux"],
    },

    # ── File System ─────────────────────────────────────────────────────────
    {
        "category": "File System",
        "name": "Find SUID Binaries",
        "cmd": "find / -perm -4000 -type f -ls 2>/dev/null",
        "desc": "Find SUID binaries — common privilege escalation vector",
        "platforms": ["linux", "mac"],
        "tags": ["suid", "privesc", "filesystem"],
    },
    {
        "category": "File System",
        "name": "Find SUID (Windows)",
        "cmd": "Get-ChildItem C:\\ -Recurse -Filter '*.exe' -EA SilentlyContinue | Where-Object {$_.Attributes -match 'System'} | Select-Object FullName,Length -First 20",
        "desc": "Find executable files with System attribute — potential malware",
        "platforms": ["windows"],
        "tags": ["suid", "privesc", "windows"],
    },
    {
        "category": "File System",
        "name": "Recent Files (last 1h)",
        "cmd": "find / -mmin -60 -type f 2>/dev/null | head -100",
        "desc": "Files modified in last hour — identify recent intrusions",
        "platforms": ["linux", "mac"],
        "tags": ["filesystem", "forensics", "recent"],
    },
    {
        "category": "File System",
        "name": "World-Writable Files",
        "cmd": "find / -xdev -type f \\( -perm -002 \\) -ls 2>/dev/null | head -50",
        "desc": "Find world-writable files — potential web shell or data exfil risk",
        "platforms": ["linux"],
        "tags": ["filesystem", "permissions", "writable"],
    },

    # ── Threat Intel ─────────────────────────────────────────────────────────
    {
        "category": "Threat Intel",
        "name": "VirusTotal Lookup (hash)",
        "cmd": "curl -s 'https://www.virustotal.com/api/v3/files/{hash}' -H 'x-apikey: YOUR_VT_KEY'",
        "desc": "Look up file hash on VirusTotal — replace {hash} with actual SHA256",
        "platforms": ["linux", "mac", "windows"],
        "tags": ["threat_intel", "virustotal", "hash"],
        "example": "curl -s 'https://www.virustotal.com/api/v3/files/HASH' -H 'x-apikey: KEY'",
    },
    {
        "category": "Threat Intel",
        "name": "AbuseIPDB Check",
        "cmd": "curl -s 'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90' -H 'Key: YOUR_API_KEY'",
        "desc": "Check IP reputation on AbuseIPDB — replace {ip} and API key",
        "platforms": ["linux", "mac", "windows"],
        "tags": ["threat_intel", "ip", "abuseipdb"],
        "example": "curl -s 'https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4' -H 'Key: KEY'",
    },
    {
        "category": "Threat Intel",
        "name": "Shodan Host Lookup",
        "cmd": "curl -s 'https://api.shodan.io/shodan/host/{ip}?key=YOUR_SHODAN_KEY'",
        "desc": "Check what services are exposed on an IP via Shodan",
        "platforms": ["linux", "mac", "windows"],
        "tags": ["threat_intel", "shodan", "recon"],
        "example": "curl -s 'https://api.shodan.io/shodan/host/1.2.3.4?key=KEY'",
    },
    {
        "category": "Threat Intel",
        "name": "CISA KEV CVE Lookup",
        "cmd": "curl -s 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' | jq '.vulnerabilities[] | select(.cveID == '{cve}')'",
        "desc": "Check if a CVE is in CISA's Known Exploited Vulnerabilities catalog",
        "platforms": ["linux", "mac", "windows"],
        "tags": ["threat_intel", "cisa", "cve"],
        "example": "curl -s CISA_URL | jq '.vulnerabilities[] | select(.cveID == \"CVE-2021-44228\")'",
    },

    # ── Packet Capture ───────────────────────────────────────────────────────
    {
        "category": "Packet Capture",
        "name": "TCPDump (live capture)",
        "cmd": "sudo tcpdump -i any -c 100 -nn -v",
        "desc": "Capture 100 packets on all interfaces (requires root)",
        "platforms": ["linux", "mac"],
        "tags": ["packet", "tcpdump", "sniffing"],
    },
    {
        "category": "Packet Capture",
        "name": "TCPDump Host Filter",
        "cmd": "sudo tcpdump -i any -c 50 host {ip} -nn",
        "desc": "Capture packets involving specific host IP",
        "platforms": ["linux", "mac"],
        "tags": ["packet", "tcpdump", "filter"],
        "example": "sudo tcpdump -i any -c 50 host 192.168.1.1 -nn",
    },
    {
        "category": "Packet Capture",
        "name": "Packet Capture (Windows)",
        "cmd": "netsh trace start capture=yes tracefile=c:\\capture.etl maxsize=1000",
        "desc": "Start Windows packet capture (netsh) — stops with 'netsh trace stop'",
        "platforms": ["windows"],
        "tags": ["packet", "windows", "capture"],
    },
]


# ─── TERMINAL WORKER THREAD ──────────────────────────────────────────────────
class TerminalWorker(QThread):
    output_ready = Signal(str)
    command_done = Signal(int, str)  # returncode, output

    def __init__(self, cmd: str, cwd: str = "", env: Optional[dict] = None):
        super().__init__()
        self.cmd = cmd
        self.cwd = cwd or os.getcwd()
        self.custom_env = env or {}
        self._stop_requested = False

    def stop(self):
        self._stop_requested = True
        self.terminate()

    def run(self):
        full_env = {**os.environ, **self.custom_env}
        try:
            proc = subprocess.Popen(
                self.cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=self.cwd,
                env=full_env,
                text=True,
            )
            # Stream output line by line
            for line in iter(proc.stdout.readline, ""):
                if self._stop_requested:
                    proc.terminate()
                    break
                if line:
                    self.output_ready.emit(line.rstrip("\n"))
            proc.wait()
            output = proc.stdout.read() if proc.stdout else ""
            self.command_done.emit(proc.returncode, output)
        except Exception as e:
            self.command_done.emit(1, f"Error: {str(e)}")


# ─── MAIN TERMINAL PAGE ─────────────────────────────────────────────────────
class TerminalPage(QWidget):
    """Blue Team Terminal with command library and interactive shell."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._workers: list = []
        self._current_worker: Optional[TerminalWorker] = None
        self._command_history: list = []
        self._history_index: int = -1
        self._current_platform = self._detect_platform()
        self._init_ui()
        self._print_banner()

    def _detect_platform(self) -> str:
        if IS_WINDOWS:
            return "windows"
        elif IS_MAC:
            return "mac"
        return "linux"

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # ── Header ──────────────────────────────────────────────────────────
        header = QVBoxLayout()
        title = QLabel("Blue Team Terminal")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #ECEFF4;")
        header.addWidget(title)
        desc = QLabel(
            "Integrated security command-line with pre-built Blueteam toolkits. "
            "Run reconnaissance, rootkit detection, network analysis, and threat intel queries."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #9BA3AF; font-size: 13px;")
        header.addWidget(desc)
        layout.addLayout(header)

        # ── Main Split: Command Library + Terminal ─────────────────────────
        splitter = QSplitter(Qt.Horizontal)
        splitter.setSizes([280, 900])

        # Left: Command library
        splitter.addWidget(self._build_command_library())
        # Right: Terminal area
        splitter.addWidget(self._build_terminal_area())

        layout.addWidget(splitter, 1)

    def _build_command_library(self) -> QWidget:
        """Left panel: searchable command quick-access library."""
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        lbl = QLabel("Command Library")
        lbl.setStyleSheet("font-size: 14px; font-weight: bold; color: #88C0D0;")
        layout.addWidget(lbl)

        # Search
        self.cmd_search = QLineEdit()
        self.cmd_search.setPlaceholderText("Search commands…")
        self.cmd_search.textChanged.connect(self._filter_commands)
        layout.addWidget(self.cmd_search)

        # Category filter
        categories = sorted(set(c["category"] for c in BLUETEAM_COMMANDS))
        self.cat_filter = QComboBox()
        self.cat_filter.addItem("All Categories")
        self.cat_filter.addItems(categories)
        self.cat_filter.currentTextChanged.connect(self._filter_commands)
        layout.addWidget(self.cat_filter)

        # Command list
        self.cmd_list = QListWidget()
        self.cmd_list.setFocusPolicy(Qt.NoFocus)
        self.cmd_list.itemDoubleClicked.connect(self._execute_selected_command)
        layout.addWidget(self.cmd_list, 1)

        # Run button
        run_btn = QPushButton("Run Selected Command")
        run_btn.setProperty("primary", True)
        set_icon(run_btn, "terminal", 15, "#1A1F27")
        run_btn.clicked.connect(self._execute_selected_command)
        layout.addWidget(run_btn)

        self._populate_commands(BLUETEAM_COMMANDS)
        return frame

    def _build_terminal_area(self) -> QWidget:
        """Right panel: interactive terminal output + input."""
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        # Toolbar
        toolbar = QHBoxLayout()
        toolbar_lbl = QLabel("Terminal")
        toolbar_lbl.setStyleSheet("font-size: 14px; font-weight: bold; color: #88C0D0;")
        toolbar.addWidget(toolbar_lbl)
        toolbar.addStretch()

        self.platform_lbl = QLabel(f"Platform: {self._current_platform.upper()}")
        self.platform_lbl.setStyleSheet("color: #9BA3AF; font-size: 11px; background: rgba(59,66,82,150); padding: 2px 8px; border-radius: 4px;")
        toolbar.addWidget(self.platform_lbl)

        clear_btn = QPushButton("Clear")
        clear_btn.setProperty("secondary", True)
        clear_btn.setFixedWidth(60)
        clear_btn.clicked.connect(self._clear_terminal)
        toolbar.addWidget(clear_btn)

        stop_btn = QPushButton("Stop")
        stop_btn.setProperty("danger", True)
        stop_btn.setFixedWidth(60)
        stop_btn.clicked.connect(self._stop_current_command)
        toolbar.addWidget(stop_btn)

        layout.addLayout(toolbar)

        # Terminal output (read-only scrollable text area)
        self.term_output = QTextEdit()
        self.term_output.setReadOnly(True)
        self.term_output.setFont(QFont("JetBrains Mono, Consolas, Courier New, monospace", 11))
        self.term_output.setStyleSheet("""
            QTextEdit {
                background: #0D1117;
                color: #79C0FF;
                border: 1px solid #30363D;
                border-radius: 8px;
                padding: 12px;
            }
        """)
        layout.addWidget(self.term_output, 1)

        # Input row
        input_row = QHBoxLayout()
        input_row.setSpacing(6)

        self.prompt_lbl = QLabel(f"fikrado@{(os.environ.get('USER') or 'security')}$")
        self.prompt_lbl.setFont(QFont("JetBrains Mono, Consolas, monospace", 11))
        self.prompt_lbl.setStyleSheet("color: #A3BE8C; background: transparent;")
        input_row.addWidget(self.prompt_lbl)

        self.term_input = QLineEdit()
        self.term_input.setFont(QFont("JetBrains Mono, Consolas, monospace", 11))
        self.term_input.setStyleSheet("""
            QLineEdit {
                background: #0D1117;
                color: #ECEFF4;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 6px 10px;
            }
            QLineEdit:focus { border-color: #58A6FF; }
        """)
        self.term_input.setPlaceholderText("Type a command and press Enter…")
        self.term_input.returnPressed.connect(self._on_input_enter)
        input_row.addWidget(self.term_input, 1)

        exec_btn = QPushButton("Run")
        exec_btn.setProperty("primary", True)
        exec_btn.setFixedWidth(60)
        exec_btn.clicked.connect(self._on_input_enter)
        input_row.addWidget(exec_btn)

        layout.addLayout(input_row)
        return frame

    # ── Command Library ───────────────────────────────────────────────────────
    def _populate_commands(self, commands: List[Dict]):
        self.cmd_list.clear()
        for cmd in commands:
            if self._current_platform not in cmd.get("platforms", ["linux", "mac", "windows"]):
                continue
            item = QListWidgetItem(f"▶  {cmd['name']}")
            item.setToolTip(f"{cmd['desc']}\n\nCommand:\n  {cmd['cmd']}")
            item.setData(Qt.UserRole, cmd)
            self.cmd_list.addItem(item)

    def _filter_commands(self, _text: str = ""):
        search = self.cmd_search.text().lower()
        cat = self.cat_filter.currentText()
        self.cmd_list.clear()
        for cmd in BLUETEAM_COMMANDS:
            if self._current_platform not in cmd.get("platforms", ["linux", "mac", "windows"]):
                continue
            if cat != "All Categories" and cmd["category"] != cat:
                continue
            if search:
                tags = " ".join(cmd.get("tags", []))
                if search not in f"{cmd['name']} {cmd['desc']} {tags}".lower():
                    continue
            item = QListWidgetItem(f"▶  {cmd['name']}")
            item.setToolTip(f"{cmd['desc']}\n\nCommand:\n  {cmd['cmd']}")
            item.setData(Qt.UserRole, cmd)
            self.cmd_list.addItem(item)

    def _execute_selected_command(self):
        item = self.cmd_list.currentItem()
        if item is None:
            return
        cmd_data = item.data(Qt.UserRole)
        raw_cmd = cmd_data["cmd"]

        # Prompt for user input if {host}, {ip} etc. are in command
        cmd = raw_cmd
        if "{host}" in raw_cmd or "{ip}" in raw_cmd or "{subnet}" in raw_cmd or "{hash}" in raw_cmd:
            input_map = {
                "{host}": "Enter host/IP: ",
                "{ip}": "Enter IP: ",
                "{subnet}": "Enter subnet (e.g. 192.168.1.0/24): ",
                "{hash}": "Enter SHA256 hash: ",
            }
            for placeholder, prompt in input_map.items():
                if placeholder in raw_cmd:
                    # For now, just show the command template
                    self._append_output(
                        f"\n[BLUETEAM] {cmd_data['name']}\n"
                        f"[INFO] Fill in the placeholder and run manually in terminal\n"
                        f"[CMD] {raw_cmd}\n",
                        color="#EBCB8B"
                    )
                    return

        # Run the command directly
        self._run_command(raw_cmd, label=f"BLUETEAM: {cmd_data['name']}")

    # ── Terminal I/O ───────────────────────────────────────────────────────────
    def _print_banner(self):
        banner = f"""
╔══════════════════════════════════════════════════════╗
║         FIKRADO SECURITY — BLUE TEAM TERMINAL         ║
║  Cross-Platform Security Operations Console            ║
║  Platform: {self._current_platform.upper():<38}║
╚══════════════════════════════════════════════════════╝
Type a command or double-click a library entry to run.
Use ↑/↓ to navigate command history.
"""
        self._append_output(banner, color="#88C0D0")

    def _append_output(self, text: str, color: str = "#79C0FF"):
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        fmt.setFontFamily("JetBrains Mono, Consolas, Courier New, monospace")
        self.term_output.moveCursor(QTextCursor.End)
        self.term_output.setCurrentCharFormat(fmt)
        self.term_output.insertPlainText(text + "\n")
        self.term_output.moveCursor(QTextCursor.End)

    def _append_error(self, text: str):
        self._append_output(f"[ERROR] {text}", color="#BF616A")

    def _append_success(self, text: str):
        self._append_output(f"[OK] {text}", color="#A3BE8C")

    def _clear_terminal(self):
        self.term_output.clear()
        self._print_banner()

    def _on_input_enter(self):
        text = self.term_input.text().strip()
        if not text:
            return
        self._history_index = -1
        self._command_history.insert(0, text)
        if len(self._command_history) > 200:
            self._command_history = self._command_history[:200]
        self.term_input.clear()
        self._run_command(text)

    def _run_command(self, cmd: str, label: str = ""):
        if self._current_worker and self._current_worker.isRunning():
            self._append_output("[!] A command is already running. Stop it first.", color="#EBCB8B")
            return

        self._append_output(f"\n{'='*60}", color="#30363D")
        if label:
            self._append_output(f">>> {label}", color="#EBCB8B")
        self._append_output(f"$ {cmd}", color="#A3BE8C")

        self._current_worker = TerminalWorker(cmd)
        self._workers.append(self._current_worker)

        def on_output(line: str):
            # Use signal/slot safely from worker thread
            QTimer.singleShot(0, lambda: self._append_output(line))

        def on_done(rc: int, output: str):
            self._current_worker = None
            color = "#A3BE8C" if rc == 0 else "#BF616A"
            self._append_output(f"\n--- Command finished (exit {rc}) ---\n", color="#30363D")
            self.term_input.setEnabled(True)

        self._current_worker.output_ready.connect(on_output)
        self._current_worker.command_done.connect(on_done)
        self.term_input.setEnabled(False)
        self._current_worker.start()

    def _stop_current_command(self):
        if self._current_worker and self._current_worker.isRunning():
            self._current_worker.stop()
            self._append_output("\n[!] Command stopped by user.", color="#EBCB8B")
            self._current_worker = None
            self.term_input.setEnabled(True)

    def cleanup(self):
        for w in self._workers:
            if w.isRunning():
                w.stop()
        self._workers.clear()