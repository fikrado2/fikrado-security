"""
Fikrado Security - AI Security Intelligence & Threat Explanation Page
Provides AI-assisted file/script reverse engineering, threat explanations,
incident remediation plans, and startup/port analysis with privacy consent.
"""
from pathlib import Path
from typing import Optional
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget
)
from plugins.plugin_manager import plugin_manager
from ui.components.dialogs import AIConsentDialog
from ui.components.toast import ToastNotification
from ui.icons import refresh_icon_label, set_icon


class AIWorkerThread(QThread):
    finished = Signal(str)
    error = Signal(str)

    def __init__(self, task_type: str, provider_id: str, payload: dict):
        super().__init__()
        self.task_type = task_type
        self.provider_id = provider_id
        self.payload = payload

    def run(self):
        try:
            plugin = plugin_manager.get_plugin(self.provider_id)
            if not plugin:
                self.error.emit(f"AI Provider '{self.provider_id}' is not loaded.")
                return

            api_key, model, endpoint = plugin_manager.get_credentials(self.provider_id)

            if self.task_type == "explain_threat":
                result = plugin.explain_threat(self.payload["threat_info"], api_key, model, endpoint)
            elif self.task_type == "analyze_file":
                result = plugin.analyze_file(self.payload["metadata"], self.payload["snippet"], api_key, model, endpoint)
            elif self.task_type == "analyze_ports":
                result = plugin.analyze_ports_and_startup(self.payload["ports"], self.payload["startup"], api_key, model, endpoint)
            elif self.task_type == "analyze_logs":
                result = plugin.analyze_logs(self.payload["summary"], api_key, model, endpoint)
            else:
                result = "Unknown AI task type."

            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class AIScanPage(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_file_path: Optional[str] = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 25, 30, 25)
        layout.setSpacing(18)

        # Header
        header = QVBoxLayout()
        header.setSpacing(4)
        title = QLabel("AI Threat Intelligence & Neural Analysis")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #ECEFF4;")
        title.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        header.addWidget(title)

        desc = QLabel(
            "Leverage Google Gemini, OpenAI, Claude, OpenRouter, or local on-device Ollama "
            "to reverse-engineer suspicious scripts, explain complex malware TTPs, and generate remediation roadmaps."
        )
        desc.setStyleSheet("color: #9BA3AF; font-size: 13px;")
        desc.setWordWrap(True)
        desc.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        header.addWidget(desc)
        layout.addLayout(header, 0)

        # Top Bar: Provider Selection + Privacy Mode Pill
        top_bar = QFrame()
        top_bar.setProperty("card", True)
        top_bar.setFixedHeight(68)
        tb_layout = QHBoxLayout(top_bar)
        tb_layout.setContentsMargins(16, 12, 16, 12)
        tb_layout.setSpacing(15)

        prov_lbl = QLabel("Active AI Engine:")
        prov_lbl.setStyleSheet("font-weight: bold; color: #ECEFF4;")
        tb_layout.addWidget(prov_lbl)

        self.provider_combo = QComboBox()
        self.provider_combo.setMinimumWidth(260)
        self.provider_combo.setMaximumWidth(340)
        self._populate_providers()
        self.provider_combo.currentIndexChanged.connect(self._on_provider_changed)
        tb_layout.addWidget(self.provider_combo, 0)
        tb_layout.addStretch(1)

        self.privacy_pill = QFrame()
        self.privacy_pill.setObjectName("PrivacyPill")
        pill_layout = QHBoxLayout(self.privacy_pill)
        pill_layout.setContentsMargins(9, 0, 11, 0)
        pill_layout.setSpacing(6)
        self.privacy_icon = QLabel()
        self.privacy_icon.setFixedSize(14, 14)
        self.privacy_icon.setStyleSheet("background: transparent; border: none;")
        pill_layout.addWidget(self.privacy_icon)
        self.privacy_lbl = QLabel("Metadata Only")
        self.privacy_lbl.setStyleSheet("background: transparent; border: none;")
        pill_layout.addWidget(self.privacy_lbl)
        self.privacy_pill.setFixedHeight(24)
        self._set_privacy("Metadata Only", "shield", "#A3BE8C", 38)
        self.privacy_pill.setToolTip(
            "Privacy mode: only safe file metadata (names, hashes, sizes) is sent to the "
            "selected AI provider. Raw file contents stay on this device."
        )
        tb_layout.addWidget(self.privacy_pill, 0, Qt.AlignVCenter)

        layout.addWidget(top_bar, 0)

        # Splitter: Left Task Input Panels, Right AI Response Output
        splitter = QSplitter(Qt.Horizontal)

        # Left Task Area
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 10, 0)
        left_layout.setSpacing(14)

        # Card 1: File / Script Analyzer
        card_file = QFrame()
        card_file.setProperty("card", True)
        cf_layout = QVBoxLayout(card_file)
        cf_layout.setContentsMargins(16, 14, 16, 14)
        cf_layout.setSpacing(10)

        cf_title = QLabel("1. Analyze Suspicious File or Script")
        cf_title.setStyleSheet("font-weight: bold; color: #88C0D0; font-size: 14px;")
        cf_layout.addWidget(cf_title)

        pick_row = QHBoxLayout()
        self.file_lbl = QLabel("No file selected")
        self.file_lbl.setStyleSheet("color: #D8DEE9; font-family: Consolas; font-size: 11px;")
        pick_row.addWidget(self.file_lbl, 1)

        pick_btn = QPushButton("Select Target File")
        pick_btn.setProperty("secondary", True)
        set_icon(pick_btn, "folder", 15)
        pick_btn.clicked.connect(self._browse_file)
        pick_row.addWidget(pick_btn)
        cf_layout.addLayout(pick_row)

        cf_or = QLabel("Or paste suspicious code / PowerShell / batch snippet directly:")
        cf_or.setStyleSheet("color: #9BA3AF; font-size: 11px;")
        cf_layout.addWidget(cf_or)

        self.code_input = QPlainTextEdit()
        self.code_input.setPlaceholderText("Paste obfuscated script, base64 payload, or suspicious command here...")
        self.code_input.setFixedHeight(120)
        self.code_input.setStyleSheet("background-color: rgba(12, 16, 21, 175); border: 1px solid rgba(255, 255, 255, 20); border-radius: 9px; font-family: Consolas; font-size: 11px;")
        cf_layout.addWidget(self.code_input)

        self.btn_analyze_file = QPushButton("Run AI Deep Code Analysis")
        self.btn_analyze_file.setProperty("primary", True)
        set_icon(self.btn_analyze_file, "brain", 16, "#1A1F27")
        self.btn_analyze_file.clicked.connect(self._trigger_file_analysis)
        cf_layout.addWidget(self.btn_analyze_file)
        left_layout.addWidget(card_file)

        # Card 2: Quick System Security Audit & Remediations
        card_audit = QFrame()
        card_audit.setProperty("card", True)
        ca_layout = QVBoxLayout(card_audit)
        ca_layout.setContentsMargins(16, 14, 16, 14)
        ca_layout.setSpacing(10)

        ca_title = QLabel("2. Automated Threat & Port Telemetry Review")
        ca_title.setStyleSheet("font-weight: bold; color: #88C0D0; font-size: 14px;")
        ca_layout.addWidget(ca_title)

        ca_desc = QLabel("Feed live open ports, registry autoruns, and recent scan findings to the AI for holistic correlation.")
        ca_desc.setWordWrap(True)
        ca_desc.setStyleSheet("color: #D8DEE9; font-size: 12px;")
        ca_layout.addWidget(ca_desc)

        audit_btns = QHBoxLayout()
        btn_audit_ports = QPushButton("Audit Ports && Startup")
        btn_audit_ports.setProperty("secondary", True)
        set_icon(btn_audit_ports, "network", 15)
        btn_audit_ports.clicked.connect(self._trigger_ports_analysis)
        audit_btns.addWidget(btn_audit_ports)

        btn_audit_report = QPushButton("Generate Remediation Roadmap")
        btn_audit_report.setProperty("secondary", True)
        set_icon(btn_audit_report, "report", 15)
        btn_audit_report.clicked.connect(self._trigger_report_analysis)
        audit_btns.addWidget(btn_audit_report)

        ca_layout.addLayout(audit_btns)
        left_layout.addWidget(card_audit)
        left_layout.addStretch()

        splitter.addWidget(left_widget)

        # Right AI Response Output Card
        right_card = QFrame()
        right_card.setProperty("card", True)
        rc_layout = QVBoxLayout(right_card)
        rc_layout.setContentsMargins(18, 16, 18, 16)
        rc_layout.setSpacing(10)

        rc_header = QHBoxLayout()
        rc_title = QLabel("AI Intelligence Briefing & MITRE TTPs")
        rc_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #FFD93D;")
        rc_header.addWidget(rc_title)
        rc_header.addStretch()

        copy_btn = QPushButton("Copy Briefing")
        copy_btn.setProperty("secondary", True)
        set_icon(copy_btn, "report", 15)
        copy_btn.clicked.connect(self._copy_output)
        rc_header.addWidget(copy_btn)
        rc_layout.addLayout(rc_header)

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(12, 16, 21, 150);
                border: 1px solid rgba(255, 255, 255, 18);
                border-radius: 11px;
                color: #ECEFF4;
                font-family: "Segoe UI";
                font-size: 13px;
                padding: 12px;
            }
        """)
        self.output_text.setHtml(
            "<p style='color: #9BA3AF; padding: 20px;'>Awaiting input. Select a file or paste a script to initiate AI threat intelligence reasoning.</p>"
        )
        rc_layout.addWidget(self.output_text)
        splitter.addWidget(right_card)

        splitter.setSizes([450, 550])
        layout.addWidget(splitter, 1)

    def _populate_providers(self):
        self.provider_combo.clear()
        plugins = plugin_manager.get_all_plugins()
        active_id = plugin_manager.settings.get("ai", "active_provider", "gemini")
        selected_idx = 0
        for idx, p in enumerate(plugins):
            local_badge = " (Local)" if p.is_local else " (Cloud)"
            self.provider_combo.addItem(f"{p.plugin_name}{local_badge}", p.plugin_id)
            if p.plugin_id == active_id:
                selected_idx = idx
        self.provider_combo.setCurrentIndex(selected_idx)

    def _set_privacy(self, text: str, icon_name: str, color: str, alpha: int):
        refresh_icon_label(self.privacy_icon, icon_name, 14)
        self.privacy_lbl.setText(text)
        self.privacy_lbl.setStyleSheet(
            f"color: {color}; font-weight: bold; font-size: 11px; "
            "background: transparent; border: none;"
        )
        value = color.lstrip("#")
        r, g, b = int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)
        self.privacy_pill.setStyleSheet(f"""
            QFrame#PrivacyPill {{
                background-color: rgba({r}, {g}, {b}, {alpha});
                border: 1px solid rgba({r}, {g}, {b}, 120);
                border-radius: 11px;
            }}
        """)

    def _on_provider_changed(self):
        provider_id = self.provider_combo.currentData()
        if provider_id:
            plugin_manager.settings.set("ai", "active_provider", provider_id)
            plugin = plugin_manager.get_plugin(provider_id)
            if plugin and plugin.is_local:
                self._set_privacy("Local On-Device", "shield", "#A3BE8C", 38)
                self.privacy_pill.setToolTip(
                    "Local provider: all analysis runs on this machine. No data leaves your device."
                )
            else:
                self._set_privacy("Cloud Consent Active", "cloud", "#88C0D0", 38)
                self.privacy_pill.setToolTip(
                    "Cloud provider: only the metadata or snippet you explicitly approve is transmitted."
                )

    def _browse_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select Suspicious File for AI Analysis")
        if f:
            self.selected_file_path = f
            self.file_lbl.setText(f)

    def explain_external_threat(self, threat: dict):
        """Called from other pages (e.g. Scan Page) to explain a specific threat."""
        provider_id = self.provider_combo.currentData()
        self._check_consent_and_run(
            task_type="explain_threat",
            provider_id=provider_id,
            payload={"threat_info": threat},
            preview_content=str(threat)
        )

    def _trigger_file_analysis(self):
        raw_code = self.code_input.toPlainText().strip()
        provider_id = self.provider_combo.currentData()

        if self.selected_file_path:
            meta, snippet = plugin_manager.prepare_file_for_ai(self.selected_file_path, privacy_mode="snippets")
            preview = f"METADATA: {meta}\n\nSNIPPET:\n{snippet[:400]}"
            self._check_consent_and_run(
                task_type="analyze_file",
                provider_id=provider_id,
                payload={"metadata": meta, "snippet": snippet},
                preview_content=preview
            )
        elif raw_code:
            meta = {"source": "User pasted code", "length": len(raw_code)}
            self._check_consent_and_run(
                task_type="analyze_file",
                provider_id=provider_id,
                payload={"metadata": meta, "snippet": raw_code},
                preview_content=raw_code[:400]
            )
        else:
            ToastNotification(self.window(), "Input Required", "Please select a file or paste script text to analyze.", "warning")

    def _trigger_ports_analysis(self):
        from scanners.network_scanner import list_active_connections
        from tools.startup_manager import startup_manager

        ports = list_active_connections()[:10]
        startup = startup_manager.list_startup_items()[:10]
        preview = f"Ports: {len(ports)} items\nStartup: {len(startup)} items"
        provider_id = self.provider_combo.currentData()

        self._check_consent_and_run(
            task_type="analyze_ports",
            provider_id=provider_id,
            payload={"ports": ports, "startup": startup},
            preview_content=preview
        )

    def _trigger_report_analysis(self):
        from core.database import db
        stats = db.count_stats()
        recent_threats = db.get_recent_threats(limit=5)
        summary = {"stats": stats, "recent_threats": recent_threats}
        provider_id = self.provider_combo.currentData()

        self._check_consent_and_run(
            task_type="analyze_logs",
            provider_id=provider_id,
            payload={"summary": summary},
            preview_content=str(summary)
        )

    def _check_consent_and_run(self, task_type: str, provider_id: str, payload: dict, preview_content: str):
        plugin = plugin_manager.get_plugin(provider_id)
        if not plugin:
            ToastNotification(self.window(), "Error", f"Plugin {provider_id} not found.", "error")
            return

        # If cloud provider and consent not previously accepted, show dialog
        if not plugin.is_local and not plugin_manager.has_cloud_consent():
            dlg = AIConsentDialog(plugin.plugin_name, preview_content, self)
            if dlg.exec() != AIConsentDialog.Accepted:
                ToastNotification(self.window(), "Cancelled", "Cloud transmission cancelled by user.", "info")
                return
            if dlg.should_remember():
                plugin_manager.set_cloud_consent(True)

        self.output_text.setHtml(
            "<div style='padding: 20px; color: #88C0D0; font-size: 14px;'><b>AI Neural Reasoning in Progress...</b><br>Contacting provider and computing security risk evaluation...</div>"
        )

        self.worker = AIWorkerThread(task_type, provider_id, payload)
        self.worker.finished.connect(self._on_ai_success)
        self.worker.error.connect(self._on_ai_error)
        self.worker.start()

    def _on_ai_success(self, text: str):
        # Convert markdown newlines to HTML
        html_formatted = text.replace("\n\n", "<br><br>").replace("\n", "<br>")
        self.output_text.setHtml(f"<div style='padding: 15px; color: #ECEFF4; line-height: 1.5;'>{html_formatted}</div>")
        ToastNotification(self.window(), "AI Analysis Ready", "Intelligence briefing generated successfully.", "success")

    def _on_ai_error(self, err: str):
        self.output_text.setHtml(f"<div style='padding: 20px; color: #BF616A;'><b>AI Error:</b><br>{err}</div>")
        ToastNotification(self.window(), "AI Error", err[:100], "error")

    def _copy_output(self):
        plain = self.output_text.toPlainText()
        if plain:
            from PySide6.QtGui import QGuiApplication
            QGuiApplication.clipboard().setText(plain)
            ToastNotification(self.window(), "Copied", "AI briefing copied to clipboard.", "info")
