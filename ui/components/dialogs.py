"""
Fikrado Security - Modals and Consent Dialogs
Enforces explicit user consent for AI Cloud analysis and Network port scanning.
"""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QVBoxLayout
)


class AIConsentDialog(QDialog):
    """Explicit privacy consent modal required before sending snippets to external AI providers."""

    def __init__(self, provider_name: str, payload_preview: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AI Privacy & Cloud Transmission Consent")
        self.setFixedSize(540, 480)
        self.setStyleSheet("""
            QDialog {
                background-color: #2E3440;
                color: #ECEFF4;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # Header
        title = QLabel("Cloud Intelligence Privacy Consent")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #88C0D0;")
        layout.addWidget(title)

        desc = QLabel(
            f"You are requesting AI analysis via <b>{provider_name}</b>. "
            "To safeguard your data privacy, review the exact metadata and snippet "
            "that will be transmitted to the cloud provider:"
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #D8DEE9; font-size: 13px;")
        layout.addWidget(desc)

        # Preview Area
        preview_box = QPlainTextEdit()
        preview_box.setPlainText(payload_preview)
        preview_box.setReadOnly(True)
        preview_box.setStyleSheet("background-color: #242933; border: 1px solid #4C566A; font-family: Consolas; font-size: 11px;")
        layout.addWidget(preview_box)

        # Privacy mode options
        self.mode_group = QButtonGroup(self)
        self.rad_meta = QRadioButton("Send Safe Metadata Only (Recommended - zero file content)")
        self.rad_snippet = QRadioButton("Send Extracted Code Snippet (Initial lines only)")
        self.rad_meta.setChecked(True)
        self.mode_group.addButton(self.rad_meta, 1)
        self.mode_group.addButton(self.rad_snippet, 2)

        layout.addWidget(self.rad_meta)
        layout.addWidget(self.rad_snippet)

        self.chk_remember = QCheckBox("Remember this consent decision for future queries")
        layout.addWidget(self.chk_remember)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setProperty("secondary", True)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        self.accept_btn = QPushButton("Authorize & Transmit")
        self.accept_btn.setProperty("primary", True)
        self.accept_btn.clicked.connect(self.accept)
        btn_layout.addWidget(self.accept_btn)

        layout.addLayout(btn_layout)

    def get_selected_mode(self) -> str:
        return "metadata_only" if self.rad_meta.isChecked() else "snippets"

    def should_remember(self) -> bool:
        return self.chk_remember.isChecked()


class NetworkConsentDialog(QDialog):
    """Authorization consent before initiating IP range / remote subnet scanning."""

    def __init__(self, target: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Authorized Testing Consent")
        self.setFixedSize(480, 260)
        self.setStyleSheet("background-color: #2E3440; color: #ECEFF4;")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        title = QLabel("⚠️ Authorization & Compliance Notice")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #EBCB8B;")
        layout.addWidget(title)

        desc = QLabel(
            f"You are about to initiate an active network port probe on <b>{target}</b>.<br><br>"
            "Port scanning external or unauthorized systems without prior written authorization "
            "may violate applicable laws and computer security policies. You must only scan "
            "networks, servers, or devices that you own or are explicitly authorized to assess."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #D8DEE9; font-size: 13px;")
        layout.addWidget(desc)

        self.chk_agree = QCheckBox("I confirm I own or have permission to test this IP/network.")
        layout.addWidget(self.chk_agree)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        cancel_btn = QPushButton("Abort")
        cancel_btn.setProperty("secondary", True)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        self.start_btn = QPushButton("Proceed with Scan")
        self.start_btn.setProperty("primary", True)
        self.start_btn.setEnabled(False)
        self.chk_agree.stateChanged.connect(lambda s: self.start_btn.setEnabled(bool(s)))
        self.start_btn.clicked.connect(self.accept)
        btn_layout.addWidget(self.start_btn)

        layout.addLayout(btn_layout)
