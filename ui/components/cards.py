"""
Fikrado Security - Reusable UI Card Components
Provides Nord-themed stat cards, metric containers, and action panels.
"""
from typing import Optional
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget
)
from ui.effects import apply_text_glow


class StatCard(QFrame):
    """Card widget displaying a KPI metric (title, value, subtext, icon)."""

    def __init__(self, title: str, value: str, subtext: str = "", accent_color: str = "#88C0D0", icon_symbol: str = "", parent=None):
        super().__init__(parent)
        self.setProperty("card", True)
        self.setStyleSheet(f"""
            QFrame[card="true"] {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                            stop:0 #3C4352, stop:1 #373E4C);
                border: 1px solid rgba(76, 86, 106, 166);
                border-radius: 12px;
                padding: 12px;
            }}
            QFrame[card="true"]:hover {{
                border: 1px solid {accent_color};
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)

        v_layout = QVBoxLayout()
        v_layout.setSpacing(4)

        # Title
        title_lbl = QLabel(title.upper())
        title_lbl.setStyleSheet(
            "color: #9BA3AF; font-size: 10px; font-weight: 700; "
            "letter-spacing: 0.6px; background: transparent;"
        )
        v_layout.addWidget(title_lbl)

        # Value
        self.value_lbl = QLabel(value)
        self.value_lbl.setStyleSheet(
            f"color: {accent_color}; font-size: 26px; font-weight: 800; background: transparent;"
        )
        apply_text_glow(self.value_lbl, accent_color, blur=16, opacity=145)
        v_layout.addWidget(self.value_lbl)

        # Subtext
        if subtext:
            sub_lbl = QLabel(subtext)
            sub_lbl.setStyleSheet(
                "color: #D8DEE9; font-size: 11px; background: transparent;"
            )
            sub_lbl.setWordWrap(True)
            v_layout.addWidget(sub_lbl)

        v_layout.addStretch()
        layout.addLayout(v_layout, 1)

        if icon_symbol:
            icon_lbl = QLabel(icon_symbol)
            icon_lbl.setStyleSheet(f"color: {accent_color}; font-size: 28px; background: transparent;")
            icon_lbl.setAlignment(Qt.AlignCenter)
            apply_text_glow(icon_lbl, accent_color, blur=14, opacity=85)
            layout.addWidget(icon_lbl, 0, Qt.AlignVCenter)

    def set_value(self, val: str):
        self.value_lbl.setText(str(val))


class ThreatBadge(QLabel):
    """Color-coded severity badge for tables and logs."""

    def __init__(self, severity: str, parent=None):
        super().__init__(severity.upper(), parent)
        sev_styles = {
            "CRITICAL": ("#BF616A", "#242933"),
            "HIGH": ("#D08770", "#242933"),
            "MEDIUM": ("#EBCB8B", "#242933"),
            "LOW": ("#88C0D0", "#242933"),
            "PASS": ("#A3BE8C", "#242933"),
            "SAFE": ("#A3BE8C", "#242933"),
        }
        bg, fg = sev_styles.get(severity.upper(), ("#4C566A", "#ECEFF4"))
        self.setStyleSheet(f"""
            background-color: {bg};
            color: {fg};
            font-size: 10px;
            font-weight: 800;
            padding: 3px 8px;
            border-radius: 4px;
            letter-spacing: 0.5px;
        """)
        self.setAlignment(Qt.AlignCenter)
        self.setFixedSize(74, 22)
