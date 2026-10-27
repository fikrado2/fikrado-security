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


class StatCard(QFrame):
    """Card widget displaying a KPI metric (title, value, subtext, icon)."""

    def __init__(self, title: str, value: str, subtext: str = "", accent_color: str = "#88C0D0", icon_symbol: str = "", parent=None):
        super().__init__(parent)
        self.setProperty("card", True)
        self.setStyleSheet(f"""
            QFrame[card="true"] {{
                background-color: #3B4252;
                border: 1px solid #434C5E;
                border-radius: 10px;
                padding: 12px;
            }}
            QFrame[card="true"]:hover {{
                border-color: {accent_color};
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)

        v_layout = QVBoxLayout()
        v_layout.setSpacing(4)

        # Title
        title_lbl = QLabel(title.upper())
        title_lbl.setStyleSheet("color: #9BA3AF; font-size: 11px; font-weight: bold; letter-spacing: 0.8px;")
        v_layout.addWidget(title_lbl)

        # Value
        self.value_lbl = QLabel(value)
        self.value_lbl.setStyleSheet(f"color: {accent_color}; font-size: 26px; font-weight: 800;")
        v_layout.addWidget(self.value_lbl)

        # Subtext
        if subtext:
            sub_lbl = QLabel(subtext)
            sub_lbl.setStyleSheet("color: #D8DEE9; font-size: 12px;")
            v_layout.addWidget(sub_lbl)

        layout.addLayout(v_layout)

        if icon_symbol:
            icon_lbl = QLabel(icon_symbol)
            icon_lbl.setStyleSheet(f"color: {accent_color}; font-size: 32px;")
            icon_lbl.setAlignment(Qt.AlignCenter)
            layout.addWidget(icon_lbl)

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
