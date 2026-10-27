"""
Fikrado Security - Reusable UI Card Components
Glass KPI cards with colored vector icon chips, severity pills, and action panels.
"""
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from ui.effects import apply_text_glow, update_glow
from ui.icons import icon_label


def _rgba(hex_color: str, alpha: int) -> str:
    """Convert ``#RRGGBB`` to a Qt ``rgba(r, g, b, a)`` string."""
    value = hex_color.lstrip("#")
    if len(value) != 6:
        return f"rgba(136, 192, 208, {alpha})"
    r, g, b = int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)
    return f"rgba({r}, {g}, {b}, {alpha})"


class StatCard(QFrame):
    """Glass KPI card: label, large value, supporting text and a vector icon chip."""

    def __init__(
        self,
        title: str,
        value: str,
        subtext: str = "",
        accent_color: str = "#88C0D0",
        icon_name: str = "",
        parent=None,
    ):
        super().__init__(parent)
        self.setProperty("card", True)
        self.setMinimumHeight(108)
        self._accent_color = accent_color
        self._icon_chip = None
        self.setStyleSheet(f"""
            QFrame[card="true"] {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                            stop:0 rgba(255, 255, 255, 22),
                                            stop:0.05 rgba(255, 255, 255, 10),
                                            stop:0.36 rgba(58, 66, 82, 176),
                                            stop:1 rgba(36, 42, 54, 218));
                border: 1px solid rgba(255, 255, 255, 26);
                border-top-color: rgba(255, 255, 255, 48);
                border-bottom-color: rgba(0, 0, 0, 115);
                border-radius: 16px;
            }}
            QFrame[card="true"]:hover {{
                border-color: {_rgba(accent_color, 135)};
                border-top-color: rgba(255, 255, 255, 78);
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        v_layout = QVBoxLayout()
        v_layout.setSpacing(3)

        title_lbl = QLabel(title.upper())
        title_lbl.setStyleSheet(
            "color: #9BA3AF; font-size: 10px; font-weight: 700; "
            "letter-spacing: 0.8px; background: transparent;"
        )
        v_layout.addWidget(title_lbl)

        self.value_lbl = QLabel(value)
        self.value_lbl.setStyleSheet(
            f"color: {accent_color}; font-size: 27px; font-weight: 800; "
            "letter-spacing: -0.5px; background: transparent;"
        )
        apply_text_glow(self.value_lbl, accent_color, blur=16, opacity=145)
        v_layout.addWidget(self.value_lbl)

        if subtext:
            sub_lbl = QLabel(subtext)
            sub_lbl.setStyleSheet(
                "color: #C9D2DE; font-size: 11px; background: transparent;"
            )
            sub_lbl.setWordWrap(True)
            v_layout.addWidget(sub_lbl)

        v_layout.addStretch()
        layout.addLayout(v_layout, 1)

        if icon_name:
            chip = QFrame()
            chip.setObjectName("IconChip")
            chip.setFixedSize(46, 46)
            chip.setStyleSheet(f"""
                QFrame#IconChip {{
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                                stop:0 {_rgba(accent_color, 40)},
                                                stop:1 {_rgba(accent_color, 16)});
                    border: 1px solid {_rgba(accent_color, 95)};
                    border-top-color: rgba(255, 255, 255, 55);
                    border-radius: 14px;
                }}
            """)
            chip_layout = QVBoxLayout(chip)
            chip_layout.setContentsMargins(0, 0, 0, 0)
            chip_layout.addWidget(icon_label(icon_name, 24), 0, Qt.AlignCenter)
            layout.addWidget(chip, 0, Qt.AlignVCenter)
            self._icon_chip = chip

    def set_value(self, val: str):
        self.value_lbl.setText(str(val))

    def set_accent(self, accent_color: str):
        """Recolour the value and icon chip when the card state changes."""
        self._accent_color = accent_color
        self.value_lbl.setStyleSheet(
            f"color: {accent_color}; font-size: 27px; font-weight: 800; "
            "letter-spacing: -0.5px; background: transparent;"
        )
        update_glow(self.value_lbl, accent_color, 145)
        if self._icon_chip is not None:
            self._icon_chip.setStyleSheet(f"""
                QFrame#IconChip {{
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                                stop:0 {_rgba(accent_color, 40)},
                                                stop:1 {_rgba(accent_color, 16)});
                    border: 1px solid {_rgba(accent_color, 95)};
                    border-top-color: rgba(255, 255, 255, 55);
                    border-radius: 14px;
                }}
            """)


class ThreatBadge(QLabel):
    """Color-coded severity pill for tables and logs."""

    def __init__(self, severity: str, parent=None):
        super().__init__(severity.upper(), parent)
        sev_styles = {
            "CRITICAL": ("#BF616A", 52),
            "HIGH": ("#D08770", 46),
            "MEDIUM": ("#EBCB8B", 42),
            "LOW": ("#88C0D0", 40),
            "PASS": ("#A3BE8C", 40),
            "SAFE": ("#A3BE8C", 40),
        }
        accent, alpha = sev_styles.get(severity.upper(), ("#9BA3AF", 36))
        self.setStyleSheet(f"""
            background-color: {_rgba(accent, alpha)};
            color: {accent};
            border: 1px solid {_rgba(accent, 125)};
            font-size: 10px;
            font-weight: 800;
            padding: 3px 8px;
            border-radius: 8px;
            letter-spacing: 0.5px;
        """)
        self.setAlignment(Qt.AlignCenter)
        self.setFixedSize(78, 22)
