"""
Fikrado Security - UI Text Formatting Helpers

Small presentation helpers shared by tables and cards.  Qt's item delegate
mis-elides strings that contain Windows backslashes (a long path collapses to
``C:...``), so paths are compacted here using forward slashes and the full value
is kept in the cell tooltip.
"""
from __future__ import annotations


def display_path(path: str, keep_parts: int = 2) -> str:
    """Return a compact, human-readable path for a table cell."""
    if not path:
        return ""
    text = str(path).strip().strip('"')
    normalized = text.replace("\\", "/").rstrip("/")
    if not normalized:
        return text

    parts = [part for part in normalized.split("/") if part]
    if len(parts) <= keep_parts:
        return normalized

    prefix = "//" if normalized.startswith("//") else ""
    return f"{prefix}…/" + "/".join(parts[-keep_parts:])
