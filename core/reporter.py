"""
Fikrado Security - Security Report Generator v2
Generates comprehensive HTML and PDF security audit reports.
Uses reportlab for high-quality PDF output.
"""
import io
import os
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from config.constants import APP_VERSION, REPORTS_DIR
from core.logger import logger


# ─── PDF REPORT GENERATION ───────────────────────────────────────────────────
def _build_pdf_reportlab(
    scan_type: str,
    files_scanned: int,
    threats: List[dict],
    duration_seconds: float,
    security_score: int,
    bootkit_results: Optional[List[dict]] = None,
    rootkit_results: Optional[List[dict]] = None,
    network_summary: Optional[List[dict]] = None,
    vuln_summary: Optional[List[dict]] = None,
    system_info: Optional[dict] = None,
) -> bytes:
    """Build a professional PDF report using reportlab (works cross-platform)."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        )
    except ImportError:
        return b""

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    # Color palette (Nord-inspired)
    nord0 = colors.HexColor("#2E3440")   # Background dark
    nord4 = colors.HexColor("#D8DEE9")   # Foreground light
    nord8 = colors.HexColor("#88C0D0")   # Cyan (primary accent)
    nord11 = colors.HexColor("#BF616A")  # Red (critical)
    nord12 = colors.HexColor("#D08770")  # Orange (high)
    nord13 = colors.HexColor("#EBCB8B")  # Yellow (medium)
    nord14 = colors.HexColor("#A3BE8C")  # Green (safe)
    nord3 = colors.HexColor("#4C566A")   # Border gray

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title", parent=styles["Title"],
        fontSize=22, textColor=nord8, spaceAfter=6,
    )
    heading_style = ParagraphStyle(
        "Section", parent=styles["Heading2"],
        fontSize=14, textColor=nord8, spaceAfter=6, spaceBefore=12,
        borderPad=4, borderWidth=0, borderColor=nord8,
    )
    body_style = ParagraphStyle("Body", parent=styles["Normal"],
        fontSize=9, textColor=nord4, leading=13)
    meta_style = ParagraphStyle("Meta", parent=styles["Normal"],
        fontSize=8, textColor=colors.HexColor("#9BA3AF"))

    story: List = []

    # ── Header Banner ──────────────────────────────────────────────────────
    story.append(Paragraph("FIKRADO SECURITY", title_style))
    story.append(Paragraph("Advanced Threat Defense & Vulnerability Audit Report", body_style))
    story.append(Spacer(1, 0.3 * cm))

    timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S")
    hostname = system_info.get("computer_name", os.environ.get("HOSTNAME", "Unknown")) if system_info else "Unknown"

    meta_data = [
        ["Report Generated:", timestamp_str],
        ["Scan Mode:", scan_type],
        ["Duration:", f"{duration_seconds:.1f} seconds"],
        ["Files Scanned:", f"{files_scanned:,}"],
        ["Hostname:", hostname],
        ["App Version:", APP_VERSION],
    ]
    meta_table = Table(meta_data, colWidths=[3.5*cm, 13*cm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TEXTCOLOR", (0, 0), (0, -1), nord8),
        ("TEXTCOLOR", (1, 0), (1, -1), nord4),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#3B4252"), colors.HexColor("#2E3440")]),
        ("GRID", (0, 0), (-1, -1), 0.3, nord3),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.5 * cm))

    # ── Security Score ────────────────────────────────────────────────────
    score_color = nord14 if security_score >= 80 else (nord13 if security_score >= 50 else nord11)
    score_data = [["SECURITY POSTURE SCORE", f"{security_score}/100"]]
    score_table = Table(score_data, colWidths=[12*cm, 4*cm])
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#3B4252")),
        ("BACKGROUND", (1, 0), (1, 0), score_color),
        ("TEXTCOLOR", (0, 0), (0, 0), nord4),
        ("TEXTCOLOR", (1, 0), (1, 0), nord0),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (0, 0), 10),
        ("FONTSIZE", (1, 0), (1, 0), 18),
        ("ALIGN", (1, 0), (1, 0), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("ROUNDEDCORNERS", [6, 6, 6, 6]),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 0.4 * cm))

    # ── Threat Summary KPIs ────────────────────────────────────────────────
    kpi_data = [
        ["Threats Detected", "Bootkit Findings", "Rootkit Findings", "Files Scanned"],
        [str(len(threats)), str(len(bootkit_results or [])), str(len(rootkit_results or [])), f"{files_scanned:,}"],
    ]
    kpi_table = Table(kpi_data, colWidths=[4*cm]*4)
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), nord3),
        ("TEXTCOLOR", (0, 0), (-1, 0), nord4),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, 1), [colors.HexColor("#3B4252")]),
        ("TEXTCOLOR", (0, 1), (-1, 1), nord4),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, nord3),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 0.4 * cm))

    # ── Threat Detection Table ─────────────────────────────────────────────
    if threats:
        story.append(Paragraph("Threat Detection Log", heading_style))
        threat_data = [["Severity", "Threat Name", "Type", "Path", "Action"]]
        for t in threats[:50]:
            sev = t.get("severity", "Medium")
            sev_color = {"Critical": nord11, "High": nord12, "Medium": nord13, "Low": nord8}.get(sev, nord4)
            threat_data.append([
                sev,
                t.get("threat_name", "Unknown")[:40],
                t.get("threat_type", "General"),
                (t.get("file_path", "") or "N/A")[:50],
                t.get("action_taken", "Flagged"),
            ])
        t = Table(threat_data, colWidths=[2*cm, 4*cm, 3*cm, 6*cm, 2*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), nord3),
            ("TEXTCOLOR", (0, 0), (-1, 0), nord4),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, -1), 7),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#2E3440"), colors.HexColor("#3B4252")]),
            ("TEXTCOLOR", (0, 1), (0, -1), nord11),
            ("GRID", (0, 0), (-1, -1), 0.3, nord3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.3 * cm))

    # ── Bootkit Findings ───────────────────────────────────────────────────
    if bootkit_results:
        story.append(Paragraph("Bootkit Integrity Findings", heading_style))
        bk_data = [["Severity", "Type", "Finding", "Recommendation"]]
        for r in bootkit_results[:30]:
            bk_data.append([
                r.get("severity", "Medium")[:12],
                r.get("type", "Unknown")[:20],
                r.get("detail", "")[:45],
                r.get("recommendation", "")[:45],
            ])
        t = Table(bk_data, colWidths=[2*cm, 3*cm, 6*cm, 6*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), nord3),
            ("TEXTCOLOR", (0, 0), (-1, 0), nord4),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, -1), 7),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#2E3440"), colors.HexColor("#3B4252")]),
            ("TEXTCOLOR", (0, 1), (0, -1), colors.HexColor("#BF616A")),
            ("GRID", (0, 0), (-1, -1), 0.3, nord3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.3 * cm))

    # ── Rootkit Findings ───────────────────────────────────────────────────
    if rootkit_results:
        story.append(Paragraph("Rootkit Detection Findings", heading_style))
        rk_data = [["Severity", "Type", "Finding", "Recommendation"]]
        for r in rootkit_results[:30]:
            rk_data.append([
                r.get("severity", "Medium")[:12],
                r.get("type", "Unknown")[:20],
                r.get("detail", "")[:45],
                r.get("recommendation", "")[:45],
            ])
        t = Table(rk_data, colWidths=[2*cm, 3*cm, 6*cm, 6*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), nord3),
            ("TEXTCOLOR", (0, 0), (-1, 0), nord4),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, -1), 7),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#2E3440"), colors.HexColor("#3B4252")]),
            ("TEXTCOLOR", (0, 1), (0, -1), colors.HexColor("#BF616A")),
            ("GRID", (0, 0), (-1, -1), 0.3, nord3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.3 * cm))

    # ── Network / Port Summary ─────────────────────────────────────────────
    if network_summary:
        story.append(Paragraph("Network Ports & Connections", heading_style))
        net_data = [["Port", "Protocol", "Service", "PID", "Risk"]]
        for n in network_summary[:30]:
            risk = n.get("is_risky", False)
            net_data.append([
                str(n.get("port", "")),
                n.get("protocol", "TCP"),
                n.get("service_name", "Unknown")[:20],
                str(n.get("pid", "N/A")),
                "RISK" if risk else "Normal",
            ])
        t = Table(net_data, colWidths=[2*cm, 2*cm, 4*cm, 2*cm, 2*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), nord3),
            ("TEXTCOLOR", (0, 0), (-1, 0), nord4),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, -1), 7),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#2E3440"), colors.HexColor("#3B4252")]),
            ("TEXTCOLOR", (4, 1), (4, -1), colors.HexColor("#BF616A")),
            ("GRID", (0, 0), (-1, -1), 0.3, nord3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.3 * cm))

    # ── Vulnerability Summary ──────────────────────────────────────────────
    if vuln_summary:
        story.append(Paragraph("Known & Emerging Vulnerabilities (CISA KEV)", heading_style))
        vuln_data = [["CVE ID", "Product", "Vulnerability", "Status"]]
        for v in vuln_summary[:30]:
            vuln_data.append([
                v.get("cve_id", "Unknown")[:15],
                v.get("product", "System")[:20],
                v.get("vulnerability_name", "")[:40],
                "Actively Exploited",
            ])
        t = Table(vuln_data, colWidths=[3*cm, 4*cm, 7*cm, 3*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), nord3),
            ("TEXTCOLOR", (0, 0), (-1, 0), nord4),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, -1), 7),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#2E3440"), colors.HexColor("#3B4252")]),
            ("TEXTCOLOR", (3, 1), (3, -1), nord11),
            ("GRID", (0, 0), (-1, -1), 0.3, nord3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(t)

    # ── Footer ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.5 * cm))
    footer_text = (
        f"<b>Generated by Fikrado Security v{APP_VERSION}</b> &bull; "
        f"Report Date: {timestamp_str} &bull; "
        f"Hostname: {hostname}"
    )
    story.append(Paragraph(footer_text, meta_style))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


# ─── PUBLIC API ──────────────────────────────────────────────────────────────
def generate_pdf_report(
    scan_type: str,
    files_scanned: int,
    threats: List[dict],
    duration_seconds: float,
    security_score: int,
    bootkit_results: Optional[List[dict]] = None,
    rootkit_results: Optional[List[dict]] = None,
    network_summary: Optional[List[dict]] = None,
    vuln_summary: Optional[List[dict]] = None,
    system_info: Optional[dict] = None,
) -> Optional[Path]:
    """Generate a PDF report using reportlab. Falls back to HTML if reportlab unavailable."""
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    pdf_path = REPORTS_DIR / f"Fikrado_PDF_Report_{timestamp}.pdf"
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    pdf_bytes = _build_pdf_reportlab(
        scan_type, files_scanned, threats, duration_seconds, security_score,
        bootkit_results, rootkit_results, network_summary, vuln_summary, system_info,
    )
    if not pdf_bytes:
        logger.warning("reportlab not available — PDF not generated")
        return None

    with open(pdf_path, "wb") as f:
        f.write(pdf_bytes)

    logger.info(f"Generated PDF report: {pdf_path}")
    return pdf_path


def generate_html_report(
    scan_type: str,
    files_scanned: int,
    threats: List[dict],
    duration_seconds: float,
    security_score: int,
    network_summary: Optional[List[dict]] = None,
    vuln_summary: Optional[List[dict]] = None,
    system_info: Optional[dict] = None,
) -> Path:
    """Generate a styled HTML report (original implementation)."""
    from core.reporter import generate_html_report as _generate_html
    return _generate_html(
        scan_type, files_scanned, threats, duration_seconds, security_score,
        network_summary, vuln_summary, system_info,
    )


def export_pdf_from_html(html_path: Path) -> Optional[Path]:
    """Convert existing HTML report to PDF via QTextDocument."""
    from core.reporter import export_pdf_report as _export_pdf
    return _export_pdf(html_path)
