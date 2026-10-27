"""
Fikrado Security - Security Report Generator
Produces rich HTML and PDF executive reports with Nord & Fikrado styling.
"""
import time
from pathlib import Path
from typing import List, Optional
from config.constants import APP_VERSION, REPORTS_DIR
from core.logger import logger


def generate_html_report(
    scan_type: str,
    files_scanned: int,
    threats: List[dict],
    duration_seconds: float,
    security_score: int,
    network_summary: Optional[List[dict]] = None,
    vuln_summary: Optional[List[dict]] = None,
    system_info: Optional[dict] = None
) -> Path:
    """Generates a standalone styled HTML report and saves to %APPDATA%/reports."""
    timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S")
    file_timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_file = REPORTS_DIR / f"Fikrado_Report_{file_timestamp}.html"

    # Threat rows
    threat_rows = ""
    if threats:
        for t in threats:
            sev = t.get("severity", "Medium")
            sev_color = {
                "Critical": "#BF616A",
                "High": "#D08770",
                "Medium": "#EBCB8B",
                "Low": "#88C0D0"
            }.get(sev, "#88C0D0")

            threat_rows += f"""
            <tr>
                <td><span style="background-color: {sev_color}; color: #2E3440; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">{sev}</span></td>
                <td><strong>{t.get('threat_name', 'Suspicious Object')}</strong></td>
                <td>{t.get('threat_type', 'General Malware')}</td>
                <td><code>{t.get('file_path', 'N/A')}</code></td>
                <td>{t.get('detection_engine', 'Heuristic')}</td>
                <td>{t.get('action_taken', 'Flagged')}</td>
            </tr>
            """
    else:
        threat_rows = """
        <tr>
            <td colspan="6" style="text-align: center; color: #A3BE8C; padding: 20px;">
                ✔ No malicious items detected during this security scan.
            </td>
        </tr>
        """

    # Network rows
    network_rows = ""
    if network_summary:
        for net in network_summary[:15]:
            is_risky = net.get("is_risky", False)
            badge = '<span style="background: #BF616A; color: #fff; padding: 2px 6px; border-radius: 3px; font-size: 10px;">RISKY</span>' if is_risky else '<span style="color: #A3BE8C; font-size: 11px;">Normal</span>'
            network_rows += f"""
            <tr>
                <td><strong>{net.get('port')}</strong> ({net.get('protocol', 'TCP')})</td>
                <td>{net.get('service_name', 'Unknown')}</td>
                <td>{net.get('process_name', 'System')} (PID: {net.get('pid', 'N/A')})</td>
                <td>{badge}</td>
                <td>{net.get('description', 'Standard connection')}</td>
            </tr>
            """

    # Vuln rows
    vuln_rows = ""
    if vuln_summary:
        for v in vuln_summary[:15]:
            vuln_rows += f"""
            <tr>
                <td><strong style="color: #88C0D0;">{v.get('cve_id', 'CVE-Unknown')}</strong></td>
                <td>{v.get('product', 'System Component')}</td>
                <td>{v.get('vulnerability_name', 'Security Advisory')}</td>
                <td><span style="color: #BF616A; font-weight: bold;">Actively Exploited</span></td>
                <td>{v.get('required_action', 'Apply vendor security update.')}</td>
            </tr>
            """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Fikrado Security Executive Audit Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #2E3440;
            color: #ECEFF4;
            margin: 0;
            padding: 40px;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #434C5E;
            padding-bottom: 25px;
            margin-bottom: 30px;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        .brand h1 {{
            margin: 0;
            font-size: 26px;
            background: linear-gradient(135deg, #FFD93D 0%, #88C0D0 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .brand p {{
            margin: 2px 0 0 0;
            color: #D8DEE9;
            font-size: 13px;
        }}
        .score-box {{
            background: #3B4252;
            padding: 15px 25px;
            border-radius: 12px;
            border: 1px solid #4C566A;
            text-align: center;
        }}
        .score-val {{
            font-size: 32px;
            font-weight: 800;
            color: #88C0D0;
        }}
        .cards-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 35px;
        }}
        .card {{
            background-color: #3B4252;
            border: 1px solid #434C5E;
            border-radius: 10px;
            padding: 16px;
        }}
        .card-title {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #9BA3AF;
            margin-bottom: 8px;
        }}
        .card-value {{
            font-size: 22px;
            font-weight: bold;
            color: #ECEFF4;
        }}
        h2 {{
            font-size: 18px;
            color: #88C0D0;
            margin-top: 30px;
            margin-bottom: 12px;
            border-left: 4px solid #FFD93D;
            padding-left: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: #3B4252;
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 30px;
            font-size: 13px;
        }}
        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid #434C5E;
        }}
        th {{
            background-color: #242933;
            color: #D8DEE9;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        code {{
            background-color: #2E3440;
            color: #88C0D0;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: Consolas, monospace;
            font-size: 12px;
        }}
        .footer {{
            margin-top: 40px;
            border-top: 1px solid #434C5E;
            padding-top: 20px;
            font-size: 12px;
            color: #9BA3AF;
            display: flex;
            justify-content: space-between;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="brand">
            <div>
                <h1>Fikrado Security</h1>
                <p>Advanced Threat Defense & Vulnerability Audit</p>
            </div>
        </div>
        <div class="score-box">
            <div class="score-val">{security_score}/100</div>
            <div style="font-size: 11px; color: #D8DEE9; text-transform: uppercase;">Security Posture</div>
        </div>
    </div>

    <div class="cards-grid">
        <div class="card">
            <div class="card-title">Scan Mode</div>
            <div class="card-value">{scan_type}</div>
        </div>
        <div class="card">
            <div class="card-title">Duration</div>
            <div class="card-value">{duration_seconds:.1f}s</div>
        </div>
        <div class="card">
            <div class="card-title">Scanned Objects</div>
            <div class="card-value">{files_scanned}</div>
        </div>
        <div class="card">
            <div class="card-title">Threats Detected</div>
            <div class="card-value" style="color: {'#BF616A' if len(threats) > 0 else '#A3BE8C'};">{len(threats)}</div>
        </div>
    </div>

    <h2>Threat Detection Log</h2>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Threat Name</th>
                <th>Classification</th>
                <th>Target Object / Path</th>
                <th>Detection Engine</th>
                <th>Action Taken</th>
            </tr>
        </thead>
        <tbody>
            {threat_rows}
        </tbody>
    </table>
"""

    if network_rows:
        html_content += f"""
    <h2>Network & Open Ports Audit</h2>
    <table>
        <thead>
            <tr>
                <th>Port / Protocol</th>
                <th>Service Name</th>
                <th>Process (PID)</th>
                <th>Risk Status</th>
                <th>Analysis & Description</th>
            </tr>
        </thead>
        <tbody>
            {network_rows}
        </tbody>
    </table>
        """

    if vuln_rows:
        html_content += f"""
    <h2>Known and Emerging Vulnerability Check (CISA KEV)</h2>
    <table>
        <thead>
            <tr>
                <th>Advisory CVE</th>
                <th>Affected Product</th>
                <th>Vulnerability Title</th>
                <th>Exploitation Status</th>
                <th>Recommended Action</th>
            </tr>
        </thead>
        <tbody>
            {vuln_rows}
        </tbody>
    </table>
        """

    html_content += f"""
    <div class="footer">
        <div>Generated by Fikrado Security v{APP_VERSION} &bull; Running on {system_info.get('computer_name', 'Windows')}</div>
        <div>Report Date: {timestamp_str}</div>
    </div>
</body>
</html>
    """

    with open(report_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    logger.info(f"Generated security report: {report_file}")
    return report_file


def export_pdf_report(html_file: Path) -> Optional[Path]:
    """Converts an HTML report to PDF format via PySide6 QtGui / QTextDocument."""
    try:
        from PySide6.QtGui import QTextDocument
        from PySide6.QtPrintSupport import QPrinter

        pdf_path = html_file.with_suffix(".pdf")
        with open(html_file, "r", encoding="utf-8") as f:
            html = f.read()

        doc = QTextDocument()
        doc.setHtml(html)

        printer = QPrinter(QPrinter.HighResolution)
        printer.setOutputFormat(QPrinter.PdfFormat)
        printer.setOutputFileName(str(pdf_path))
        doc.print_(printer)

        logger.info(f"Exported PDF report: {pdf_path}")
        return pdf_path
    except Exception as e:
        logger.warning(f"Could not convert to PDF using QPrinter: {e}")
        return None
