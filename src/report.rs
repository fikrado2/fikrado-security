use crate::db::Database;
use crate::models::{HardeningCheck, InstalledApp, OpenPort, QuarantineItem, ThreatFinding};
use crate::network;
use crate::quarantine;
use crate::tools::{defender, firewall, hardening};
use crate::vuln;
use chrono::Local;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use sysinfo::System;

const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SecurityReportData {
    pub generated_at: String,
    pub hostname: String,
    pub os_name: String,
    pub cpu_brand: String,
    pub total_memory_gb: f64,
    pub posture_score: u32,
    pub posture_grade: String,
    pub defender_active: bool,
    pub defender_sig_version: String,
    pub firewall_domain: bool,
    pub firewall_private: bool,
    pub firewall_public: bool,
    pub total_listening_ports: usize,
    pub risky_ports_count: usize,
    pub installed_apps_count: usize,
    pub cve_matches_count: usize,
    pub hardening_checks: Vec<HardeningCheck>,
    pub threats_history: Vec<ThreatFinding>,
    pub quarantine_items: Vec<QuarantineItem>,
    pub active_connections: Vec<OpenPort>,
    pub vulnerable_apps: Vec<InstalledApp>,
}

pub fn gather_report_data(db: &Database) -> SecurityReportData {
    let mut sys = System::new_all();
    sys.refresh_all();

    let hostname = System::host_name().unwrap_or_else(|| "WINDOWS-HOST".to_string());
    let os_name = System::long_os_version().unwrap_or_else(|| "Microsoft Windows 11 Enterprise".to_string());
    let cpu_brand = sys.cpus().first().map(|c| c.brand().to_string()).unwrap_or_else(|| "x86_64 Processor".to_string());
    let total_memory_gb = sys.total_memory() as f64 / (1024.0 * 1024.0 * 1024.0);

    let def_status = defender::get_defender_status();
    let fw_status = firewall::get_firewall_status();
    let hardening_checks = hardening::run_hardening_audit();
    let active_connections = network::list_active_connections();
    let installed_apps = vuln::get_installed_software(db);
    let threats_history = db.get_recent_threats(100).unwrap_or_default();
    let quarantine_items = quarantine::list_quarantine_items();

    let risky_ports = active_connections.iter().filter(|c| c.is_risky).count();
    let vulnerable_apps: Vec<InstalledApp> = installed_apps.iter().filter(|a| !a.cve_matches.is_empty()).cloned().collect();
    let cve_matches_count: usize = vulnerable_apps.iter().map(|a| a.cve_matches.len()).sum();
    let installed_apps_count = installed_apps.len();

    // Calculate score
    let mut score: i32 = 100;
    if !def_status.real_time_protection {
        score -= 25;
    }
    if !fw_status.public_enabled || !fw_status.private_enabled {
        score -= 20;
    }
    for check in &hardening_checks {
        if check.status == "Fail" {
            score -= 15;
        } else if check.status == "Warn" {
            score -= 5;
        }
    }
    if risky_ports > 0 {
        score -= (risky_ports as i32 * 5).min(20);
    }
    if cve_matches_count > 0 {
        score -= (cve_matches_count as i32 * 5).min(25);
    }
    let final_score = score.clamp(15, 100) as u32;

    let grade = if final_score >= 90 {
        "A+ SECURE".to_string()
    } else if final_score >= 75 {
        "B ADEQUATE".to_string()
    } else if final_score >= 50 {
        "C AT RISK".to_string()
    } else {
        "CRITICAL RISK".to_string()
    };

    SecurityReportData {
        generated_at: Local::now().format("%Y-%m-%d %H:%M:%S UTC%z").to_string(),
        hostname,
        os_name,
        cpu_brand,
        total_memory_gb,
        posture_score: final_score,
        posture_grade: grade,
        defender_active: def_status.real_time_protection && def_status.antivirus_enabled,
        defender_sig_version: def_status.definition_version,
        firewall_domain: fw_status.domain_enabled,
        firewall_private: fw_status.private_enabled,
        firewall_public: fw_status.public_enabled,
        total_listening_ports: active_connections.len(),
        risky_ports_count: risky_ports,
        installed_apps_count,
        cve_matches_count,
        hardening_checks,
        threats_history,
        quarantine_items,
        active_connections,
        vulnerable_apps,
    }
}

pub fn generate_html_report(data: &SecurityReportData) -> String {
    let score_color = if data.posture_score >= 80 {
        "#10b981"
    } else if data.posture_score >= 60 {
        "#f59e0b"
    } else {
        "#ef4444"
    };

    let mut hardening_rows = String::new();
    for c in &data.hardening_checks {
        let (badge_bg, badge_text) = match c.status.as_str() {
            "Pass" => ("#10b981", "PASS"),
            "Warn" => ("#f59e0b", "WARN"),
            _ => ("#ef4444", "FAIL"),
        };
        hardening_rows.push_str(&format!(
            "<tr>\
                <td style='font-weight:600;'>{}</td>\
                <td><span style='background:{}; color:#ffffff; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700;'>{}</span></td>\
                <td style='color:#475569;'>{}</td>\
                <td style='color:#0f172a; font-family:monospace; font-size:12px;'>{}</td>\
            </tr>",
            c.title, badge_bg, badge_text, c.details, c.recommendation
        ));
    }

    let mut conn_rows = String::new();
    for conn in data.active_connections.iter().take(20) {
        let (badge_bg, badge_text) = if conn.is_risky {
            ("#ef4444", "HIGH RISK")
        } else {
            ("#10b981", "SAFE")
        };
        conn_rows.push_str(&format!(
            "<tr>\
                <td><strong>{}</strong></td>\
                <td>{}</td>\
                <td>{}</td>\
                <td>{}</td>\
                <td><span style='background:{}; color:#ffffff; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700;'>{}</span></td>\
                <td>{}</td>\
            </tr>",
            conn.protocol, conn.port, conn.local_ip, conn.process_name, badge_bg, badge_text, conn.service_name
        ));
    }

    let mut vuln_rows = String::new();
    if data.vulnerable_apps.is_empty() {
        vuln_rows.push_str("<tr><td colspan='4' style='text-align:center; color:#10b981; font-weight:600;'>No known CISA KEV vulnerabilities detected in installed software.</td></tr>");
    } else {
        for app in &data.vulnerable_apps {
            let cve_list: Vec<String> = app.cve_matches.iter().map(|c| c.cve_id.clone()).collect();
            vuln_rows.push_str(&format!(
                "<tr>\
                    <td><strong>{}</strong></td>\
                    <td>{}</td>\
                    <td>{}</td>\
                    <td><span style='background:#ef4444; color:#ffffff; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700;'>{}</span></td>\
                </tr>",
                app.name, app.version, app.publisher, cve_list.join(", ")
            ));
        }
    }

    let mut threat_rows = String::new();
    if data.threats_history.is_empty() {
        threat_rows.push_str("<tr><td colspan='5' style='text-align:center; color:#10b981; font-weight:600;'>No malicious threat activity recorded. System integrity clean.</td></tr>");
    } else {
        for t in data.threats_history.iter().take(10) {
            threat_rows.push_str(&format!(
                "<tr>\
                    <td><span style='background:#ef4444; color:#ffffff; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700;'>{}</span></td>\
                    <td><strong>{}</strong></td>\
                    <td>{}</td>\
                    <td style='font-family:monospace; font-size:11px; max-width:260px; word-break:break-all;'>{}</td>\
                    <td>{}</td>\
                </tr>",
                t.severity, t.threat_name, t.detection_engine, t.file_path, t.detected_at
            ));
        }
    }

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Fikrado Security - Executive Audit Report</title>
<style>
  @page {{
    size: A4;
    margin: 15mm 15mm 15mm 15mm;
  }}
  * {{
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #1e293b;
    background: #ffffff;
    padding: 24px;
    line-height: 1.5;
  }}
  .header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 3px solid #0f172a;
    padding-bottom: 16px;
    margin-bottom: 24px;
  }}
  .brand-title {{
    font-size: 26px;
    font-weight: 900;
    letter-spacing: 0.5px;
    color: #0f172a;
  }}
  .brand-sub {{
    font-size: 13px;
    color: #64748b;
    font-weight: 500;
  }}
  .meta-box {{
    text-align: right;
    font-size: 12px;
    color: #475569;
  }}
  .kpi-grid {{
    display: grid;
    grid-template-columns: 180px 1fr 1fr 1fr;
    gap: 16px;
    margin-bottom: 24px;
  }}
  .score-card {{
    background: #f8fafc;
    border: 2px solid {};
    border-radius: 8px;
    padding: 16px;
    text-align: center;
  }}
  .score-num {{
    font-size: 44px;
    font-weight: 900;
    color: {};
    line-height: 1;
  }}
  .score-label {{
    font-size: 11px;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 6px;
    color: {};
  }}
  .kpi-card {{
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 14px;
  }}
  .kpi-title {{
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    color: #64748b;
    margin-bottom: 6px;
  }}
  .kpi-val {{
    font-size: 18px;
    font-weight: 800;
    color: #0f172a;
  }}
  .section-title {{
    font-size: 16px;
    font-weight: 800;
    color: #0f172a;
    border-left: 4px solid #3b82f6;
    padding-left: 10px;
    margin-top: 26px;
    margin-bottom: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 18px;
    font-size: 12px;
  }}
  th {{
    background: #f1f5f9;
    color: #334155;
    font-weight: 700;
    text-align: left;
    padding: 8px 10px;
    border-bottom: 2px solid #cbd5e1;
  }}
  td {{
    padding: 8px 10px;
    border-bottom: 1px solid #e2e8f0;
  }}
  .footer {{
    margin-top: 36px;
    border-top: 1px solid #e2e8f0;
    padding-top: 12px;
    font-size: 11px;
    color: #94a3b8;
    display: flex;
    justify-content: space-between;
  }}
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="brand-title">FIKRADO SECURITY</div>
    <div class="brand-sub">Enterprise Endpoint Threat Defense Platform · Executive Audit Report</div>
  </div>
  <div class="meta-box">
    <div><strong>Generated:</strong> {}</div>
    <div><strong>Host:</strong> {}</div>
    <div><strong>OS:</strong> {}</div>
    <div><strong>Specs:</strong> {:.1} GB RAM | {}</div>
  </div>
</div>

<div class="kpi-grid">
  <div class="score-card">
    <div class="score-num">{}</div>
    <div class="score-label">{}</div>
  </div>
  <div class="kpi-card">
    <div class="kpi-title">Microsoft Defender</div>
    <div class="kpi-val" style="color:{};">{}</div>
    <div style="font-size:11px; color:#64748b; margin-top:4px;">Signatures: {}</div>
  </div>
  <div class="kpi-card">
    <div class="kpi-title">Windows Firewall</div>
    <div class="kpi-val">{} / 3 Active</div>
    <div style="font-size:11px; color:#64748b; margin-top:4px;">Domain: {} | Private: {} | Public: {}</div>
  </div>
  <div class="kpi-card">
    <div class="kpi-title">Network Attack Surface</div>
    <div class="kpi-val">{} Sockets</div>
    <div style="font-size:11px; color:{}; margin-top:4px;">{} High Risk Exposed Ports</div>
  </div>
</div>

<div class="section-title">1. Endpoint Hardening & Defense Compliance</div>
<table>
  <thead>
    <tr>
      <th style="width:25%;">Security Control</th>
      <th style="width:12%;">Status</th>
      <th style="width:33%;">Technical State</th>
      <th style="width:30%;">Remediation Guidance</th>
    </tr>
  </thead>
  <tbody>
    {}
  </tbody>
</table>

<div class="section-title">2. Software Vulnerabilities & CISA KEV Correlation</div>
<table>
  <thead>
    <tr>
      <th style="width:30%;">Application Name</th>
      <th style="width:20%;">Installed Version</th>
      <th style="width:25%;">Publisher</th>
      <th style="width:25%;">Identified CISA KEV CVEs</th>
    </tr>
  </thead>
  <tbody>
    {}
  </tbody>
</table>

<div class="section-title">3. Active Listening Network Ports & Threat Exposure</div>
<table>
  <thead>
    <tr>
      <th style="width:10%;">Proto</th>
      <th style="width:10%;">Port</th>
      <th style="width:20%;">Bind Address</th>
      <th style="width:25%;">Process Attribution</th>
      <th style="width:15%;">Risk Level</th>
      <th style="width:20%;">Service Name</th>
    </tr>
  </thead>
  <tbody>
    {}
  </tbody>
</table>

<div class="section-title">4. Endpoint Threat Detections & Quarantine Vault</div>
<table>
  <thead>
    <tr>
      <th style="width:12%;">Severity</th>
      <th style="width:22%;">Threat Classification</th>
      <th style="width:18%;">Detection Engine</th>
      <th style="width:33%;">Target File Location</th>
      <th style="width:15%;">Timestamp</th>
    </tr>
  </thead>
  <tbody>
    {}
  </tbody>
</table>

<div class="footer">
  <div>Fikrado Security v2.6.87 · Native Windows Rust Threat Defense Platform · Confidential Security Audit</div>
  <div>Signature: Official Endpoint Telemetry Certified</div>
</div>

</body>
</html>
"#,
        score_color,
        score_color,
        score_color,
        data.generated_at,
        data.hostname,
        data.os_name,
        data.total_memory_gb,
        data.cpu_brand,
        data.posture_score,
        data.posture_grade,
        if data.defender_active { "#10b981" } else { "#ef4444" },
        if data.defender_active { "ACTIVE & SHIELDED" } else { "DISABLED / AT RISK" },
        data.defender_sig_version,
        (data.firewall_domain as usize) + (data.firewall_private as usize) + (data.firewall_public as usize),
        if data.firewall_domain { "ON" } else { "OFF" },
        if data.firewall_private { "ON" } else { "OFF" },
        if data.firewall_public { "ON" } else { "OFF" },
        data.total_listening_ports,
        if data.risky_ports_count == 0 { "#10b981" } else { "#ef4444" },
        data.risky_ports_count,
        hardening_rows,
        vuln_rows,
        conn_rows,
        threat_rows
    )
}

pub fn generate_pdf_report(db: &Database, custom_dest: Option<PathBuf>) -> Result<PathBuf, String> {
    let data = gather_report_data(db);
    let html = generate_html_report(&data);

    let temp_dir = std::env::temp_dir();
    let temp_html = temp_dir.join(format!("fikrado_audit_{}.html", Local::now().timestamp_millis()));
    std::fs::write(&temp_html, html).map_err(|e| format!("Failed to write HTML report: {}", e))?;

    let dest_pdf = match custom_dest {
        Some(p) => p,
        None => {
            // Default to user's Desktop
            let desktop = if let Ok(userprofile) = std::env::var("USERPROFILE") {
                PathBuf::from(userprofile).join("Desktop")
            } else {
                temp_dir.clone()
            };
            desktop.join("Fikrado_Security_Audit_Report.pdf")
        }
    };

    // Locate Microsoft Edge
    let edge_paths = [
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    ];

    let mut edge_exe = None;
    for p in &edge_paths {
        if Path::new(p).exists() {
            edge_exe = Some(p.to_string());
            break;
        }
    }

    let edge = edge_exe.ok_or_else(|| "Microsoft Edge is required to compile the executive PDF report.".to_string())?;

    let output = Command::new(&edge)
        .args([
            "--headless",
            "--disable-gpu",
            "--run-all-compositor-stages-before-draw",
            &format!("--print-to-pdf={}", dest_pdf.to_string_lossy()),
            &temp_html.to_string_lossy(),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Edge PDF engine error: {}", e))?;

    let _ = std::fs::remove_file(&temp_html);

    if dest_pdf.exists() && output.status.success() {
        // Automatically open the generated PDF in the default Windows PDF reader
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-Command", &format!("Start-Process '{}'", dest_pdf.to_string_lossy())])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();

        Ok(dest_pdf)
    } else {
        Err("Failed to render PDF report via headless print engine.".to_string())
    }
}
