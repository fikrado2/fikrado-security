use crate::models::ThreatFinding;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x08000000;

pub fn inspect_persistence() -> Vec<ThreatFinding> {
    let mut findings = Vec::new();
    findings.extend(check_registry_persistence());
    findings.extend(check_startup_folders());
    findings
}

fn check_registry_persistence() -> Vec<ThreatFinding> {
    let mut findings = Vec::new();

    let targets = [
        ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU Run"),
        ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU RunOnce"),
        ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM Run"),
        ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM RunOnce"),
    ];

    for (key, label) in &targets {
        let output = match Command::new("reg")
            .args(["query", key])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
            Err(_) => continue,
        };

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("HKEY_") {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let name = parts[0];
                let value = parts[2..].join(" ");
                let val_lower = value.to_ascii_lowercase();

                let mut is_suspicious = false;
                let mut reason = "";

                if val_lower.contains("temp\\") || val_lower.contains("\\tmp\\") {
                    is_suspicious = true;
                    reason = "Persistence binary executes from a temporary directory.";
                } else if val_lower.contains("powershell")
                    && (val_lower.contains("-enc") || val_lower.contains("-w hidden") || val_lower.contains("-windowstyle hidden"))
                {
                    is_suspicious = true;
                    reason = "Persistence entry runs obfuscated or hidden PowerShell script.";
                } else if val_lower.contains("certutil") || val_lower.contains("bitsadmin") || val_lower.contains("mshta") {
                    is_suspicious = true;
                    reason = "Persistence entry uses LOLBin (Living-Off-The-Land Binary).";
                }

                if is_suspicious {
                    findings.push(ThreatFinding {
                        id: None,
                        scan_id: None,
                        file_path: value.clone(),
                        threat_name: format!("Suspicious Registry Autostart: {}", name),
                        threat_type: "Trojan".to_string(),
                        severity: "High".to_string(),
                        detection_engine: "Persistence Inspector".to_string(),
                        description: format!("{} key '{}' -> '{}'. {}", label, name, value, reason),
                        action_taken: "Flagged".to_string(),
                        sha256: "".to_string(),
                        detected_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    });
                }
            }
        }
    }

    findings
}

fn check_startup_folders() -> Vec<ThreatFinding> {
    let mut findings = Vec::new();

    let mut folders = Vec::new();
    if let Ok(appdata) = std::env::var("APPDATA") {
        folders.push(PathBuf::from(appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }
    if let Ok(programdata) = std::env::var("PROGRAMDATA") {
        folders.push(PathBuf::from(programdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }

    let suspicious_exts = ["vbs", "bat", "cmd", "ps1", "hta", "js", "wsf"];

    for folder in folders {
        if !folder.exists() || !folder.is_dir() {
            continue;
        }

        if let Ok(entries) = std::fs::read_dir(&folder) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let ext = path
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(|s| s.to_ascii_lowercase())
                        .unwrap_or_default();

                    if suspicious_exts.contains(&ext.as_str()) {
                        findings.push(ThreatFinding {
                            id: None,
                            scan_id: None,
                            file_path: path.to_string_lossy().to_string(),
                            threat_name: format!("Suspicious Startup Script: {}", path.file_name().unwrap_or_default().to_string_lossy()),
                            threat_type: "Trojan".to_string(),
                            severity: "High".to_string(),
                            detection_engine: "Startup Folder Audit".to_string(),
                            description: format!("Uncompiled script '{}' found in Windows autostart directory.", path.display()),
                            action_taken: "Flagged".to_string(),
                            sha256: "".to_string(),
                            detected_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                        });
                    }
                }
            }
        }
    }

    findings
}
