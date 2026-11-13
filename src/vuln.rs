use crate::db::Database;
use crate::models::InstalledApp;
use std::collections::HashSet;
use std::os::windows::process::CommandExt;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x08000000;

pub fn get_installed_software(db: &Database) -> Vec<InstalledApp> {
    let mut software_list = Vec::new();
    let mut seen = HashSet::new();

    let cisa_kevs = db.get_cisa_kevs().unwrap_or_default();

    let reg_paths = [
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    ];

    for reg_path in &reg_paths {
        let output = match Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Get-ItemProperty '{}/*' | Where-Object {{ $_.DisplayName }} | Select-Object DisplayName, DisplayVersion, Publisher, PSChildName | ConvertTo-Json -Compress",
                    reg_path
                ),
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
            Err(_) => continue,
        };

        if output.trim().is_empty() {
            continue;
        }

        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&output) {
            let items = if val.is_array() {
                val.as_array().cloned().unwrap_or_default()
            } else if val.is_object() {
                vec![val]
            } else {
                Vec::new()
            };

            for item in items {
                let name = item["DisplayName"].as_str().unwrap_or("").trim();
                if name.is_empty() {
                    continue;
                }
                let version = item["DisplayVersion"].as_str().unwrap_or("Unknown").trim();
                let publisher = item["Publisher"].as_str().unwrap_or("Unknown").trim();
                let child_name = item["PSChildName"].as_str().unwrap_or("").trim();

                let key = format!("{}:{}", name.to_ascii_lowercase(), version.to_ascii_lowercase());
                if seen.contains(&key) {
                    continue;
                }
                seen.insert(key);

                // Match with CISA KEV
                let mut matched_cves = Vec::new();
                let name_lower = name.to_ascii_lowercase();

                for cve in &cisa_kevs {
                    let prod_lower = cve.product.to_ascii_lowercase();
                    let vendor_lower = cve.vendor_project.to_ascii_lowercase();

                    if name_lower.contains(&prod_lower)
                        || (vendor_lower.len() > 3 && name_lower.contains(&vendor_lower))
                    {
                        matched_cves.push(cve.clone());
                    }
                }

                software_list.push(InstalledApp {
                    name: name.to_string(),
                    version: version.to_string(),
                    publisher: publisher.to_string(),
                    registry_id: child_name.to_string(),
                    cve_matches: matched_cves,
                });
            }
        }
    }

    software_list.sort_by(|a, b| {
        b.cve_matches.len().cmp(&a.cve_matches.len()).then_with(|| a.name.cmp(&b.name))
    });

    software_list
}

pub fn upgrade_application(app_name: &str) -> Result<String, String> {
    let output = Command::new("winget")
        .args(["upgrade", "--exact", "--name", app_name, "--accept-source-agreements", "--accept-package-agreements"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to run winget: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if output.status.success() {
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Err(if !stderr.is_empty() { stderr } else { stdout })
    }
}

pub fn get_windows_hotfixes() -> Vec<String> {
    let output = match Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-HotFix | Select-Object -First 15 -ExpandProperty HotFixID",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return Vec::new(),
    };

    output
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}
