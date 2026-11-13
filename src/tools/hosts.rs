use crate::models::HostsAuditResult;
use std::fs;
use std::path::PathBuf;

pub fn get_hosts_path() -> PathBuf {
    PathBuf::from("C:\\Windows\\System32\\drivers\\etc\\hosts")
}

pub fn check_hosts_file() -> HostsAuditResult {
    let path = get_hosts_path();
    let content = fs::read_to_string(&path).unwrap_or_default();

    let mut total_lines = 0;
    let mut active_entries = 0;
    let mut hijacked_entries = Vec::new();

    let suspicious_domains = [
        "microsoft.com", "windowsupdate.com", "google.com", "virustotal.com",
        "symantec.com", "mcafee.com", "bitdefender.com", "kaspersky.com"
    ];

    for line in content.lines() {
        total_lines += 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        active_entries += 1;
        let lower = trimmed.to_ascii_lowercase();

        for dom in &suspicious_domains {
            if lower.contains(dom) {
                hijacked_entries.push(trimmed.to_string());
                break;
            }
        }
    }

    let is_clean = hijacked_entries.is_empty();

    HostsAuditResult {
        path: path.to_string_lossy().to_string(),
        total_lines,
        active_entries,
        hijacked_entries,
        is_clean,
    }
}

pub fn restore_default_hosts() -> Result<(), String> {
    let default_content = "# Microsoft Windows default hosts file\n\
# Created by Fikrado Security Integrity Restorer\n\
\n\
127.0.0.1       localhost\n\
::1             localhost\n";

    let path = get_hosts_path();
    fs::write(&path, default_content).map_err(|e| format!("Failed to write hosts file: {}", e))
}
