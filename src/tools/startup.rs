use crate::models::StartupItem;
use std::os::windows::process::CommandExt;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x08000000;

pub fn list_startup_items() -> Vec<StartupItem> {
    let mut items = Vec::new();
    let keys = [
        ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU Run"),
        ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM Run"),
    ];

    for (key, location) in &keys {
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
                let cmd = parts[2..].join(" ");
                let cmd_lower = cmd.to_ascii_lowercase();

                let mut is_suspicious = false;
                let mut reason = String::new();

                if cmd_lower.contains("temp\\") || cmd_lower.contains("\\tmp") {
                    is_suspicious = true;
                    reason = "Executes from temporary directory.".to_string();
                } else if cmd_lower.contains("powershell") && cmd_lower.contains("-enc") {
                    is_suspicious = true;
                    reason = "Hidden encoded PowerShell launcher.".to_string();
                }

                items.push(StartupItem {
                    id: format!("{}:{}", key, name),
                    name: name.to_string(),
                    command: cmd,
                    location: location.to_string(),
                    is_enabled: true,
                    is_suspicious,
                    reason,
                });
            }
        }
    }

    items
}

pub fn remove_startup_item(key_path: &str, item_name: &str) -> Result<String, String> {
    let output = Command::new("reg")
        .args(["delete", key_path, "/v", item_name, "/f"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        Ok(format!("Startup item '{}' removed.", item_name))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}
