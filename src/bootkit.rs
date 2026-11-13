use crate::models::BootkitResult;
use std::fs::File;
use std::io::Read;
use std::os::windows::process::CommandExt;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x08000000;

pub fn scan_bootkit_and_rootkit() -> Vec<BootkitResult> {
    let mut findings = Vec::new();

    // 1. MBR PhysicalDrive0 Integrity Check
    match File::open(r"\\.\PhysicalDrive0") {
        Ok(mut f) => {
            let mut mbr = [0u8; 512];
            if f.read_exact(&mut mbr).is_ok() {
                // Check boot signature 0x55AA at offset 510
                if mbr[510] != 0x55 || mbr[511] != 0xAA {
                    findings.push(BootkitResult {
                        check_type: "MBR Anomaly".to_string(),
                        severity: "Critical".to_string(),
                        detail: "PhysicalDrive0 MBR lacks standard 0x55AA boot sector signature.".to_string(),
                        indicator: format!("Offset 510-511 bytes: {:02X} {:02X}", mbr[510], mbr[511]),
                        recommendation: "Rebuild MBR using Windows Recovery Environment (bootrec /fixmbr).".to_string(),
                    });
                }
            }
        }
        Err(_) => {
            // Permission denied if not elevated Administrator
        }
    }

    // 2. Hidden Process Detection (WMI vs Tasklist)
    let wmi_output = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-Process | Select-Object -ExpandProperty ProcessName"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let tasklist_output = Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    if let (Ok(w), Ok(t)) = (wmi_output, tasklist_output) {
        let wmi_str = String::from_utf8_lossy(&w.stdout);
        let tasklist_str = String::from_utf8_lossy(&t.stdout);

        let mut tlist_set = std::collections::HashSet::new();
        for line in tasklist_str.lines() {
            let parts: Vec<&str> = line.split(',').collect();
            if !parts.is_empty() {
                let name = parts[0].trim_matches('"').trim_end_matches(".exe").to_ascii_lowercase();
                tlist_set.insert(name);
            }
        }

        let known_system = ["csrss", "smss", "wininit", "services", "lsass", "svchost", "dwm", "explorer", "runtimebroker", "taskhostw"];
        let mut hidden_procs = Vec::new();

        for line in wmi_str.lines() {
            let name = line.trim().to_ascii_lowercase();
            if !name.is_empty() && !known_system.contains(&name.as_str()) && !tlist_set.contains(&name) {
                hidden_procs.push(name);
            }
        }

        if !hidden_procs.is_empty() {
            findings.push(BootkitResult {
                check_type: "Hidden Process".to_string(),
                severity: "High".to_string(),
                detail: format!("Found {} processes visible in WMI but unlisted in tasklist.", hidden_procs.len()),
                indicator: hidden_procs.join(", "),
                recommendation: "Analyze anomalous processes using Process Explorer or memory forensics.".to_string(),
            });
        }
    }

    // 3. Driver Directory Inspection
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let drivers_dir = std::path::PathBuf::from(sys_root).join("System32\\drivers");
    if drivers_dir.exists() {
        let suspicious_driver_patterns = ["rtcwatch", "diskreg", "safeguard", "hook", "inject"];
        if let Ok(entries) = std::fs::read_dir(drivers_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                for pat in &suspicious_driver_patterns {
                    if name.contains(pat) {
                        findings.push(BootkitResult {
                            check_type: "Rootkit Driver Heuristic".to_string(),
                            severity: "High".to_string(),
                            detail: format!("Kernel driver '{}' matches suspicious naming pattern.", name),
                            indicator: format!("Driver: {}", name),
                            recommendation: "Verify driver digital signature with sigverif.exe.".to_string(),
                        });
                        break;
                    }
                }
            }
        }
    }

    findings
}
