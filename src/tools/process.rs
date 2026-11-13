use crate::models::ProcessItem;
use sysinfo::System;

pub fn list_processes() -> Vec<ProcessItem> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut list = Vec::new();

    let critical_names = ["csrss.exe", "lsass.exe", "services.exe", "svchost.exe", "explorer.exe", "smss.exe"];

    for (pid, proc) in sys.processes() {
        let name = proc.name().to_string_lossy().to_string();
        let exe_path = proc.exe().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
        let cpu_percent = proc.cpu_usage();
        let memory_mb = proc.memory() as f64 / (1024.0 * 1024.0);

        let path_lower = exe_path.to_ascii_lowercase();
        let name_lower = name.to_ascii_lowercase();

        let mut is_suspicious = false;
        let mut reason = String::new();

        if path_lower.contains("temp\\") || path_lower.contains("\\tmp") {
            is_suspicious = true;
            reason = "Process binary is executing from a temporary folder.".to_string();
        } else if critical_names.iter().any(|&c| c.eq_ignore_ascii_case(&name_lower)) {
            // Check if critical system process is running from outside System32
            if !path_lower.is_empty() && !path_lower.contains("system32") && !path_lower.contains("syswow64") {
                is_suspicious = true;
                reason = "Masquerading system process running outside System32.".to_string();
            }
        }

        list.push(ProcessItem {
            pid: pid.as_u32(),
            name,
            exe_path,
            cpu_percent,
            memory_mb,
            is_suspicious,
            risk_reason: reason,
        });
    }

    list.sort_by(|a, b| {
        b.is_suspicious
            .cmp(&a.is_suspicious)
            .then_with(|| b.memory_mb.partial_cmp(&a.memory_mb).unwrap_or(std::cmp::Ordering::Equal))
    });

    list
}
