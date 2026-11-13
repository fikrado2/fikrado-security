use std::os::windows::process::CommandExt;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct TerminalCommandDef {
    pub category: String,
    pub name: String,
    pub cmd: String,
    pub desc: String,
}

pub fn get_blueteam_commands() -> Vec<TerminalCommandDef> {
    vec![
        TerminalCommandDef {
            category: "Network Recon".to_string(),
            name: "Listening TCP & UDP Sockets".to_string(),
            cmd: "netstat -ano".to_string(),
            desc: "Display all active listening ports with owning process identifiers.".to_string(),
        },
        TerminalCommandDef {
            category: "Network Recon".to_string(),
            name: "Active Network Interfaces".to_string(),
            cmd: "ipconfig /all".to_string(),
            desc: "Full network interface configuration and DNS server mappings.".to_string(),
        },
        TerminalCommandDef {
            category: "Network Recon".to_string(),
            name: "DNS Cache Flush".to_string(),
            cmd: "ipconfig /flushdns".to_string(),
            desc: "Purges local DNS resolver cache to eliminate poisoned DNS entries.".to_string(),
        },
        TerminalCommandDef {
            category: "System Hardening".to_string(),
            name: "Query Running Services".to_string(),
            cmd: "powershell -NoProfile -Command \"Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object -First 20 Name, DisplayName\"".to_string(),
            desc: "List active Windows system services.".to_string(),
        },
        TerminalCommandDef {
            category: "Persistence Audit".to_string(),
            name: "Registry Autostart Keys".to_string(),
            cmd: "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            desc: "Inspect machine-wide startup persistence entries in the Windows registry.".to_string(),
        },
        TerminalCommandDef {
            category: "Vulnerability Audit".to_string(),
            name: "Installed Windows Hotfixes".to_string(),
            cmd: "powershell -NoProfile -Command \"Get-HotFix | Select-Object -First 10 HotFixID, InstalledOn, Description\"".to_string(),
            desc: "Query recently installed Microsoft security patches and KBs.".to_string(),
        },
        TerminalCommandDef {
            category: "Endpoint Defense".to_string(),
            name: "Microsoft Defender Status".to_string(),
            cmd: "powershell -NoProfile -Command \"Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureVersion\"".to_string(),
            desc: "Check active Microsoft Defender antivirus and signature versions.".to_string(),
        },
    ]
}

pub fn execute_terminal_cmd(command_line: &str) -> (bool, String) {
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", command_line])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            let combined = if !stderr.is_empty() {
                format!("{}\n[STDERR]\n{}", stdout, stderr)
            } else {
                stdout
            };
            (o.status.success(), combined)
        }
        Err(e) => (false, format!("Failed to launch process: {}", e)),
    }
}
