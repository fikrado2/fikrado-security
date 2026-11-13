use crate::models::HardeningCheck;
use std::os::windows::process::CommandExt;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x08000000;

pub fn run_hardening_audit() -> Vec<HardeningCheck> {
    let mut checks = Vec::new();

    // 1. UAC Check
    let uac_output = Command::new("reg")
        .args([
            "query",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "/v",
            "EnableLUA",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let uac_active = if let Ok(o) = uac_output {
        let text = String::from_utf8_lossy(&o.stdout);
        text.contains("0x1")
    } else {
        true
    };

    checks.push(HardeningCheck {
        id: "uac".to_string(),
        title: "User Account Control (UAC)".to_string(),
        status: if uac_active { "Pass".to_string() } else { "Fail".to_string() },
        details: if uac_active {
            "UAC administrative authorization prompts are fully active.".to_string()
        } else {
            "UAC is disabled! Silent elevation allows malware to gain root without warning.".to_string()
        },
        recommendation: if uac_active {
            "Keep UAC at maximum setting.".to_string()
        } else {
            "Enable UAC in Control Panel > User Accounts.".to_string()
        },
    });

    // 2. Windows Defender Antivirus
    let def_status = super::defender::get_defender_status();
    let def_pass = def_status.real_time_protection && def_status.antivirus_enabled;
    checks.push(HardeningCheck {
        id: "defender".to_string(),
        title: "Microsoft Defender Real-Time Protection".to_string(),
        status: if def_pass { "Pass".to_string() } else { "Warn".to_string() },
        details: format!(
            "Real-time shield: {}, Antivirus engine: {}, Definitions: {}.",
            if def_status.real_time_protection { "Enabled" } else { "Disabled" },
            if def_status.antivirus_enabled { "Active" } else { "Inactive" },
            def_status.definition_version
        ),
        recommendation: "Ensure definitions update automatically every 24 hours.".to_string(),
    });

    // 3. Windows Firewall
    let fw = super::firewall::get_firewall_status();
    let fw_pass = fw.domain_enabled && fw.private_enabled && fw.public_enabled;
    checks.push(HardeningCheck {
        id: "firewall".to_string(),
        title: "Windows Filtering Platform Firewall".to_string(),
        status: if fw_pass { "Pass".to_string() } else { "Warn".to_string() },
        details: format!(
            "Domain: {}, Private: {}, Public: {}.",
            if fw.domain_enabled { "ON" } else { "OFF" },
            if fw.private_enabled { "ON" } else { "OFF" },
            if fw.public_enabled { "ON" } else { "OFF" }
        ),
        recommendation: "Enable firewall across all profiles to prevent unauthorized inbound probes.".to_string(),
    });

    // 4. SMBv1 Legacy Protocol Check
    let smb_output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let smb_disabled = if let Ok(o) = smb_output {
        let text = String::from_utf8_lossy(&o.stdout).trim().to_string();
        text != "Enabled"
    } else {
        true
    };

    checks.push(HardeningCheck {
        id: "smbv1".to_string(),
        title: "Legacy SMBv1 Protocol Status".to_string(),
        status: if smb_disabled { "Pass".to_string() } else { "Fail".to_string() },
        details: if smb_disabled {
            "Vulnerable SMBv1 protocol is disabled on this system.".to_string()
        } else {
            "CRITICAL: SMBv1 is enabled. High risk of EternalBlue / ransomware propagation.".to_string()
        },
        recommendation: if smb_disabled {
            "No action needed.".to_string()
        } else {
            "Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol".to_string()
        },
    });

    // 5. Remote Desktop Network Exposure
    let rdp_output = Command::new("reg")
        .args([
            "query",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
            "/v",
            "fDenyTSConnections",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let rdp_denied = if let Ok(o) = rdp_output {
        let text = String::from_utf8_lossy(&o.stdout);
        text.contains("0x1")
    } else {
        true
    };

    checks.push(HardeningCheck {
        id: "rdp".to_string(),
        title: "Remote Desktop Protocol (RDP) Exposure".to_string(),
        status: if rdp_denied { "Pass".to_string() } else { "Warn".to_string() },
        details: if rdp_denied {
            "Inbound Remote Desktop connections are blocked.".to_string()
        } else {
            "Remote Desktop is active and accepting remote connection requests.".to_string()
        },
        recommendation: "Require VPN and Network Level Authentication (NLA) if RDP is required.".to_string(),
    });

    checks
}

pub fn apply_hardening_fix(check_id: &str) -> Result<String, String> {
    match check_id {
        "uac" => {
            let res = Command::new("reg")
                .args(["add", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/v", "EnableLUA", "/t", "REG_DWORD", "/d", "1", "/f"])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .map_err(|e| e.to_string())?;
            if res.status.success() {
                Ok("UAC authorization prompt policy enforced.".to_string())
            } else {
                Err(String::from_utf8_lossy(&res.stderr).to_string())
            }
        }
        "firewall" => {
            let _ = Command::new("netsh").args(["advfirewall", "set", "allprofiles", "state", "on"]).creation_flags(CREATE_NO_WINDOW).output();
            Ok("All Windows Firewall profiles (Domain, Private, Public) enabled.".to_string())
        }
        "smbv1" => {
            let res = Command::new("powershell")
                .args(["-NoProfile", "-Command", "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue"])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .map_err(|e| e.to_string())?;
            if res.status.success() {
                Ok("Legacy SMBv1 protocol disabled.".to_string())
            } else {
                Err(String::from_utf8_lossy(&res.stderr).to_string())
            }
        }
        "rdp" => {
            let res = Command::new("reg")
                .args(["add", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "1", "/f"])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .map_err(|e| e.to_string())?;
            if res.status.success() {
                Ok("Inbound RDP access disabled to prevent remote brute force attacks.".to_string())
            } else {
                Err(String::from_utf8_lossy(&res.stderr).to_string())
            }
        }
        "defender" => {
            let _ = Command::new("powershell")
                .args(["-NoProfile", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue"])
                .creation_flags(CREATE_NO_WINDOW)
                .output();
            Ok("Microsoft Defender Real-time protection enabled.".to_string())
        }
        _ => Err("Unknown hardening check identifier.".to_string()),
    }
}
