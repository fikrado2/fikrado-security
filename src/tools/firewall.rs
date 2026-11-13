use std::os::windows::process::CommandExt;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct FirewallProfileStatus {
    pub domain_enabled: bool,
    pub private_enabled: bool,
    pub public_enabled: bool,
}

pub fn get_firewall_status() -> FirewallProfileStatus {
    let output = Command::new("netsh")
        .args(["advfirewall", "show", "allprofiles", "state"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let mut domain = true;
    let mut private = true;
    let mut public = true;

    if let Ok(o) = output {
        let text = String::from_utf8_lossy(&o.stdout);
        let mut current_profile = "";
        for line in text.lines() {
            let line = line.trim();
            if line.contains("Domain Profile") {
                current_profile = "domain";
            } else if line.contains("Private Profile") {
                current_profile = "private";
            } else if line.contains("Public Profile") {
                current_profile = "public";
            } else if line.starts_with("State") {
                let is_on = line.to_ascii_uppercase().contains("ON");
                match current_profile {
                    "domain" => domain = is_on,
                    "private" => private = is_on,
                    "public" => public = is_on,
                    _ => {}
                }
            }
        }
    }

    FirewallProfileStatus {
        domain_enabled: domain,
        private_enabled: private,
        public_enabled: public,
    }
}

pub fn set_firewall_profile(profile: &str, enable: bool) -> Result<String, String> {
    let state_str = if enable { "on" } else { "off" };
    let output = Command::new("netsh")
        .args(["advfirewall", "set", profile, "state", state_str])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        Ok(format!("Firewall profile {} set to {}.", profile, state_str))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

pub fn enable_all_profiles() -> Result<String, String> {
    let output = Command::new("netsh")
        .args(["advfirewall", "set", "allprofiles", "state", "on"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        Ok("All Windows Firewall profiles (Domain, Private, Public) successfully enabled.".to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}
