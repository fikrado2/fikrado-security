use crate::models::NetworkDiagResult;
use std::os::windows::process::CommandExt;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x08000000;

pub fn get_network_diagnostics() -> NetworkDiagResult {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetIPConfiguration | Select-Object -First 1 | ForEach-Object { @{ Adapter = $_.InterfaceAlias; IP = ($_.IPv4Address.IPAddress); Gateway = ($_.IPv4DefaultGateway.NextHop); DNS = ($_.DNSServer.ServerAddresses) } } | ConvertTo-Json -Compress",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let mut adapter_name = "Ethernet / Wi-Fi".to_string();
    let mut ip_address = "127.0.0.1".to_string();
    let mut gateway = "N/A".to_string();
    let mut dns_servers = Vec::new();

    if let Ok(o) = output {
        let text = String::from_utf8_lossy(&o.stdout);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(a) = val["Adapter"].as_str() {
                adapter_name = a.to_string();
            }
            if let Some(ip) = val["IP"].as_str() {
                ip_address = ip.to_string();
            }
            if let Some(gw) = val["Gateway"].as_str() {
                gateway = gw.to_string();
            }
            if let Some(arr) = val["DNS"].as_array() {
                for d in arr {
                    if let Some(ds) = d.as_str() {
                        dns_servers.push(ds.to_string());
                    }
                }
            } else if let Some(ds) = val["DNS"].as_str() {
                dns_servers.push(ds.to_string());
            }
        }
    }

    if dns_servers.is_empty() {
        dns_servers.push("1.1.1.1".to_string());
        dns_servers.push("8.8.8.8".to_string());
    }

    // Query external public IP with quick timeout
    let public_ip = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_millis(1500))
        .build()
        .ok()
        .and_then(|client| client.get("https://api.ipify.org").send().ok())
        .and_then(|resp| resp.text().ok())
        .unwrap_or_else(|| "Offline / Hidden".to_string());

    NetworkDiagResult {
        adapter_name,
        ip_address,
        mac_address: "Protected".to_string(),
        dns_servers,
        gateway,
        public_ip,
    }
}

pub fn flush_dns_cache() -> Result<String, String> {
    let output = Command::new("ipconfig")
        .arg("/flushdns")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to flush DNS: {}", e))?;

    if output.status.success() {
        Ok("DNS Resolver Cache successfully flushed.".to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}
