use crate::models::OpenPort;
use std::net::{TcpStream, ToSocketAddrs};
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::time::Duration;
use sysinfo::{Pid, System};

const CREATE_NO_WINDOW: u32 = 0x08000000;

pub fn list_active_connections() -> Vec<OpenPort> {
    let mut results = Vec::new();
    let mut sys = System::new_all();
    sys.refresh_all();

    let output = match Command::new("netstat")
        .args(["-ano"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return results,
    };

    let mut seen = std::collections::HashSet::new();

    for line in output.lines() {
        let line = line.trim();
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let proto = parts[0].to_ascii_uppercase();
        if proto != "TCP" && proto != "UDP" {
            continue;
        }

        let (local_addr, remote_addr, state, pid_str) = if proto == "TCP" && parts.len() >= 5 {
            (parts[1], parts[2], parts[3], parts[4])
        } else if proto == "UDP" && parts.len() >= 4 {
            (parts[1], parts[2], "LISTENING", parts[3])
        } else {
            continue;
        };

        let pid: Option<u32> = pid_str.parse().ok();

        // Parse local IP and port
        let (local_ip, port) = parse_host_port(local_addr);
        if port == 0 {
            continue;
        }

        let key = format!("{}:{}:{:?}", proto, port, pid);
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);

        let (remote_ip, remote_port) = parse_host_port(remote_addr);

        // Resolve process info
        let (pname, ppath) = if let Some(p) = pid {
            if let Some(proc) = sys.process(Pid::from(p as usize)) {
                let name = proc.name().to_string_lossy().to_string();
                let path = proc.exe().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
                (name, path)
            } else {
                (format!("Process ({})", p), String::new())
            }
        } else {
            ("System / Kernel".to_string(), String::new())
        };

        // Check if port is in risky port catalog
        let (is_risky, service, severity, desc, rec) = evaluate_port_risk(port);

        results.push(OpenPort {
            protocol: proto,
            local_ip,
            port,
            remote_ip,
            remote_port,
            status: state.to_string(),
            pid,
            process_name: pname,
            exe_path: ppath,
            is_risky,
            service_name: service,
            severity,
            description: desc,
            recommendation: rec,
        });
    }

    // Sort: risky ports first, then listening state
    results.sort_by(|a, b| {
        b.is_risky
            .cmp(&a.is_risky)
            .then_with(|| (a.status == "LISTENING").cmp(&(b.status == "LISTENING")).reverse())
            .then_with(|| a.port.cmp(&b.port))
    });

    results
}

fn parse_host_port(addr: &str) -> (String, u16) {
    if let Some(idx) = addr.rfind(':') {
        let host = &addr[..idx];
        let port_str = &addr[idx + 1..];
        let port: u16 = port_str.parse().unwrap_or(0);
        (host.trim_matches('[').trim_matches(']').to_string(), port)
    } else {
        (addr.to_string(), 0)
    }
}

fn evaluate_port_risk(port: u16) -> (bool, String, String, String, String) {
    match port {
        21 => (
            true,
            "FTP (File Transfer)".to_string(),
            "High".to_string(),
            "Unencrypted legacy file transfer protocol vulnerable to packet sniffing and credential theft.".to_string(),
            "Disable FTP service and replace with SFTP or FTPS with TLS 1.3.".to_string(),
        ),
        23 => (
            true,
            "Telnet".to_string(),
            "Critical".to_string(),
            "Unencrypted plaintext remote terminal service transmitting keystrokes and credentials in cleartext.".to_string(),
            "Immediately shut down Telnet server and migrate to SSHv2.".to_string(),
        ),
        135 => (
            true,
            "Microsoft RPC".to_string(),
            "High".to_string(),
            "Windows Remote Procedure Call endpoint mapper widely targeted for remote code execution and lateral movement.".to_string(),
            "Block inbound RPC from public networks using Windows Firewall.".to_string(),
        ),
        137 | 138 | 139 => (
            true,
            "NetBIOS Name / Datagram".to_string(),
            "Medium".to_string(),
            "Legacy NetBIOS protocol susceptible to NBNS spoofing and credential relay attacks.".to_string(),
            "Disable NetBIOS over TCP/IP in network adapter properties.".to_string(),
        ),
        445 => (
            true,
            "SMB / Windows Shares".to_string(),
            "Critical".to_string(),
            "Server Message Block file sharing, primary target of WannaCry, NotPetya, and EternalBlue exploits.".to_string(),
            "Never expose port 445 to internet. Restrict SMB access strictly to trusted local subnets.".to_string(),
        ),
        3389 => (
            true,
            "Remote Desktop Protocol (RDP)".to_string(),
            "High".to_string(),
            "Windows Remote Desktop service frequently targeted by brute-force bots and BlueKeep vulnerability.".to_string(),
            "Enforce Network Level Authentication (NLA), change default port, and require VPN for access.".to_string(),
        ),
        5900 => (
            true,
            "VNC Remote Desktop".to_string(),
            "High".to_string(),
            "Virtual Network Computing service often deployed with weak or bypassable authentication.".to_string(),
            "Tunnel VNC through SSH or disable external internet exposure.".to_string(),
        ),
        8080 => (
            true,
            "HTTP-Alt / Proxy".to_string(),
            "Low".to_string(),
            "Common alternate HTTP web server or development proxy listener.".to_string(),
            "Verify identity of owning process to confirm authorized software.".to_string(),
        ),
        _ => (
            false,
            format!("Port {}", port),
            "None".to_string(),
            "Standard active network port.".to_string(),
            "".to_string(),
        ),
    }
}

pub fn kill_process(pid: u32) -> Result<String, String> {
    let output = Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to execute taskkill: {}", e))?;

    if output.status.success() {
        Ok(format!("Process {} terminated successfully.", pid))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

pub fn add_firewall_block_rule(port: u16, protocol: &str) -> Result<String, String> {
    let rule_name = format!("Fikrado_Security_Block_{}_{}", protocol, port);
    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", rule_name),
            "dir=in",
            "action=block",
            &format!("protocol={}", protocol),
            &format!("localport={}", port),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to execute netsh: {}", e))?;

    if output.status.success() {
        Ok(format!("Inbound firewall rule '{}' added successfully.", rule_name))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

pub fn scan_remote_port_range(host: &str, ports: &[u16]) -> Vec<OpenPort> {
    let mut results = Vec::new();

    for &port in ports {
        let addr_str = format!("{}:{}", host, port);
        if let Ok(mut addrs) = addr_str.to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                if TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok() {
                    let (is_risky, service, severity, desc, rec) = evaluate_port_risk(port);
                    results.push(OpenPort {
                        protocol: "TCP".to_string(),
                        local_ip: host.to_string(),
                        port,
                        remote_ip: host.to_string(),
                        remote_port: port,
                        status: "OPEN".to_string(),
                        pid: None,
                        process_name: "Remote Target".to_string(),
                        exe_path: "".to_string(),
                        is_risky,
                        service_name: service,
                        severity,
                        description: desc,
                        recommendation: rec,
                    });
                }
            }
        }
    }

    results
}
