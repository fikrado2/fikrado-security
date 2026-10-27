"""
Fikrado Security - Network & Open Port Scanner
Enumerates listening ports, maps PIDs and processes, flags risky services with plain-language alerts,
and provides one-click remediation (Kill Process, Add Firewall Block Rule).
"""
import ipaddress
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple
import psutil
from config.security_rules import RISKY_PORTS
from core.logger import logger


def get_process_details(pid: Optional[int]) -> Tuple[str, str]:
    """Retrieves process name and executable path safely from a PID."""
    if not pid:
        return "System / Kernel", ""
    try:
        p = psutil.Process(pid)
        return p.name(), p.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return f"Process ({pid})", ""
    except Exception:
        return "Unknown", ""


def list_active_connections() -> List[dict]:
    """
    Returns all active listening ports and connections on the local machine
    enriched with process ownership, PID, protocol, and risk assessment.
    """
    results = []
    seen = set()

    try:
        connections = psutil.net_connections(kind="inet")
    except Exception as e:
        logger.warning(f"psutil.net_connections failed: {e}. Falling back to netstat.")
        return _fallback_netstat()

    for conn in connections:
        try:
            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            laddr = conn.laddr
            raddr = conn.raddr
            status = conn.status

            if not laddr:
                continue

            local_ip = laddr.ip
            local_port = laddr.port
            remote_ip = raddr.ip if raddr else ""
            remote_port = raddr.port if raddr else 0
            pid = conn.pid

            # Key for deduplication
            key = (proto, local_port, pid, status)
            if key in seen:
                continue
            seen.add(key)

            pname, ppath = get_process_details(pid)

            # Check if this port is flagged in our RISKY_PORTS catalog
            is_risky = local_port in RISKY_PORTS
            risk_info = RISKY_PORTS.get(local_port, {})
            severity = risk_info.get("severity", "Low") if is_risky else "None"
            desc = risk_info.get("description", "Standard networking port.") if is_risky else "Active connection."
            rec = risk_info.get("recommendation", "") if is_risky else ""

            results.append({
                "protocol": proto,
                "local_ip": local_ip,
                "port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "status": status,
                "pid": pid,
                "process_name": pname,
                "exe_path": ppath,
                "is_risky": is_risky,
                "service_name": risk_info.get("service", f"Port {local_port}"),
                "severity": severity,
                "description": desc,
                "recommendation": rec
            })
        except Exception:
            continue

    # Sort so risky and listening ports appear first
    results.sort(key=lambda x: (not x["is_risky"], x["status"] != "LISTEN", x["port"]))
    return results


def _fallback_netstat() -> List[dict]:
    """Fallback command parser using netstat -ano."""
    results = []
    try:
        res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=8)
        if res.returncode == 0:
            lines = res.stdout.splitlines()
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0] in ("TCP", "UDP"):
                    proto = parts[0]
                    local_addr = parts[1]
                    state = parts[3] if proto == "TCP" and len(parts) >= 5 else ("UDP" if proto == "UDP" else "")
                    pid_str = parts[-1]
                    try:
                        pid = int(pid_str)
                    except ValueError:
                        pid = 0

                    if ":" in local_addr:
                        port_str = local_addr.split(":")[-1]
                        try:
                            port = int(port_str)
                        except ValueError:
                            continue

                        pname, ppath = get_process_details(pid)
                        is_risky = port in RISKY_PORTS
                        risk_info = RISKY_PORTS.get(port, {})

                        results.append({
                            "protocol": proto,
                            "local_ip": local_addr.split(":")[0],
                            "port": port,
                            "remote_ip": "",
                            "remote_port": 0,
                            "status": state,
                            "pid": pid,
                            "process_name": pname,
                            "exe_path": ppath,
                            "is_risky": is_risky,
                            "service_name": risk_info.get("service", f"Port {port}"),
                            "severity": risk_info.get("severity", "Low") if is_risky else "None",
                            "description": risk_info.get("description", "Standard connection"),
                            "recommendation": risk_info.get("recommendation", "")
                        })
    except Exception as e:
        logger.error(f"Fallback netstat failed: {e}")
    return results


def scan_target_port(target_ip: str, port: int, timeout: float = 0.5) -> Optional[dict]:
    """Probes a single socket port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target_ip, port))
        s.close()
        if result == 0:
            risk_info = RISKY_PORTS.get(port, {})
            return {
                "ip": target_ip,
                "port": port,
                "protocol": "TCP",
                "status": "OPEN",
                "service": risk_info.get("service", f"Port {port}"),
                "is_risky": port in RISKY_PORTS,
                "severity": risk_info.get("severity", "Low") if port in RISKY_PORTS else "None",
                "description": risk_info.get("description", "Open network port")
            }
    except Exception:
        pass
    return None


def scan_port_range(target_ip: str, ports: List[int], max_threads: int = 50) -> List[dict]:
    """Scans a list of ports concurrently against a target IP."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scan_target_port, target_ip, port) for port in ports]
        for f in futures:
            res = f.result()
            if res:
                open_ports.append(res)
    return open_ports


def kill_process(pid: int) -> Tuple[bool, str]:
    """Terminates an offending process by PID."""
    if pid <= 4:
        return False, "Cannot terminate Windows System / Idle process."
    try:
        p = psutil.Process(pid)
        pname = p.name()
        p.kill()
        logger.info(f"Terminated process {pname} (PID: {pid}) via Network Scanner action.")
        return True, f"Successfully terminated {pname} (PID: {pid})."
    except psutil.NoSuchProcess:
        return True, f"Process {pid} has already exited."
    except psutil.AccessDenied:
        return False, f"Access denied terminating PID {pid}. Administrator rights required."
    except Exception as e:
        return False, f"Failed to terminate PID {pid}: {str(e)}"


def add_firewall_block_rule(rule_name: str, port: int, protocol: str = "TCP") -> Tuple[bool, str]:
    """Adds a Windows Firewall inbound block rule via netsh advfirewall."""
    try:
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"protocol={protocol}",
            f"localport={port}"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
        if res.returncode == 0 and "Ok." in res.stdout:
            logger.info(f"Added Windows Firewall block rule: {rule_name} on port {port}/{protocol}")
            return True, f"Firewall rule '{rule_name}' successfully added (Blocked {protocol} {port})."
        return False, f"netsh returned error: {res.stderr or res.stdout}"
    except Exception as e:
        return False, f"Failed to execute netsh: {str(e)}"
