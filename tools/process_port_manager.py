"""
Fikrado Security - Cross-Platform Process & Port Manager
Close running applications and scan for open ports with process association.
"""
import os
import signal
import socket
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Optional

from core.logger import logger
from core.platforms import IS_WINDOWS, IS_LINUX, IS_MAC


def _run_cmd(cmd: List[str], timeout: int = 30) -> tuple[bool, str]:
    """Run a command, return (success, stdout)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "LANG": "C", "LC_ALL": "C"}
        )
        return result.returncode == 0, result.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError:
        return False, f"Command not found: {cmd[0]}"
    except Exception as e:
        return False, str(e)


# ─── PROCESS MANAGEMENT ──────────────────────────────────────────────────────
def list_processes() -> List[Dict]:
    """Return list of running processes with security reputation hints."""
    import psutil
    processes = []
    suspicious_names = {
        "mimikatz", "pwdump", "fgdump", "wce.exe", "lazagne",
        "mimicom", "netcat", "nc.exe", "psexec", "psexesvc",
        "vnc", "rdp", "teamviewer", "anydesk",
    }

    for proc in psutil.process_iter(["pid", "name", "exe", "username", "create_time"]):
        try:
            info = proc.info
            name = info.get("name", "unknown") or "unknown"
            exe = info.get("exe") or ""
            pid = info.get("pid", 0) or 0
            username = info.get("username") or "?"
            created = info.get("create_time") or 0

            # Reputation analysis
            name_lower = name.lower()
            if any(s in name_lower for s in suspicious_names):
                rep, reason = "Suspicious", f"Known security tool name: {name}"
            elif not exe or not Path(exe).exists():
                rep, reason = "Unknown", "No executable path found"
            elif os.getpid() == pid:
                rep, reason = "System", "This process"
            elif username in ("SYSTEM", "root", "NT AUTHORITY"):
                rep, reason = "System", f"High-privilege: {username}"
            else:
                rep, reason = "Normal", "Standard user process"

            # CPU and memory
            try:
                p = psutil.Process(pid)
                cpu = round(p.cpu_percent(interval=0.1), 1)
                mem = round(p.memory_info().rss / (1024 * 1024), 1)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cpu, mem = 0.0, 0.0

            processes.append({
                "pid": pid,
                "name": name,
                "exe": exe,
                "reputation": rep,
                "reputation_reason": reason,
                "cpu": cpu,
                "mem_mb": mem,
                "user": username,
                "start_time": created,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return sorted(processes, key=lambda x: x.get("cpu", 0), reverse=True)[:300]


def kill_process(pid: int, force: bool = False) -> tuple[bool, str]:
    """Terminate a process by PID. Returns (success, message)."""
    try:
        import psutil
        proc = psutil.Process(pid)
        name = proc.name()
        # Don't kill our own process
        if pid == os.getpid():
            return False, "Cannot terminate the security scanner itself."
        if proc.username() in ("SYSTEM", "root") and not force:
            return False, f"Refusing to force-kill system process {name} (PID {pid}). Use force=True."
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except psutil.TimeoutExpired:
            proc.kill()
        logger.info(f"Terminated process: {name} (PID {pid})")
        return True, f"Successfully terminated {name} (PID {pid})"
    except psutil.NoSuchProcess:
        return False, f"Process {pid} no longer exists."
    except psutil.AccessDenied:
        return False, f"Access denied: Cannot terminate PID {pid}. Run as Administrator/Root."
    except Exception as e:
        logger.exception(f"Failed to kill PID {pid}")
        return False, f"Failed to terminate PID {pid}: {str(e)}"


def close_app_by_name(name: str) -> tuple[bool, str]:
    """Close all processes matching the given name. Returns (success, message)."""
    import psutil
    killed = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if proc.info["name"].lower() == name.lower():
                pid = proc.info["pid"]
                if pid != os.getpid():
                    proc.terminate()
                    killed.append(str(pid))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    if killed:
        return True, f"Closed processes: {', '.join(killed)}"
    return False, f"No process named '{name}' found."


# ─── PORT SCANNING ──────────────────────────────────────────────────────────
def get_open_ports() -> List[Dict]:
    """Get all open ports with process association. Cross-platform."""
    results = []
    if IS_WINDOWS:
        ok, netstat = _run_cmd(["netstat", "-ano"])
        if ok:
            for line in netstat.splitlines():
                parts = line.split()
                if len(parts) >= 4 and "LISTENING" in line:
                    proto = parts[0].upper()
                    local = parts[1]
                    if ":" in local:
                        addr, port_str = local.rsplit(":", 1)
                        try:
                            port = int(port_str)
                            pid = int(parts[-1]) if parts[-1].isdigit() else 0
                            # Get process name
                            pname = ""
                            try:
                                import psutil
                                pname = psutil.Process(pid).name() if pid else ""
                            except Exception:
                                pass
                            # Determine risk
                            suspicious_ports = {4444, 5555, 6666, 31337, 1337, 12345, 27374}
                            risk = "Normal"
                            if port in suspicious_ports:
                                risk = "Suspicious"
                            if port in (80, 443):
                                risk = "HTTP(S)"
                            results.append({
                                "port": port,
                                "proto": proto,
                                "address": addr,
                                "pid": pid,
                                "process": pname,
                                "state": "LISTENING",
                                "risk": risk,
                            })
                        except (ValueError, IndexError):
                            pass
    elif IS_LINUX:
        # Use ss on Linux (modern, reliable)
        ok, ss_out = _run_cmd(["ss", "-tulnp"])
        if ok:
            for line in ss_out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5 and "LISTEN" in line:
                    try:
                        proto = parts[0].upper().replace("SKC", "TCP")
                        state = parts[1]
                        local = parts[4] if len(parts) > 4 else ""
                        if ":" in local:
                            addr, port_str = local.rsplit(":", 1)
                            try:
                                port = int(port_str)
                                # Extract PID/Program
                                pid_prog = ""
                                for p in parts:
                                    if "/" in p:
                                        pid_prog = p
                                        break
                                risk = "Normal"
                                if port in {4444, 5555, 6666, 31337, 1337}:
                                    risk = "Suspicious"
                                results.append({
                                    "port": port,
                                    "proto": proto,
                                    "address": addr,
                                    "pid": pid_prog,
                                    "process": pid_prog,
                                    "state": state,
                                    "risk": risk,
                                })
                            except (ValueError, IndexError):
                                pass
                    except Exception:
                        pass
    elif IS_MAC:
        ok, lsof_out = _run_cmd(["lsof", "-i", "-P", "-n", "+c0"])
        if ok:
            for line in lsof_out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 9:
                    try:
                        name = parts[0]
                        proto = parts[7].upper() if len(parts) > 7 else "TCP"
                        if "IPv" not in proto:
                            continue
                        proto = "TCP" if "TCP" in parts[7] else "UDP"
                        local = parts[8] if len(parts) > 8 else ""
                        if ":" in local:
                            addr, port_str = local.rsplit(":", 1)
                            try:
                                port = int(port_str)
                                pid = int(parts[1]) if parts[1].isdigit() else 0
                                results.append({
                                    "port": port,
                                    "proto": proto,
                                    "address": addr,
                                    "pid": pid,
                                    "process": name,
                                    "state": "LISTENING",
                                    "risk": "Normal",
                                })
                            except (ValueError, IndexError):
                                pass
                    except Exception:
                        pass
    return results


def close_port(port: int, proto: str = "TCP") -> tuple[bool, str]:
    """Close a listening port by terminating its associated process."""
    ports = get_open_ports()
    matches = [p for p in ports if p["port"] == port and proto.upper() in p["proto"]]
    if not matches:
        return False, f"No {proto} process found listening on port {port}."

    match = matches[0]
    pid = match.get("pid", 0)
    if not pid:
        return False, f"Could not determine PID for port {port}."

    # Try to convert PID if it's in "PID/program" format
    if isinstance(pid, str) and "/" in pid:
        try:
            pid = int(pid.split("/")[0])
        except (ValueError, IndexError):
            return False, f"Could not parse PID from: {pid}"

    try:
        import psutil
        proc = psutil.Process(pid)
        pname = proc.name()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except psutil.TimeoutExpired:
            proc.kill()
        return True, f"Closed port {port}/{proto} (terminated {pname}, PID {pid})"
    except psutil.NoSuchProcess:
        return False, f"Process {pid} no longer exists."
    except psutil.AccessDenied:
        return False, f"Access denied. Run as Administrator/Root to close port {port}."
    except Exception as e:
        return False, f"Failed to close port {port}: {str(e)}"


def kill_port_by_name(port_name: str) -> tuple[bool, str]:
    """Kill processes listening on ports that match a service name."""
    ports = get_open_ports()
    killed = []
    for p in ports:
        if port_name.lower() in p.get("process", "").lower():
            pid = p.get("pid", 0)
            if not pid or pid == "N/A":
                continue
            if isinstance(pid, str) and "/" in pid:
                try:
                    pid = int(pid.split("/")[0])
                except (ValueError, IndexError):
                    continue
            try:
                import psutil
                proc = psutil.Process(pid)
                proc.terminate()
                killed.append(f"{p['process']}({p['port']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    if killed:
        return True, f"Closed: {', '.join(killed)}"
    return False, f"No process matching '{port_name}' found listening on any port."
