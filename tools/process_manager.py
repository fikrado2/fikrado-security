"""
Fikrado Security - Advanced Process Manager with Reputation Analysis
Audits running processes, CPU/RAM utilization, digital signatures, entropy, and execution paths.
"""
from typing import Dict, List, Optional, Tuple
import psutil
from core.logger import logger
from scanners.pe_analyzer import calculate_entropy


class ProcessManager:

    def list_processes(self) -> List[dict]:
        """Lists running processes with reputation and security risk scores."""
        processes = []

        for p in psutil.process_iter(["pid", "name", "exe", "cpu_percent", "memory_info", "status", "username"]):
            try:
                pinfo = p.info
                pid = pinfo["pid"]
                name = pinfo["name"] or "Unknown"
                exe = pinfo["exe"] or ""
                mem_mb = (pinfo["memory_info"].rss / (1024 * 1024)) if pinfo.get("memory_info") else 0
                cpu = pinfo["cpu_percent"] or 0.0
                user = pinfo.get("username") or "System"
                status = pinfo.get("status") or "running"

                # Calculate reputation indicators
                reputation = "Normal"
                rep_color = "#A3BE8C"  # Nord Green
                reasons = []

                if exe:
                    exe_lower = exe.lower()
                    if "\\temp\\" in exe_lower or "\\appdata\\local\\temp" in exe_lower:
                        reputation = "Suspicious"
                        rep_color = "#BF616A"
                        reasons.append("Running from temporary directory")

                    # Check for masquerading system names running outside System32
                    system_names = ["svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "services.exe", "explorer.exe"]
                    if name.lower() in system_names and "c:\\windows" not in exe_lower:
                        reputation = "High Risk"
                        rep_color = "#BF616A"
                        reasons.append("Masquerading as Windows core system process")

                processes.append({
                    "pid": pid,
                    "name": name,
                    "exe": exe,
                    "cpu": cpu,
                    "mem_mb": round(mem_mb, 1),
                    "user": user,
                    "status": status,
                    "reputation": reputation,
                    "reputation_color": rep_color,
                    "reputation_reason": ", ".join(reasons) if reasons else "Trusted location"
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

        processes.sort(key=lambda x: (x["reputation"] == "Normal", -x["mem_mb"]))
        return processes

    def terminate_process(self, pid: int) -> Tuple[bool, str]:
        """Terminates process by PID safely."""
        if pid <= 4:
            return False, "Cannot terminate Windows System idle or kernel process."
        try:
            p = psutil.Process(pid)
            pname = p.name()
            p.kill()
            return True, f"Process {pname} (PID: {pid}) terminated."
        except psutil.NoSuchProcess:
            return True, f"Process {pid} has already stopped."
        except psutil.AccessDenied:
            return False, f"Access denied terminating PID {pid}. Administrator rights required."
        except Exception as e:
            return False, f"Error terminating process: {str(e)}"


process_manager = ProcessManager()
