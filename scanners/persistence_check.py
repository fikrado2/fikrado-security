"""
Fikrado Security - Persistence & Process Anomaly Inspector
Scans Registry Run/RunOnce, Startup folders, Scheduled Tasks, WMI subscriptions,
and running processes for stealth persistence and suspicious execution chains.
"""
import os
import subprocess
import winreg
from pathlib import Path
from typing import Dict, List
import psutil
from core.logger import logger


class PersistenceInspector:
    """Audits persistence hooks and active process execution chains."""

    def inspect_all(self) -> List[dict]:
        """Runs full suite of persistence and process checks."""
        findings = []
        findings.extend(self.check_registry_persistence())
        findings.extend(self.check_startup_folders())
        findings.extend(self.check_scheduled_tasks())
        findings.extend(self.check_services())
        findings.extend(self.check_wmi_subscriptions())
        findings.extend(self.inspect_running_processes())
        return findings

    def check_registry_persistence(self) -> List[dict]:
        """Inspects Run, RunOnce, and Winlogon keys."""
        findings = []
        reg_targets = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        ]

        for hive, subkey, label in reg_targets:
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                    count = winreg.QueryInfoKey(key)[1]
                    for i in range(count):
                        name, value, _ = winreg.EnumValue(key, i)
                        val_str = str(value).lower()
                        # Suspicious if points to Temp, AppData, or runs script interpreters directly
                        is_suspicious = False
                        reason = ""

                        if "temp\\" in val_str or "\\tmp" in val_str:
                            is_suspicious = True
                            reason = "Persistence binary executes from a temporary folder."
                        elif "powershell" in val_str and ("-enc" in val_str or "-w hidden" in val_str):
                            is_suspicious = True
                            reason = "Persistence entry runs hidden/encoded PowerShell command."
                        elif "certutil" in val_str or "bitsadmin" in val_str:
                            is_suspicious = True
                            reason = "Persistence entry uses LOLBins (Living-off-the-Land binary)."

                        if is_suspicious:
                            findings.append({
                                "engine": "Persistence Inspector",
                                "threat_name": f"Suspicious Registry Startup: {name}",
                                "threat_type": "Trojan",
                                "severity": "High",
                                "description": f"{label} key '{name}' -> '{value}'. Reason: {reason}",
                                "file_path": str(value)
                            })
            except Exception as e:
                logger.debug(f"Could not read {label}: {e}")

        return findings

    def check_startup_folders(self) -> List[dict]:
        """Checks user and common Startup directory files."""
        findings = []
        user_startup = Path(os.getenv("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup"
        common_startup = Path(os.getenv("PROGRAMDATA", "C:/ProgramData")) / "Microsoft/Windows/Start Menu/Programs/Startup"

        for folder in (user_startup, common_startup):
            if folder.exists() and folder.is_dir():
                try:
                    for item in folder.iterdir():
                        if item.is_file():
                            ext = item.suffix.lower()
                            if ext in (".vbs", ".bat", ".cmd", ".ps1", ".hta", ".js"):
                                findings.append({
                                    "engine": "Persistence Inspector",
                                    "threat_name": f"Suspicious Script in Startup Folder: {item.name}",
                                    "threat_type": "Suspicious",
                                    "severity": "Medium",
                                    "description": f"Startup folder contains executable script '{item.name}'.",
                                    "file_path": str(item)
                                })
                except Exception as e:
                    logger.debug(f"Error inspecting startup directory {folder}: {e}")

        return findings

    def check_scheduled_tasks(self) -> List[dict]:
        """Queries Windows Task Scheduler for unusual tasks."""
        findings = []
        try:
            cmd = ["schtasks", "/query", "/fo", "csv", "/v"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            if res.returncode == 0:
                lines = res.stdout.splitlines()
                if len(lines) > 1:
                    import csv
                    import io
                    reader = csv.reader(io.StringIO(res.stdout))
                    header = next(reader, None)
                    if header:
                        task_name_idx = 0
                        task_run_idx = -1
                        for idx, col in enumerate(header):
                            if "Task To Run" in col:
                                task_run_idx = idx
                                break

                        if task_run_idx != -1:
                            for row in reader:
                                if len(row) > task_run_idx:
                                    tname = row[task_name_idx]
                                    trun = row[task_run_idx].lower()
                                    if "\\temp\\" in trun or ("powershell" in trun and "-enc" in trun):
                                        findings.append({
                                            "engine": "Persistence Inspector",
                                            "threat_name": f"Suspicious Scheduled Task: {tname}",
                                            "threat_type": "Trojan",
                                            "severity": "High",
                                            "description": f"Scheduled task '{tname}' executes: {trun}",
                                            "file_path": trun
                                        })
        except Exception as e:
            logger.debug(f"Scheduled tasks inspection skipped: {e}")

        return findings

    def check_services(self) -> List[dict]:
        """Inspects non-standard Windows services running from user directories."""
        findings = []
        try:
            for s in psutil.win_service_iter():
                try:
                    s_info = s.as_dict()
                    bin_path = (s_info.get("binpath") or "").lower()
                    if bin_path:
                        if "\\appdata\\local\\temp" in bin_path or "\\users\\" in bin_path:
                            findings.append({
                                "engine": "Persistence Inspector",
                                "threat_name": f"Anomalous Service Binary: {s_info.get('name')}",
                                "threat_type": "Backdoor",
                                "severity": "High",
                                "description": f"Windows service '{s_info.get('name')}' executes from user directory: {bin_path}",
                                "file_path": bin_path
                            })
                except Exception:
                    continue
        except Exception as e:
            logger.debug(f"Service audit error: {e}")

        return findings

    def check_wmi_subscriptions(self) -> List[dict]:
        """Queries WMI root\\subscription for persistence events."""
        findings = []
        try:
            cmd = ["powershell", "-NoProfile", "-Command", "Get-CimInstance -Namespace root\\subscription -ClassName __EventConsumer | Select-Object Name, CommandLineTemplate | ConvertTo-Json"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
            if res.returncode == 0 and res.stdout.strip():
                import json
                try:
                    data = json.loads(res.stdout)
                    items = [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])
                    for it in items:
                        c_name = it.get("Name", "Unknown")
                        c_cmd = str(it.get("CommandLineTemplate", ""))
                        if c_cmd and ("temp" in c_cmd.lower() or "powershell" in c_cmd.lower()):
                            findings.append({
                                "engine": "Persistence Inspector",
                                "threat_name": f"WMI Event Consumer Persistence: {c_name}",
                                "threat_type": "Trojan",
                                "severity": "High",
                                "description": f"WMI consumer '{c_name}' triggers command: {c_cmd}",
                                "file_path": c_cmd
                            })
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"WMI subscription check skipped: {e}")

        return findings

    def inspect_running_processes(self) -> List[dict]:
        """
        Inspects running processes for:
        - Executing from Temp directories with active network connections
        - Unusual parent-child relationships (e.g. Office apps spawning PowerShell/Cmd)
        """
        findings = []
        suspicious_parents = {
            "winword.exe": ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
            "excel.exe": ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
            "powerpnt.exe": ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"],
            "outlook.exe": ["powershell.exe", "cmd.exe", "wscript.exe", "certutil.exe"]
        }

        # Build PID lookup
        proc_lookup = {}
        for p in psutil.process_iter(["pid", "name", "ppid", "exe"]):
            try:
                proc_lookup[p.info["pid"]] = p.info
            except Exception:
                continue

        for pid, pinfo in proc_lookup.items():
            try:
                pname = (pinfo.get("name") or "").lower()
                pexe = (pinfo.get("exe") or "").lower()
                ppid = pinfo.get("ppid")

                # Check 1: Unusual Parent-Child
                if ppid and ppid in proc_lookup:
                    parent_name = (proc_lookup[ppid].get("name") or "").lower()
                    if parent_name in suspicious_parents:
                        if pname in suspicious_parents[parent_name]:
                            findings.append({
                                "engine": "Process Chain Inspector",
                                "threat_name": f"Unusual Process Chain ({parent_name} -> {pname})",
                                "threat_type": "Trojan",
                                "severity": "Critical",
                                "description": f"Productivity application '{parent_name}' spawned command interpreter '{pname}'. Classic macro/exploit pattern.",
                                "file_path": pexe or pname
                            })

                # Check 2: Process running from Temp
                if pexe and ("\\appdata\\local\\temp" in pexe or "\\temp\\" in pexe):
                    # Check if process has open network sockets
                    try:
                        p_obj = psutil.Process(pid)
                        conns = p_obj.net_connections()
                        if conns:
                            findings.append({
                                "engine": "Process Inspector",
                                "threat_name": f"Temp Process with Network Activity ({pname})",
                                "threat_type": "Suspicious",
                                "severity": "High",
                                "description": f"Process '{pname}' is running out of a Temp folder and has active network sockets.",
                                "file_path": pexe
                            })
                    except Exception:
                        pass

            except Exception:
                continue

        return findings


persistence_inspector = PersistenceInspector()
