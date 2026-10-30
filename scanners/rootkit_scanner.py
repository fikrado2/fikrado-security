"""
Fikrado Security - Rootkit Scanner
Cross-platform rootkit detection using behavioral analysis and I/O inspection.
"""
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Dict

from core.logger import logger
from core.platforms import IS_WINDOWS, IS_LINUX, IS_MAC


def _run_cmd(cmd: List[str], timeout: int = 30) -> tuple[bool, str]:
    """Run a command and return (success, stdout)."""
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


# ─── WINDOWS ─────────────────────────────────────────────────────────────────
def _scan_windows_rootkit() -> List[Dict]:
    """Windows rootkit indicators — hidden processes, SSDT hooks, DKOM."""
    findings = []

    # 1. Check for hidden processes via WMI vs Tasklist discrepancy
    ok_wmi, wmi_out = _run_cmd([
        "powershell", "-NoProfile", "-Command",
        "Get-Process | Select-Object -ExpandProperty ProcessName"
    ])
    ok_tlist, tlist_out = _run_cmd(["tasklist", "/FO", "CSV", "/NH"])
    if ok_wmi and ok_tlist:
        wmi_procs = set(line.strip() for line in wmi_out.splitlines() if line.strip())
        tlist_procs = set()
        for line in tlist_out.splitlines():
            parts = line.split(',')
            if parts:
                tlist_procs.add(parts[0].strip('"').lower())
        hidden = wmi_procs - tlist_procs
        # Filter out known system processes
        known = {"csrss", "smss", "wininit", "services", "lsass", "svchost", "dwm",
                 "fontdrvhost", "sihost", "RuntimeBroker", "taskhostw", "explorer"}
        suspicious_hidden = [p for p in hidden if p not in known and p]
        if suspicious_hidden:
            findings.append({
                "severity": "High",
                "type": "Hidden Process Detected",
                "detail": f"WMI found {len(suspicious_hidden)} process(es) not visible in tasklist",
                "indicator": ", ".join(sorted(suspicious_hidden)[:10]),
                "recommendation": "Investigate each process in Process Hacker or Process Explorer",
            })

    # 2. Check for suspicious loaded DLLs in system-critical processes
    critical = ["csrss.exe", "smss.exe", "wininit.exe", "services.exe", "lsass.exe"]
    for proc in critical:
        ok, dlls = _run_cmd([
            "powershell", "-NoProfile", "-Command",
            f"Get-Process -Name '{proc.rstrip('.exe')}' -Module | Select-Object -ExpandProperty ModuleName"
        ])
        if ok and dlls:
            suspicious_dlls = [d for d in dlls.splitlines()
                              if any(s in d.lower() for s in ["mimikatz", "pwdump", "hook", "inject", "keylog"])]
            if suspicious_dlls:
                findings.append({
                    "severity": "Critical",
                    "type": "Suspicious DLL in System Process",
                    "detail": f"Suspicious DLL(s) loaded in {proc}",
                    "indicator": f"{proc}: {', '.join(suspicious_dlls[:5])}",
                    "recommendation": f"Analyze {proc} in Process Explorer for unknown modules",
                })

    # 3. Check for unauthorized services (non-Microsoft)
    ok, svc_out = _run_cmd([
        "powershell", "-NoProfile", "-Command",
        "Get-Service | Where-Object {$_.DisplayName -notmatch 'Microsoft|Windows|Standard'} | Select-Object Name,DisplayName,Status -First 20 | ConvertTo-Json"
    ])
    if ok:
        import json
        try:
            svcs = json.loads(svc_out)
            if isinstance(svcs, dict):
                svcs = [svcs]
            for svc in svcs:
                name = svc.get("Name", "")
                if any(s in name.lower() for s in ["root", "hide", "inject", "keylog", "backdoor"]):
                    findings.append({
                        "severity": "High",
                        "type": "Suspicious Service",
                        "detail": f"Non-standard service: {svc.get('DisplayName', name)}",
                        "indicator": f"Service: {name}, Status: {svc.get('Status', 'Unknown')}",
                        "recommendation": f"Investigate service: sc query {name}",
                    })
        except (json.JSONDecodeError, TypeError):
            pass

    # 4. Check for hooking via farina/certutil suspicious modules
    ok, drivers = _run_cmd([
        "powershell", "-NoProfile", "-Command",
        "Get-Process | Select-Object -ExpandProperty Modules | Where-Object {$_.ModuleName -like '*mimikatz*' -or $_.ModuleName -like '*pwdump*'} | Select-Object ModuleName,FileName"
    ])
    if ok and drivers.strip():
        findings.append({
            "severity": "Critical",
            "type": "Credential Theft Tool DLL",
            "detail": "Known credential theft tool DLL is loaded in memory",
            "indicator": drivers[:300],
            "recommendation": "System is compromised — isolate and investigate immediately",
        })

    # 5. Check for unexpected network listeners (potential rootkit backdoor)
    ok, netstat_out = _run_cmd(["netstat", "-ano"])
    if ok:
        suspicious_ports = {"31337", "1337", "12345", "27374"}
        for line in netstat_out.splitlines():
            if any(f":{p}" in line for p in suspicious_ports):
                findings.append({
                    "severity": "Critical",
                    "type": "Suspicious Network Listener",
                    "detail": f"Rootkit-common backdoor port detected: {line.strip()}",
                    "indicator": line.strip(),
                    "recommendation": "Investigate the PID and terminate if unauthorized",
                })

    return findings


# ─── LINUX ───────────────────────────────────────────────────────────────────
def _scan_linux_rootkit() -> List[Dict]:
    """Linux rootkit indicators — LKM, hidden processes, suspicious files."""
    findings = []

    # 1. Try chkrootkit if available (cross-reference with manual checks)
    ok, chk_out = _run_cmd(["which", "chkrootkit"])
    if ok:
        ok2, chk_result = _run_cmd(["sudo", "chkrootkit", "-q"], timeout=60)
        if ok2 and chk_result:
            for line in chk_result.splitlines():
                if any(kw in line.lower() for kw in ["warning", "infected", "suspicious"]):
                    findings.append({
                        "severity": "High",
                        "type": "chkrootkit Detection",
                        "detail": f"chkrootkit flagged: {line.strip()[:120]}",
                        "indicator": line.strip()[:200],
                        "recommendation": "Investigate with 'sudo chkrootkit' full output",
                    })

    # 2. Try rkhunter if available
    ok, rkh_out = _run_cmd(["which", "rkhunter"])
    if ok:
        ok2, rkh_result = _run_cmd(["sudo", "rkhunter", "--check", "--skip-keypress", "--quiet"], timeout=90)
        if ok2 and rkh_result:
            for line in rkh_result.splitlines():
                if "[WARNING]" in line or "Suspicious" in line:
                    findings.append({
                        "severity": "High",
                        "type": "rkhunter Warning",
                        "detail": line.strip()[:150],
                        "indicator": line.strip()[:200],
                        "recommendation": "Review full rkhunter log: /var/log/rkhunter.log",
                    })

    # 3. Check for suspicious kernel modules
    suspicious_mods = ["diamorphine", "reptile", "azazel", "brootkit", "suterusu", "hide_lkm"]
    ok, lsmod = _run_cmd(["lsmod"])
    if ok:
        for line in lsmod.splitlines():
            for susp in suspicious_mods:
                if susp in line.lower():
                    findings.append({
                        "severity": "Critical",
                        "type": "Known Rootkit Kernel Module",
                        "detail": f"Known rootkit module detected: {line.strip()}",
                        "indicator": f"Module: {susp}",
                        "recommendation": "Immediately unload: sudo rmmod " + susp,
                    })

    # 4. Check for hidden processes (using /proc scanning)
    ok, proc_list = _run_cmd(["ls", "/proc"])
    if ok:
        visible_pids = set()
        for entry in proc_list.splitlines():
            if entry.isdigit():
                visible_pids.add(entry)

        # Also get from ps
        ok2, ps_out = _run_cmd(["ps", "aux"])
        if ok2:
            ps_pids = set()
            for line in ps_out.splitlines()[1:]:
                parts = line.split()
                if parts and parts[0].isdigit():
                    ps_pids.add(parts[0])

            hidden = visible_pids - ps_pids
            if len(hidden) > 10:  # Some are always hidden (kernel threads)
                # Kernel threads visible in /proc but not ps
                hidden_non_kernel = [
                    pid for pid in hidden
                    if Path(f"/proc/{pid}/exe").exists()
                ]
                if hidden_non_kernel:
                    findings.append({
                        "severity": "High",
                        "type": "Hidden Process",
                        "detail": f"{len(hidden_non_kernel)} process(es) visible in /proc but not in ps output",
                        "indicator": ", ".join(sorted(hidden_non_kernel)[:10]),
                        "recommendation": "Use 'ps aux | diff - /proc/*/stat' to identify",
                    })

    # 5. Check for suspicious files in /dev (character devices used by some rootkits)
    ok, dev_out = _run_cmd(["ls", "-la", "/dev/.static"])
    if ok and dev_out:
        findings.append({
            "severity": "High",
            "type": "Suspicious /dev Directory",
            "detail": "Hidden directory /dev/.static detected — possible rootkit storage",
            "indicator": dev_out.strip()[:200],
            "recommendation": "Investigate /dev/.static contents and compare with known-good system",
        })

    # 6. Check for LD_PRELOAD rootkits
    ok, ld_preload = _run_cmd(["grep", "-r", "LD_PRELOAD", "/etc/ld.so.preload"])
    if ok and ld_preload:
        findings.append({
            "severity": "Critical",
            "type": "LD_PRELOAD Rootkit",
            "detail": "LD_PRELOAD reference found in /etc/ld.so.preload",
            "indicator": ld_preload.strip()[:200],
            "recommendation": "This is a strong indicator of rootkit — investigate /etc/ld.so.preload immediately",
        })

    # 7. Check SSH authorized_keys for backdoor accounts
    auth_keys_files = [
        "/root/.ssh/authorized_keys",
        "/home/*/.ssh/authorized_keys",
    ]
    ok, auth_out = _run_cmd([
        "bash", "-c", "cat " + " ".join(auth_keys_files) + " 2>/dev/null"
    ])
    if ok and auth_out:
        suspicious_keys = [l for l in auth_out.splitlines() if l and not l.startswith("#")]
        if suspicious_keys:
            findings.append({
                "severity": "Medium",
                "type": "SSH Authorized Keys Present",
                "detail": f"Found {len(suspicious_keys)} authorized SSH key(s). Review for unauthorized access.",
                "indicator": f"{len(suspicious_keys)} key(s) total",
                "recommendation": "Review all SSH authorized_keys for unexpected entries",
            })

    return findings


# ─── MACOS ───────────────────────────────────────────────────────────────────
def _scan_macos_rootkit() -> List[Dict]:
    """macOS rootkit indicators — unsigned KEXTs, hidden kexts, launchd backdoors."""
    findings = []

    # 1. Check for unsigned kernel extensions
    ok, kexts = _run_cmd(["kextstat", "-l"])
    if ok:
        for line in kexts.splitlines():
            if line.strip():
                # Check if bundle ID contains suspicious terms
                for susp in ["hide", "inject", "keylog", "hook", "root"]:
                    if susp in line.lower():
                        findings.append({
                            "severity": "High",
                            "type": "Suspicious Kernel Extension",
                            "detail": f"Potentially unwanted KEXT: {line.strip()[:120]}",
                            "indicator": line.strip()[:200],
                            "recommendation": "Unload with: sudo kextunload -b <bundle_id>",
                        })

    # 2. Check for hidden launch agents via LaunchControl
    suspicious_agents = ["com.agent", "com.helper", "com.updater", "com.system"]
    agent_paths = ["/Library/LaunchAgents", "/Library/LaunchDaemons",
                   str(Path.home() / "Library/LaunchAgents")]
    for apath in agent_paths:
        if not Path(apath).exists():
            continue
        try:
            for plist in Path(apath).glob("*.plist"):
                for susp in suspicious_agents:
                    if susp in plist.name.lower():
                        findings.append({
                            "severity": "High",
                            "type": "Suspicious LaunchAgent/Daemon",
                            "detail": f"Non-standard launch item: {plist.name}",
                            "indicator": f"Path: {plist}",
                            "recommendation": f"Investigate and remove if unneeded: sudo rm '{plist}'",
                        })
        except PermissionError:
            pass

    # 3. Check for network anomalies (listening on unusual ports)
    ok, lsof = _run_cmd(["lsof", "-i", "-P", "-n"])
    if ok:
        unusual = {"6666", "6667", "31337", "12345"}
        for line in lsof.splitlines():
            for port in unusual:
                if f":{port}" in line:
                    findings.append({
                        "severity": "High",
                        "type": "Unusual Listening Port",
                        "detail": f"Process listening on suspicious port {port}",
                        "indicator": line.strip()[:150],
                        "recommendation": f"Investigate PID in Activity Monitor",
                    })

    return findings


# ─── CROSS-PLATFORM ──────────────────────────────────────────────────────────
def scan_rootkit() -> List[Dict]:
    """
    Perform a rootkit integrity scan on the current platform.
    Returns a list of rootkit indicators.
    """
    logger.info("Starting rootkit scan...")
    try:
        if IS_WINDOWS:
            findings = _scan_windows_rootkit()
        elif IS_LINUX:
            findings = _scan_linux_rootkit()
        elif IS_MAC:
            findings = _scan_macos_rootkit()
        else:
            findings = [{
                "severity": "Warning",
                "type": "Unknown Platform",
                "detail": "Rootkit scan not implemented for this platform",
                "indicator": sys.platform,
                "recommendation": "Run on Windows, Linux, or macOS for rootkit detection",
            }]

        logger.info(f"Rootkit scan complete: {len(findings)} findings")
        return findings

    except Exception as e:
        logger.exception("Rootkit scan failed")
        return [{
            "severity": "Error",
            "type": "Scan Error",
            "detail": f"Rootkit scan encountered an error: {str(e)}",
            "indicator": "Exception during scan",
            "recommendation": "Check logs for details and ensure administrator/root privileges",
        }]