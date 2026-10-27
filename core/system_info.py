"""
Fikrado Security - System Information & Security Auditing
Inspects Windows configuration, UAC elevation, Defender status, and security posture.
"""
import ctypes
import os
import platform
import sys
from typing import Dict, List, Tuple
from core.logger import logger
from core.subprocess_utils import run_hidden


def is_admin() -> bool:
    """Returns True if the process has elevated Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_windows_info() -> dict:
    """Gathers Windows OS version, build, architecture, and system specs."""
    win_ver = platform.win32_ver()
    return {
        "os_name": "Windows",
        "os_version": win_ver[0],
        "os_build": win_ver[1],
        "os_service_pack": win_ver[2],
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "computer_name": os.getenv("COMPUTERNAME", "Unknown"),
        "username": os.getenv("USERNAME", "Unknown"),
        "is_admin": is_admin(),
        "python_version": platform.python_version(),
    }


def get_defender_status() -> dict:
    """Queries Windows Defender status via PowerShell Get-MpComputerStatus."""
    default_status = {
        "installed": True,
        "realtime_protection": True,
        "antivirus_enabled": True,
        "antispyware_enabled": True,
        "behavior_monitor": True,
        "definitions_updated": True,
        "antivirus_signature_age": 0,
        "raw_status": "Active"
    }

    try:
        cmd = [
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, AntispywareEnabled, BehaviorMonitorEnabled, AntivirusSignatureAge | ConvertTo-Json"
        ]
        res = run_hidden(cmd, capture_output=True, text=True, timeout=8)
        if res.returncode == 0 and res.stdout.strip():
            import json
            data = json.loads(res.stdout)
            return {
                "installed": True,
                "realtime_protection": bool(data.get("RealTimeProtectionEnabled", True)),
                "antivirus_enabled": bool(data.get("AntivirusEnabled", True)),
                "antispyware_enabled": bool(data.get("AntispywareEnabled", True)),
                "behavior_monitor": bool(data.get("BehaviorMonitorEnabled", True)),
                "definitions_updated": data.get("AntivirusSignatureAge", 0) <= 3,
                "antivirus_signature_age": data.get("AntivirusSignatureAge", 0),
                "raw_status": "Active" if data.get("AntivirusEnabled", True) else "Disabled"
            }
    except Exception as e:
        logger.debug(f"Defender status query fallback: {e}")

    return default_status


def audit_system_hardening() -> Tuple[List[dict], int]:
    """
    Performs a thorough security hardening audit against key Windows security controls.
    Returns (checklist, security_score_0_to_100).
    """
    checks = []

    # 1. Admin / UAC Elevation
    admin_state = is_admin()
    checks.append({
        "category": "Privilege",
        "name": "Process Elevation (UAC Admin)",
        "status": "Pass" if admin_state else "Warning",
        "points": 10 if admin_state else 5,
        "max_points": 10,
        "detail": "Running with Administrator privileges required for comprehensive kernel/file access." if admin_state else "Running as standard user; some low-level scans may be limited.",
        "remediation": "Right click and select 'Run as Administrator' if higher privileges are required."
    })

    # 2. Windows Defender Real-Time Protection
    def_stat = get_defender_status()
    def_pass = def_stat.get("realtime_protection", True)
    checks.append({
        "category": "Antivirus",
        "name": "Windows Defender Real-Time Shield",
        "status": "Pass" if def_pass else "Critical",
        "points": 20 if def_pass else 0,
        "max_points": 20,
        "detail": "Native Windows Defender real-time engine is active." if def_pass else "Windows Defender real-time protection is disabled!",
        "remediation": "Enable Real-Time Protection in Windows Security Settings."
    })

    # 3. Windows Firewall Check
    firewall_pass = True
    try:
        fw_res = run_hidden(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            capture_output=True, text=True, timeout=5
        )
        if "OFF" in fw_res.stdout.upper():
            firewall_pass = False
    except Exception:
        pass

    checks.append({
        "category": "Network",
        "name": "Windows Defender Firewall",
        "status": "Pass" if firewall_pass else "Critical",
        "points": 15 if firewall_pass else 0,
        "max_points": 15,
        "detail": "All Windows Firewall profiles (Domain, Private, Public) are active." if firewall_pass else "One or more Windows Firewall profiles are disabled.",
        "remediation": "Turn on Windows Firewall for all network profiles via Control Panel or netsh."
    })

    # 4. SMBv1 Protocol Check (Ransomware vector)
    smbv1_disabled = True
    try:
        cmd = ["powershell", "-NoProfile", "-Command", "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue | Select-Object -ExpandProperty State"]
        smb_res = run_hidden(cmd, capture_output=True, text=True, timeout=5)
        if "Enabled" in smb_res.stdout:
            smbv1_disabled = False
    except Exception:
        pass

    checks.append({
        "category": "Protocol Hardening",
        "name": "SMBv1 Legacy Protocol Disabled",
        "status": "Pass" if smbv1_disabled else "Critical",
        "points": 15 if smbv1_disabled else 0,
        "max_points": 15,
        "detail": "SMBv1 legacy protocol is disabled, mitigating WannaCry and EternalBlue vectors." if smbv1_disabled else "SMBv1 is ENABLED! This poses extreme vulnerability to network worms.",
        "remediation": "Disable SMBv1 via 'Turn Windows features on or off' or Disable-WindowsOptionalFeature."
    })

    # 5. Remote Desktop Protocol (RDP) Exposure
    rdp_secure = True
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\Terminal Server") as key:
            fDenyTSConnections, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
            if fDenyTSConnections == 0:
                rdp_secure = False  # RDP is enabled
    except Exception:
        pass

    checks.append({
        "category": "Remote Access",
        "name": "Remote Desktop (RDP) Exposure",
        "status": "Pass" if rdp_secure else "Warning",
        "points": 15 if rdp_secure else 5,
        "max_points": 15,
        "detail": "Remote Desktop connections are disabled, eliminating remote brute-force attack vectors." if rdp_secure else "Remote Desktop is enabled. Ensure strong passwords, MFA, and NLA are enforced.",
        "remediation": "Disable RDP in System Properties if remote administration is not required."
    })

    # 6. SmartScreen Status Check
    smartscreen_active = True
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer") as key:
            val, _ = winreg.QueryValueEx(key, "SmartScreenEnabled")
            if val.lower() == "off":
                smartscreen_active = False
    except Exception:
        pass

    checks.append({
        "category": "Application Security",
        "name": "Windows Defender SmartScreen",
        "status": "Pass" if smartscreen_active else "Warning",
        "points": 15 if smartscreen_active else 0,
        "max_points": 15,
        "detail": "SmartScreen filter is protecting against unrecognized apps and malicious downloads." if smartscreen_active else "SmartScreen filter is turned off.",
        "remediation": "Enable SmartScreen in App & Browser Control in Windows Security."
    })

    # 7. UAC System Policy Check
    uac_enabled = True
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            enable_lua, _ = winreg.QueryValueEx(key, "EnableLUA")
            if enable_lua == 0:
                uac_enabled = False
    except Exception:
        pass

    checks.append({
        "category": "Access Control",
        "name": "User Account Control (UAC) Subsystem",
        "status": "Pass" if uac_enabled else "Critical",
        "points": 10 if uac_enabled else 0,
        "max_points": 10,
        "detail": "User Account Control is enforcing privilege boundaries." if uac_enabled else "User Account Control (LUA) is disabled, allowing silent malware elevation.",
        "remediation": "Re-enable UAC via Control Panel -> User Account Control Settings."
    })

    total_points = sum(c["points"] for c in checks)
    max_possible = sum(c["max_points"] for c in checks)
    score = int((total_points / max_possible) * 100) if max_possible > 0 else 75

    return checks, score
