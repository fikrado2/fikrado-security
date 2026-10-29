"""
Fikrado Security - System Information & Security Auditing
Inspects OS configuration, elevation, firewall/AV status, and security posture.
Windows-specific probes (registry, PowerShell, netsh) are used on Windows;
Linux and macOS receive native equivalents or an explicit "not verifiable".
"""
import os
import platform
import shutil
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple
from core.logger import logger
from core.platforms import (
    IS_LINUX,
    IS_MACOS,
    IS_WINDOWS,
    PLATFORM_NAME,
    is_admin,
    hosts_file_path,
)
from core.subprocess_utils import run_hidden

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows import safety
    winreg = None


_DEFENDER_CACHE_LOCK = threading.Lock()
_DEFENDER_CACHE = {"status": None, "timestamp": 0.0}

_HARDENING_CACHE_LOCK = threading.Lock()
_HARDENING_CACHE = {"checks": None, "score": 0, "timestamp": 0.0}

# Sentinel returned on non-Windows hosts: Windows Defender does not exist there,
# so the UI must show "unavailable" instead of a fake ENABLED/DISABLED state.
_DEFENDER_UNAVAILABLE = {
    "available": False,
    "installed": False,
    "realtime_protection": False,
    "antivirus_enabled": False,
    "antispyware_enabled": False,
    "behavior_monitor": False,
    "definitions_updated": False,
    "antivirus_signature_age": 0,
    "raw_status": "Unavailable",
}


def get_system_info() -> dict:
    """Gathers OS name, version, build, architecture, and system specs."""
    if IS_WINDOWS:
        win_ver = platform.win32_ver()
        os_name = "Windows"
        os_version = win_ver[0]
        os_build = win_ver[1]
        os_service_pack = win_ver[2]
        computer_name = os.getenv("COMPUTERNAME", "Unknown")
        username = os.getenv("USERNAME", "Unknown")
    elif IS_MACOS:
        os_name = "macOS"
        os_version = platform.mac_ver()[0]
        os_build = platform.release()
        os_service_pack = ""
        computer_name = platform.node() or "Unknown"
        username = os.getenv("USER", "Unknown")
    else:
        os_name = "Linux"
        os_version = platform.freedesktop_os_release().get("PRETTY_NAME", "") if hasattr(platform, "freedesktop_os_release") else ""
        os_version = os_version or platform.release()
        os_build = platform.release()
        os_service_pack = ""
        computer_name = platform.node() or "Unknown"
        username = os.getenv("USER", "Unknown")

    return {
        "os_name": os_name,
        "os_version": os_version,
        "os_build": os_build,
        "os_service_pack": os_service_pack,
        "architecture": platform.machine(),
        "processor": platform.processor() or platform.machine(),
        "computer_name": computer_name,
        "username": username,
        "is_admin": is_admin(),
        "python_version": platform.python_version(),
    }


# Backwards-compatible alias: older call sites import get_windows_info.
get_windows_info = get_system_info


def _read_registry_value(hive, path: str, name: str):
    """Reads a registry value without raising; returns None when unavailable."""
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(hive, path) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except OSError:
        return None


def _query_defender_status_deep() -> dict:
    """Queries Windows Defender status via PowerShell Get-MpComputerStatus."""
    if not IS_WINDOWS:
        return dict(_DEFENDER_UNAVAILABLE)

    default_status = {
        "available": True,
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
                "available": True,
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


def _query_defender_status_fast() -> dict:
    """Reads Defender state from the registry (instant, no PowerShell)."""
    if not IS_WINDOWS:
        return dict(_DEFENDER_UNAVAILABLE)

    default_status = {
        "available": True,
        "installed": True,
        "realtime_protection": True,
        "antivirus_enabled": True,
        "antispyware_enabled": True,
        "behavior_monitor": True,
        "definitions_updated": True,
        "antivirus_signature_age": 0,
        "raw_status": "Active",
    }
    if winreg is None:
        return default_status

    disable_av = _read_registry_value(
        winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender", "DisableAntiSpyware"
    )
    disable_rt = _read_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
        "DisableRealtimeMonitoring",
    )
    policy_rt = _read_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "DisableRealtimeMonitoring",
    )
    enabled = not (disable_av == 1 or disable_rt == 1 or policy_rt == 1)
    return {
        "available": True,
        "installed": True,
        "realtime_protection": enabled,
        "antivirus_enabled": enabled,
        "antispyware_enabled": enabled,
        "behavior_monitor": enabled,
        "definitions_updated": True,
        "antivirus_signature_age": 0,
        "raw_status": "Active" if enabled else "Disabled",
    }


def get_defender_status(
    max_age_seconds: float = 60.0, force: bool = False, deep: bool = False
) -> dict:
    """Returns a cached Defender status so repeated UI queries stay instant.

    The default path reads the registry, which is effectively free.  ``deep``
    runs the slower ``Get-MpComputerStatus`` query for signature details and is
    reserved for explicit user-initiated audits; it always bypasses the cache so
    a re-audit cannot silently reuse an earlier fast result.
    """
    if deep:
        return _query_defender_status_deep()

    now = time.monotonic()
    if not force:
        with _DEFENDER_CACHE_LOCK:
            cached = _DEFENDER_CACHE["status"]
            if cached is not None and now - _DEFENDER_CACHE["timestamp"] <= max_age_seconds:
                return dict(cached)

    status = _query_defender_status_fast()
    with _DEFENDER_CACHE_LOCK:
        _DEFENDER_CACHE["status"] = dict(status)
        _DEFENDER_CACHE["timestamp"] = time.monotonic()
    return status


_FIREWALL_PROFILES = (
    ("Domain", "DomainProfile"),
    ("Private", "StandardProfile"),
    ("Public", "PublicProfile"),
)


def get_firewall_profiles_status(deep: bool = False) -> Dict[str, bool]:
    """
    Returns firewall state for all profiles, using the registry by default.

    On Linux/macOS Windows profiles do not exist, so an empty dict is returned
    and callers must fall back to :func:`get_firewall_enabled`.
    """
    if not IS_WINDOWS:
        return {}

    if deep:
        status = {"Domain": True, "Private": True, "Public": True}
        try:
            res = run_hidden(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=5,
            )
            if res.returncode == 0:
                current_profile = None
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if "Domain Profile Settings" in line:
                        current_profile = "Domain"
                    elif "Private Profile Settings" in line:
                        current_profile = "Private"
                    elif "Public Profile Settings" in line:
                        current_profile = "Public"
                    elif current_profile and "State" in line:
                        status[current_profile] = "ON" in line.upper()
                return status
        except Exception as exc:
            logger.debug(f"Deep firewall query fallback: {exc}")

    status = {}
    for label, key_name in _FIREWALL_PROFILES:
        value = None
        if winreg is not None:
            value = _read_registry_value(
                winreg.HKEY_LOCAL_MACHINE,
                rf"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{key_name}",
                "EnableFirewall",
            )
        # Missing values default to enabled, which matches Windows defaults.
        status[label] = value != 0
    return status


def get_firewall_enabled(deep: bool = False) -> Optional[bool]:
    """
    Cross-platform single firewall verdict.

    Returns True/False when the host firewall state can be determined, or
    ``None`` when no supported firewall backend is available.
    """
    if IS_WINDOWS:
        profiles = get_firewall_profiles_status(deep=deep)
        return all(profiles.values()) if profiles else None

    if IS_MACOS:
        socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        if os.path.exists(socketfilterfw):
            try:
                res = run_hidden([socketfilterfw, "--getglobalstate"], timeout=5)
                if res.returncode == 0:
                    return "enabled" in res.stdout.lower()
            except Exception as exc:
                logger.debug(f"socketfilterfw probe failed: {exc}")
        return None

    # Linux: prefer a firewall manager CLI, then fall back to the raw backends.
    probes = (
        (["ufw", "status"], lambda out: out.strip().startswith("Status: active")),
        (["firewall-cmd", "--state"], lambda out: out.strip() == "running"),
        (["nft", "list", "ruleset"], lambda out: bool(out.strip())),
        (["iptables", "-S"], lambda out: bool(out.strip())),
    )
    for cmd, predicate in probes:
        if not shutil.which(cmd[0]):
            continue
        try:
            res = run_hidden(cmd, timeout=6)
            if res.returncode == 0:
                return predicate(res.stdout)
        except Exception as exc:
            logger.debug(f"Firewall probe {cmd[0]} failed: {exc}")
    return None


def _smb1_disabled(deep: bool = False) -> bool:
    """Checks whether the legacy SMBv1 protocol is disabled."""
    if not IS_WINDOWS:
        return True

    if deep:
        try:
            cmd = [
                "powershell", "-NoProfile", "-Command",
                "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol "
                "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty State",
            ]
            smb_res = run_hidden(cmd, capture_output=True, text=True, timeout=8)
            if smb_res.stdout.strip():
                return "Enabled" not in smb_res.stdout
        except Exception:
            pass

    if winreg is None:
        return True

    smb1 = _read_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "SMB1",
    )
    mrxsmb10 = _read_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\mrxsmb10",
        "Start",
    )
    if smb1 == 1 or (mrxsmb10 is not None and mrxsmb10 != 4):
        return False
    if smb1 == 0 or mrxsmb10 == 4:
        return True
    # Both values are absent on modern Windows, where SMBv1 is disabled by default.
    try:
        build = int(platform.version().split(".")[-1])
    except Exception:
        build = 0
    return build >= 16299


def _audit_hardening_posix(deep: bool = False) -> Tuple[List[dict], int]:
    """
    Security posture audit for Linux and macOS.

    Only checks that can actually be evaluated on these platforms are listed;
    Windows-only controls (UAC, SmartScreen, SMBv1, RDP, Defender) are omitted
    rather than reported as passing. ``N/A`` checks are excluded from the score.
    """
    checks: List[dict] = []

    # 1. Privilege elevation (root / sudo)
    admin_state = is_admin()
    checks.append({
        "category": "Privilege",
        "name": "Process Elevation (Root)",
        "status": "Pass" if admin_state else "Warning",
        "points": 15 if admin_state else 8,
        "max_points": 15,
        "detail": (
            "Running with root privileges; low-level scans and remediation actions are fully available."
            if admin_state else
            "Running as a regular user; some scans and remediation actions will be limited."
        ),
        "remediation": (
            "Launch the application with elevated privileges if deeper inspection is required."
            if not admin_state else "No action required."
        ),
    })

    # 2. Host firewall
    firewall_state = get_firewall_enabled(deep=deep)
    if firewall_state is None:
        checks.append({
            "category": "Network",
            "name": "Host Firewall",
            "status": "N/A",
            "points": 0,
            "max_points": 0,
            "detail": "No supported firewall backend (ufw, firewalld, nftables, socketfilterfw) was detected.",
            "remediation": "Install and enable ufw/firewalld to enforce host-level packet filtering.",
        })
    else:
        checks.append({
            "category": "Network",
            "name": "Host Firewall",
            "status": "Pass" if firewall_state else "Critical",
            "points": 25 if firewall_state else 0,
            "max_points": 25,
            "detail": "Host firewall is active and filtering inbound traffic." if firewall_state else "Host firewall is disabled — inbound traffic is unrestricted.",
            "remediation": "Enable the host firewall (e.g. `sudo ufw enable` or `sudo firewall-cmd --set-default-zone=public`).",
        })

    # 3. Resolver hosts file integrity
    try:
        from tools.browser_hosts_check import browser_hosts_checker

        is_clean, _lines, flagged = browser_hosts_checker.check_hosts_file()
        hosts_ok = bool(is_clean)
        hosts_detail = (
            f"{hosts_file_path()} is clean."
            if hosts_ok else
            f"{len(flagged)} suspicious redirect(s) found in {hosts_file_path()}."
        )
    except Exception as exc:
        logger.debug(f"Hosts integrity check skipped: {exc}")
        hosts_ok = True
        hosts_detail = f"{hosts_file_path()} could not be read."

    checks.append({
        "category": "Resolver Integrity",
        "name": "Hosts File Integrity",
        "status": "Pass" if hosts_ok else "Critical",
        "points": 25 if hosts_ok else 0,
        "max_points": 25,
        "detail": hosts_detail,
        "remediation": "Remove unauthorized DNS redirections from the system hosts file.",
    })

    # 4. Optional antivirus engine availability
    clam_found = bool(shutil.which("clamscan"))
    checks.append({
        "category": "Antivirus",
        "name": "ClamAV Scanner Availability",
        "status": "Pass" if clam_found else "Warning",
        "points": 15 if clam_found else 5,
        "max_points": 15,
        "detail": (
            "ClamAV (clamscan) is installed and available for signature-based scanning."
            if clam_found else
            "ClamAV is not installed; only YARA, hash and heuristic engines are active."
        ),
        "remediation": "Install ClamAV with your package manager to enable signature scanning.",
    })

    # 5. Real-time shield state
    try:
        from tools.realtime_guard import realtime_guard

        shield_active = bool(realtime_guard.is_active)
    except Exception as exc:
        logger.debug(f"Shield state lookup failed: {exc}")
        shield_active = False

    checks.append({
        "category": "Runtime Protection",
        "name": "Fikrado Real-Time Shield",
        "status": "Pass" if shield_active else "Warning",
        "points": 20 if shield_active else 0,
        "max_points": 20,
        "detail": "Real-time filesystem, process and network monitoring is running." if shield_active else "Real-time protection is paused or disabled.",
        "remediation": "Resume the Real-Time Shield from the Security Tools page.",
    })

    return _score_checks(checks)


def _score_checks(checks: List[dict]) -> Tuple[List[dict], int]:
    """Computes a 0-100 score, ignoring checks whose max_points is 0 (N/A)."""
    total_points = sum(c["points"] for c in checks)
    max_possible = sum(c["max_points"] for c in checks)
    score = int((total_points / max_possible) * 100) if max_possible > 0 else 75
    return checks, score


def audit_system_hardening(deep: bool = False) -> Tuple[List[dict], int]:
    """
    Performs a security hardening audit against platform security controls.

    Windows keeps its original registry/PowerShell based checklist; Linux and
    macOS run an equivalent audit built from checks that exist on those hosts.
    By default every Windows check reads the registry or an in-process API, so
    the dashboard score is available instantly.  ``deep`` re-runs the slower
    PowerShell/netsh probes for an explicit, user-initiated audit.
    Returns (checklist, security_score_0_to_100).
    """
    if not IS_WINDOWS:
        return _audit_hardening_posix(deep=deep)

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
    def_stat = get_defender_status(deep=deep)
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
    firewall_pass = all(get_firewall_profiles_status(deep=deep).values())

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
    smbv1_disabled = _smb1_disabled(deep=deep)

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

    return _score_checks(checks)


def get_hardening_audit(
    max_age_seconds: float = 300.0, force: bool = False, deep: bool = False
) -> Tuple[List[dict], int]:
    """Returns a cached hardening audit, running the expensive checks only when stale."""
    if not force:
        with _HARDENING_CACHE_LOCK:
            checks = _HARDENING_CACHE["checks"]
            if (
                checks is not None
                and time.monotonic() - _HARDENING_CACHE["timestamp"] <= max_age_seconds
            ):
                return checks, _HARDENING_CACHE["score"]

    checks, score = audit_system_hardening(deep=deep)
    with _HARDENING_CACHE_LOCK:
        _HARDENING_CACHE["checks"] = checks
        _HARDENING_CACHE["score"] = score
        _HARDENING_CACHE["timestamp"] = time.monotonic()
    return checks, score
