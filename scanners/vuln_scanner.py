"""
Fikrado Security - Known and Emerging Vulnerability Check
Audits installed applications, Windows hotfix patch levels, outdated apps via winget,
and matches against the CISA Known Exploited Vulnerabilities (KEV) catalog.
"""
import re
import subprocess
import winreg
from typing import Dict, List, Optional, Tuple
from core.database import db
from core.logger import logger


def get_installed_software() -> List[dict]:
    """
    Enumerates installed software from 32-bit, 64-bit machine and user registry keys.
    """
    software_list = []
    seen = set()

    registry_roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", 0),
    ]

    for hive, subkey, flag in registry_roots:
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | flag) as key:
                num_subkeys = winreg.QueryInfoKey(key)[0]
                for i in range(num_subkeys):
                    try:
                        sub_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, sub_name, 0, winreg.KEY_READ) as app_key:
                            try:
                                name, _ = winreg.QueryValueEx(app_key, "DisplayName")
                            except FileNotFoundError:
                                continue

                            version = ""
                            try:
                                version, _ = winreg.QueryValueEx(app_key, "DisplayVersion")
                            except FileNotFoundError:
                                pass

                            publisher = ""
                            try:
                                publisher, _ = winreg.QueryValueEx(app_key, "Publisher")
                            except FileNotFoundError:
                                pass

                            unique_key = (name.strip().lower(), str(version).strip().lower())
                            if unique_key in seen:
                                continue
                            seen.add(unique_key)

                            software_list.append({
                                "name": name.strip(),
                                "version": str(version).strip() if version else "Unknown",
                                "publisher": str(publisher).strip() if publisher else "Unknown",
                                "registry_id": sub_name
                            })
                    except Exception:
                        continue
        except Exception as e:
            logger.debug(f"Registry software enumeration notice: {e}")

    software_list.sort(key=lambda x: x["name"].lower())
    return software_list


def get_windows_hotfixes() -> List[dict]:
    """Retrieves installed Windows security updates and KB patch levels."""
    hotfixes = []
    try:
        cmd = [
            "powershell", "-NoProfile", "-Command",
            "Get-HotFix | Select-Object HotFixID, Description, InstalledOn | ConvertTo-Json"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if res.returncode == 0 and res.stdout.strip():
            import json
            data = json.loads(res.stdout)
            items = [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])
            for it in items:
                hotfixes.append({
                    "hotfix_id": it.get("HotFixID", "KB-Unknown"),
                    "description": it.get("Description", "Security Update"),
                    "installed_on": str(it.get("InstalledOn", "Recent"))
                })
    except Exception as e:
        logger.debug(f"Hotfix enumeration fallback: {e}")

    return hotfixes


def get_winget_upgrades() -> List[dict]:
    """Queries winget for available software package upgrades."""
    upgrades = []
    try:
        cmd = ["winget", "upgrade", "--accept-source-agreements"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if res.returncode == 0:
            lines = res.stdout.splitlines()
            start_parsing = False
            for line in lines:
                if "---" in line:
                    start_parsing = True
                    continue
                if not start_parsing or not line.strip():
                    continue

                parts = re.split(r"\s{2,}", line.strip())
                if len(parts) >= 4:
                    upgrades.append({
                        "name": parts[0],
                        "id": parts[1],
                        "installed_version": parts[2],
                        "available_version": parts[3]
                    })
    except Exception as e:
        logger.debug(f"winget upgrade check notice: {e}")

    return upgrades


def correlate_with_cisa_kev(software_list: List[dict]) -> List[dict]:
    """
    Cross-checks installed applications against the CISA Known Exploited Vulnerabilities catalog.
    Matches product keywords against actively exploited CVE advisories.
    """
    findings = []
    tracked_keywords = [
        "chrome", "edge", "firefox", "acrobat", "adobe", "office", "word",
        "excel", "outlook", "vlc", "git", "python", "7-zip", "winrar",
        "zoom", "teams", "vmware", "virtualbox", "java", "anydesk", "teamviewer"
    ]

    for app in software_list:
        app_name_lower = app["name"].lower()
        for kw in tracked_keywords:
            if kw in app_name_lower:
                kev_matches = db.search_cisa_kev(kw)
                for km in kev_matches:
                    findings.append({
                        "app_name": app["name"],
                        "app_version": app["version"],
                        "cve_id": km["cve_id"],
                        "product": km["product"],
                        "vendor": km["vendor_project"],
                        "vulnerability_name": km["vulnerability_name"],
                        "severity": "Critical",
                        "status": "Actively Exploited (CISA KEV)",
                        "date_added": km["date_added"],
                        "short_description": km["short_description"],
                        "required_action": km["required_action"],
                    })
                break  # Matched keyword for this app

    return findings


def execute_winget_upgrade(app_id: str) -> Tuple[bool, str]:
    """Executes a non-blocking winget package upgrade."""
    try:
        cmd = [
            "winget", "upgrade", "--id", app_id,
            "--silent", "--accept-source-agreements", "--accept-package-agreements"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if res.returncode == 0:
            return True, f"Successfully initiated upgrade for package {app_id}."
        return False, f"winget upgrade failed (code {res.returncode}): {res.stderr or res.stdout}"
    except Exception as e:
        return False, f"Failed to execute winget: {str(e)}"
