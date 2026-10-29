"""
Fikrado Security - Known and Emerging Vulnerability Check
Audits installed applications, OS patch levels, and outdated packages, and
matches them against the CISA Known Exploited Vulnerabilities (KEV) catalog.

Installed software is enumerated from the registry on Windows, from the native
package manager on Linux, and from Homebrew/system packages on macOS.
"""
import os
import platform
import re
import shutil
from typing import Dict, List, Optional, Tuple
from core.logger import logger
from core.platforms import IS_LINUX, IS_MACOS, IS_WINDOWS
from core.subprocess_utils import run_hidden

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows import safety
    winreg = None

from core.database import db


def get_installed_software() -> List[dict]:
    """
    Enumerates installed software:
      * Windows: 32-bit/64-bit machine and user registry uninstall keys
      * Linux: dpkg, rpm, pacman, apk or flatpak (whichever is present)
      * macOS: Homebrew + system package receipts
    """
    if IS_WINDOWS:
        return _get_installed_software_windows()
    if IS_MACOS:
        return _get_installed_software_macos()
    return _get_installed_software_linux()


def _get_installed_software_windows() -> List[dict]:
    """Enumerates installed software from the Windows uninstall registry keys."""
    software_list = []
    seen = set()

    if winreg is None:
        return software_list

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


def _parse_package_lines(lines: List[str], delimiter: str, max_fields: int = 2) -> List[dict]:
    """Converts `name<del>version` package lines into the shared software shape."""
    software_list: List[dict] = []
    seen = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = line.split(delimiter, max_fields - 1)
        name = parts[0].strip()
        version = parts[1].strip() if len(parts) > 1 else "Unknown"
        if not name:
            continue
        key = (name.lower(), version.lower())
        if key in seen:
            continue
        seen.add(key)
        software_list.append({
            "name": name,
            "version": version or "Unknown",
            "publisher": "System Package Manager",
            "registry_id": name,
        })
    software_list.sort(key=lambda x: x["name"].lower())
    return software_list


def _get_installed_software_linux() -> List[dict]:
    """Enumerates installed software from the native Linux package manager."""
    candidates = (
        (["dpkg-query", "-W", "-f", "${Package} ${Version}\n"], " ", "dpkg"),
        (["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"], " ", "rpm"),
        (["pacman", "-Q"], " ", "pacman"),
        (["apk", "info"], "\n", "apk"),
        (["flatpak", "list", "--columns=application,version"], "\t", "flatpak"),
    )
    for cmd, delimiter, _backend in candidates:
        if not shutil.which(cmd[0]):
            continue
        try:
            res = run_hidden(cmd, capture_output=True, text=True, timeout=20)
            if res.returncode == 0 and res.stdout.strip():
                return _parse_package_lines(res.stdout.splitlines(), delimiter)
        except Exception as e:
            logger.debug(f"Package enumeration via {cmd[0]} failed: {e}")

    logger.debug("No supported Linux package manager found for software inventory.")
    return []


def _get_installed_software_macos() -> List[dict]:
    """Enumerates installed software from Homebrew and macOS package receipts."""
    software_list: List[dict] = []
    seen = set()

    def _add(name: str, version: str, publisher: str):
        name = name.strip()
        version = (version or "Unknown").strip()
        if not name:
            return
        key = (name.lower(), version.lower())
        if key in seen:
            return
        seen.add(key)
        software_list.append({
            "name": name,
            "version": version or "Unknown",
            "publisher": publisher,
            "registry_id": name,
        })

    if shutil.which("brew"):
        for formulae in (["brew", "list", "--versions"], ["brew", "list", "--cask", "--versions"]):
            try:
                res = run_hidden(formulae, capture_output=True, text=True, timeout=30)
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        parts = line.split()
                        if parts:
                            _add(parts[0], " ".join(parts[1:]) or "Unknown", "Homebrew")
            except Exception as e:
                logger.debug(f"Homebrew enumeration failed: {e}")

    if shutil.which("pkgutil"):
        try:
            res = run_hidden(["pkgutil", "--pkgs"], capture_output=True, text=True, timeout=30)
            if res.returncode == 0:
                for pkg in res.stdout.splitlines():
                    if pkg.strip():
                        _add(pkg.strip(), "Unknown", "Apple Installer")
        except Exception as e:
            logger.debug(f"pkgutil enumeration failed: {e}")

    software_list.sort(key=lambda x: x["name"].lower())
    return software_list


def get_windows_hotfixes() -> List[dict]:
    """Retrieves installed Windows security updates and KB patch levels."""
    hotfixes = []
    if not IS_WINDOWS:
        # Windows-only data source; other platforms report patch state through
        # their package manager (see get_installed_software).
        return hotfixes

    try:
        cmd = [
            "powershell", "-NoProfile", "-Command",
            "Get-HotFix | Select-Object HotFixID, Description, InstalledOn | ConvertTo-Json"
        ]
        res = run_hidden(cmd, capture_output=True, text=True, timeout=10)
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
    """Queries winget for available software package upgrades (Windows only)."""
    upgrades = []
    if not IS_WINDOWS:
        return upgrades

    try:
        cmd = ["winget", "upgrade", "--accept-source-agreements"]
        res = run_hidden(cmd, capture_output=True, text=True, timeout=20)
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
    """Executes a non-blocking winget package upgrade (Windows only)."""
    if not IS_WINDOWS:
        return False, (
            "In-app upgrades use winget and are only available on Windows. "
            "Use your platform package manager to apply updates."
        )
    try:
        cmd = [
            "winget", "upgrade", "--id", app_id,
            "--silent", "--accept-source-agreements", "--accept-package-agreements"
        ]
        res = run_hidden(cmd, capture_output=True, text=True, timeout=120)
        if res.returncode == 0:
            return True, f"Successfully initiated upgrade for package {app_id}."
        return False, f"winget upgrade failed (code {res.returncode}): {res.stderr or res.stdout}"
    except Exception as e:
        return False, f"Failed to execute winget: {str(e)}"
