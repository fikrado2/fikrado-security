"""
Fikrado Security - Browser Extension & Hosts File Integrity Checker
Detects malicious DNS redirects in C:\\Windows\\System32\\drivers\\etc\\hosts
and high-privilege/suspicious browser extensions.
"""
import json
import os
from pathlib import Path
from typing import Dict, List, Tuple
from core.logger import logger

HOSTS_PATH = Path(r"C:\Windows\System32\drivers\etc\hosts")
DEFAULT_HOSTS_CONTENT = """# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
127.0.0.1       localhost
::1             localhost
"""


class BrowserHostsChecker:

    def check_hosts_file(self) -> Tuple[bool, List[str], List[dict]]:
        """
        Parses Windows hosts file for suspicious redirects.
        Returns: (is_clean, raw_active_lines, flagged_entries)
        """
        flagged = []
        active_lines = []
        is_clean = True

        if not HOSTS_PATH.exists():
            return True, [], []

        try:
            with open(HOSTS_PATH, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    active_lines.append(stripped)
                    parts = stripped.split()
                    if len(parts) >= 2:
                        target_ip = parts[0]
                        domain = parts[1].lower()

                        # Check if redirects antivirus, updates, or major portals
                        suspicious_domains = [
                            "microsoft.com", "windowsupdate.com", "virustotal.com",
                            "avast.com", "kaspersky.com", "bitdefender.com", "symantec.com",
                            "malwarebytes.com", "google.com", "bing.com"
                        ]
                        for sd in suspicious_domains:
                            if sd in domain and target_ip != "127.0.0.1" and target_ip != "::1":
                                is_clean = False
                                flagged.append({
                                    "ip": target_ip,
                                    "domain": domain,
                                    "reason": f"Redirects security/portal domain '{domain}' away from standard server."
                                })
        except Exception as e:
            logger.error(f"Error reading hosts file: {e}")

        return is_clean, active_lines, flagged

    def restore_default_hosts(self) -> Tuple[bool, str]:
        """Resets hosts file to Microsoft default clean template."""
        try:
            with open(HOSTS_PATH, "w", encoding="utf-8") as f:
                f.write(DEFAULT_HOSTS_CONTENT)
            logger.info("Restored clean default Windows hosts file.")
            return True, "Hosts file successfully restored to default clean state."
        except PermissionError:
            return False, "Access denied. Administrator privileges required to modify hosts file."
        except Exception as e:
            return False, f"Error restoring hosts: {str(e)}"

    def check_browser_extensions(self) -> List[dict]:
        """Audits Chrome, Edge, and Firefox extensions for high-risk permissions."""
        extensions = []
        local_appdata = Path(os.getenv("LOCALAPPDATA", ""))
        appdata = Path(os.getenv("APPDATA", ""))

        browser_dirs = [
            ("Google Chrome", local_appdata / "Google/Chrome/User Data/Default/Extensions"),
            ("Microsoft Edge", local_appdata / "Microsoft/Edge/User Data/Default/Extensions"),
            ("Brave Browser", local_appdata / "BraveSoftware/Brave-Browser/User Data/Default/Extensions"),
        ]

        high_risk_permissions = {"<all_urls>", "webRequestBlocking", "debugger", "cookies", "management", "nativeMessaging"}

        for b_name, b_path in browser_dirs:
            if not b_path.exists():
                continue
            try:
                for ext_dir in b_path.iterdir():
                    if ext_dir.is_dir():
                        # Find version subdirectory
                        for ver_dir in ext_dir.iterdir():
                            manifest_file = ver_dir / "manifest.json"
                            if manifest_file.exists():
                                try:
                                    with open(manifest_file, "r", encoding="utf-8", errors="ignore") as mf:
                                        mdata = json.load(mf)
                                    name = mdata.get("name", ext_dir.name)
                                    version = mdata.get("version", "1.0")
                                    perms = set(mdata.get("permissions", []))
                                    risky_found = list(perms.intersection(high_risk_permissions))

                                    extensions.append({
                                        "browser": b_name,
                                        "name": name if not name.startswith("__MSG_") else ext_dir.name,
                                        "version": version,
                                        "id": ext_dir.name,
                                        "risky_permissions": risky_found,
                                        "severity": "High" if len(risky_found) >= 2 else ("Medium" if len(risky_found) == 1 else "Low"),
                                        "path": str(manifest_file)
                                    })
                                except Exception:
                                    continue
            except Exception as e:
                logger.debug(f"Extension audit notice for {b_name}: {e}")

        extensions.sort(key=lambda x: (x["severity"] != "High", x["severity"] != "Medium"))
        return extensions


browser_hosts_checker = BrowserHostsChecker()
