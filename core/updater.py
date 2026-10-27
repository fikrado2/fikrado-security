"""
Fikrado Security - Signature & Vulnerability Database Updater
Manages automatic and on-demand synchronization of threat signatures and CISA KEV feeds.
"""
import json
import time
from pathlib import Path
from typing import Tuple
import requests
from config.constants import SIGNATURES_DIR
from config.security_rules import BUILTIN_MALWARE_HASHES
from core.database import db
from core.logger import logger
from core.subprocess_utils import run_hidden

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OFFLINE_KEV_FILE = SIGNATURES_DIR / "cisa_kev.json"


def init_offline_signatures():
    """Seeds database with built-in signatures if empty."""
    try:
        # Seed built-in hashes
        for sha256, info in BUILTIN_MALWARE_HASHES.items():
            with db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR IGNORE INTO malware_signatures (sha256, threat_name, threat_type, severity, source, added_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (sha256, info["name"], info["type"], info["severity"], "Builtin", time.strftime("%Y-%m-%d")))
                conn.commit()

        # Seed sample CISA KEV entries if none cached yet
        stats = db.count_stats()
        if stats.get("kev_count", 0) == 0:
            sample_kev = [
                {
                    "cveID": "CVE-2024-38112",
                    "vendorProject": "Microsoft",
                    "product": "Windows MSHTML Platform",
                    "vulnerabilityName": "Microsoft Windows MSHTML Platform Spoofing Vulnerability",
                    "dateAdded": "2024-07-09",
                    "shortDescription": "Windows MSHTML platform contains a spoofing vulnerability that allows an attacker to execute arbitrary code.",
                    "requiredAction": "Apply vendor security updates promptly.",
                    "dueDate": "2024-07-30",
                    "notes": "Exploitation detected in the wild."
                },
                {
                    "cveID": "CVE-2024-38021",
                    "vendorProject": "Microsoft",
                    "product": "Office",
                    "vulnerabilityName": "Microsoft Office Remote Code Execution Vulnerability",
                    "dateAdded": "2024-07-09",
                    "shortDescription": "Microsoft Office contains an unauthorized remote code execution vulnerability.",
                    "requiredAction": "Apply vendor updates.",
                    "dueDate": "2024-07-30",
                    "notes": "Reported in zero-day exploit chain."
                },
                {
                    "cveID": "CVE-2024-21338",
                    "vendorProject": "Microsoft",
                    "product": "Windows Kernel",
                    "vulnerabilityName": "Windows Kernel Elevation of Privilege Vulnerability",
                    "dateAdded": "2024-02-29",
                    "shortDescription": "Allows a local attacker with standard privileges to obtain SYSTEM kernel privileges.",
                    "requiredAction": "Apply Windows cumulative updates.",
                    "dueDate": "2024-03-21",
                    "notes": "Used by Lazarus group in BYOVD attacks."
                },
                {
                    "cveID": "CVE-2023-36884",
                    "vendorProject": "Microsoft",
                    "product": "Windows and Office",
                    "vulnerabilityName": "Microsoft Office and Windows HTML Remote Code Execution Vulnerability",
                    "dateAdded": "2023-07-12",
                    "shortDescription": "Specially crafted Microsoft Office document leads to remote code execution.",
                    "requiredAction": "Apply official vendor security patch.",
                    "dueDate": "2023-08-04",
                    "notes": "Targeted attacks against government agencies."
                },
                {
                    "cveID": "CVE-2021-40444",
                    "vendorProject": "Microsoft",
                    "product": "MSHTML",
                    "vulnerabilityName": "Microsoft MSHTML Remote Code Execution Vulnerability",
                    "dateAdded": "2021-11-03",
                    "shortDescription": "Active exploitation via weaponized Word documents loading ActiveX controls.",
                    "requiredAction": "Apply vendor security patch.",
                    "dueDate": "2021-11-17",
                    "notes": "Widely weaponized in commercial crimeware."
                }
            ]
            db.cache_cisa_kev(sample_kev)
    except Exception as e:
        logger.error(f"Error seeding offline signatures: {e}")


def update_cisa_kev_online() -> Tuple[bool, str]:
    """Downloads latest CISA Known Exploited Vulnerabilities catalog."""
    try:
        logger.info(f"Downloading CISA KEV catalog from {CISA_KEV_URL}...")
        resp = requests.get(CISA_KEV_URL, timeout=12)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                db.cache_cisa_kev(vulns)
                # Save offline copy
                with open(OFFLINE_KEV_FILE, "w", encoding="utf-8") as f:
                    json.dump(data, f)
                return True, f"Successfully synced {len(vulns)} actively exploited vulnerabilities from CISA."
        return False, f"Failed to download CISA KEV (HTTP {resp.status_code})"
    except Exception as e:
        logger.warning(f"CISA KEV download failed: {e}")
        return False, f"Network update error: {str(e)}"


def run_freshclam(freshclam_path: str = "freshclam.exe") -> Tuple[bool, str]:
    """Runs ClamAV freshclam to update antivirus definitions."""
    try:
        res = run_hidden([freshclam_path], capture_output=True, text=True, timeout=60)
        if res.returncode == 0:
            return True, "ClamAV virus signatures updated successfully."
        return False, f"freshclam exited with code {res.returncode}: {res.stderr[:200]}"
    except FileNotFoundError:
        return False, "ClamAV freshclam executable not found in PATH."
    except Exception as e:
        return False, f"Error running freshclam: {str(e)}"
