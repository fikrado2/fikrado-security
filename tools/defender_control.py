"""
Fikrado Security - Windows Defender Integration & Controls
Communicates with Windows Defender to query status, trigger scans, and update definitions.
"""
import subprocess
from typing import Tuple
from core.logger import logger
from core.system_info import get_defender_status


class DefenderControl:

    def get_status(self) -> dict:
        return get_defender_status()

    def update_signatures(self) -> Tuple[bool, str]:
        """Forces an immediate Windows Defender signature update."""
        try:
            cmd = ["powershell", "-NoProfile", "-Command", "Update-MpSignature"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode == 0:
                logger.info("Windows Defender signatures updated successfully.")
                return True, "Windows Defender signatures successfully updated."
            return False, f"Update command failed: {res.stderr or res.stdout}"
        except Exception as e:
            return False, f"Failed to run signature update: {str(e)}"

    def trigger_quick_scan(self) -> Tuple[bool, str]:
        """Launches a native Windows Defender quick scan."""
        try:
            cmd = ["powershell", "-NoProfile", "-Command", "Start-MpScan -ScanType QuickScan"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode == 0:
                return True, "Windows Defender Quick Scan initiated successfully."
            return False, f"Quick scan trigger failed: {res.stderr or res.stdout}"
        except Exception as e:
            return False, f"Failed to trigger scan: {str(e)}"


defender_control = DefenderControl()
