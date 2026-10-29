"""
Fikrado Security - Cross-Platform Defender Integration & Controls
Communicates with Windows Defender on Windows, provides status on all platforms.
"""
from typing import Tuple
from core.logger import logger
from core.platforms import IS_WINDOWS


class DefenderControl:

    def get_status(self) -> dict:
        """Returns Defender status. On non-Windows, returns unavailable sentinel."""
        if IS_WINDOWS:
            from core.system_info import get_defender_status
            return get_defender_status()
        return {"status": "unavailable", "available": False,
                "reason": "Windows Defender is only available on Windows platforms."}

    def update_signatures(self) -> Tuple[bool, str]:
        """Forces an immediate signature update.
        On Windows updates Defender; on other platforms notifies the user.
        """
        if IS_WINDOWS:
            try:
                cmd = ["powershell", "-NoProfile", "-Command", "Update-MpSignature"]
                from core.subprocess_utils import run_hidden
                res = run_hidden(cmd, capture_output=True, text=True, timeout=30)
                if res.returncode == 0:
                    logger.info("Windows Defender signatures updated successfully.")
                    return True, "Windows Defender signatures successfully updated."
                return False, f"Update command failed: {res.stderr or res.stdout}"
            except Exception as e:
                return False, f"Failed to run signature update: {str(e)}"
        return False, "Windows Defender signature updates are only available on Windows platforms."

    def trigger_quick_scan(self) -> Tuple[bool, str]:
        """Launches a native Windows Defender quick scan.
        On non-Windows returns a platform-notice.
        """
        if IS_WINDOWS:
            try:
                cmd = ["powershell", "-NoProfile", "-Command", "Start-MpScan -ScanType QuickScan"]
                from core.subprocess_utils import run_hidden
                res = run_hidden(cmd, capture_output=True, text=True, timeout=60)
                if res.returncode == 0:
                    return True, "Windows Defender Quick Scan initiated successfully."
                return False, f"Quick scan trigger failed: {res.stderr or res.stdout}"
            except Exception as e:
                return False, f"Failed to trigger scan: {str(e)}"
        return False, "Windows Defender Quick Scan is only available on Windows platforms."


defender_control = DefenderControl()
