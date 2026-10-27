"""
Fikrado Security - Windows Startup Manager
Inspects, disables, and re-enables startup items across registry hives and Startup folders.
"""
import os
import winreg
from pathlib import Path
from typing import Dict, List, Tuple
from core.logger import logger


class StartupManager:

    def list_startup_items(self) -> List[dict]:
        """Collects all startup items from HKCU, HKLM, and Startup directories."""
        items = []

        # 1. HKCU Run
        self._read_reg_startup(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "User Registry (HKCU)", items)
        # 2. HKLM Run
        self._read_reg_startup(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "System Registry (HKLM)", items)

        # 3. Startup Folder (User)
        user_startup = Path(os.getenv("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup"
        self._read_folder_startup(user_startup, "User Startup Folder", items)

        # 4. Startup Folder (Common)
        common_startup = Path(os.getenv("PROGRAMDATA", "C:/ProgramData")) / "Microsoft/Windows/Start Menu/Programs/Startup"
        self._read_folder_startup(common_startup, "System Startup Folder", items)

        return items

    def _read_reg_startup(self, hive, key_path: str, location_label: str, results: list):
        try:
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                num_vals = winreg.QueryInfoKey(key)[1]
                for i in range(num_vals):
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        is_disabled = name.startswith("[DISABLED]_")
                        display_name = name.replace("[DISABLED]_", "")
                        results.append({
                            "name": display_name,
                            "raw_name": name,
                            "command": str(val),
                            "location": location_label,
                            "type": "registry",
                            "hive": hive,
                            "key_path": key_path,
                            "enabled": not is_disabled
                        })
                    except Exception:
                        continue
        except Exception as e:
            logger.debug(f"Startup registry read notice: {e}")

    def _read_folder_startup(self, folder: Path, location_label: str, results: list):
        if not folder.exists():
            return
        try:
            for item in folder.iterdir():
                if item.is_file():
                    is_disabled = item.suffix.lower() == ".disabled"
                    results.append({
                        "name": item.stem,
                        "raw_name": item.name,
                        "command": str(item.resolve()),
                        "location": location_label,
                        "type": "file",
                        "file_path": str(item.resolve()),
                        "enabled": not is_disabled
                    })
        except Exception as e:
            logger.debug(f"Startup folder read notice: {e}")

    def toggle_item(self, item: dict, enable: bool) -> Tuple[bool, str]:
        """Toggles a startup item on or off safely."""
        try:
            if item["type"] == "registry":
                hive = item["hive"]
                key_path = item["key_path"]
                cmd = item["command"]
                raw_name = item["raw_name"]
                new_name = item["name"] if enable else f"[DISABLED]_{item['name']}"

                with winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, raw_name)
                    winreg.SetValueEx(key, new_name, 0, winreg.REG_SZ, cmd)
                return True, f"Startup item '{item['name']}' {'enabled' if enable else 'disabled'}."

            elif item["type"] == "file":
                p = Path(item["file_path"])
                if not p.exists():
                    return False, "Startup file not found."
                if enable and p.suffix.lower() == ".disabled":
                    new_path = p.with_suffix("")
                    p.rename(new_path)
                elif not enable and p.suffix.lower() != ".disabled":
                    new_path = p.with_suffix(p.suffix + ".disabled")
                    p.rename(new_path)
                return True, f"Startup file '{item['name']}' {'enabled' if enable else 'disabled'}."

        except Exception as e:
            return False, f"Error toggling item: {str(e)}"
        return False, "Unknown item type"


startup_manager = StartupManager()
