"""
Fikrado Security - Startup Manager
Inspects, disables, and re-enables startup items across platform autostart
locations: Windows registry hives and Startup folders, Linux autostart
directories, and macOS LaunchAgents.
"""
import os
from pathlib import Path
from typing import Dict, List, Tuple
from core.logger import logger
from core.platforms import IS_WINDOWS, system_startup_dirs, user_startup_dirs

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows import safety
    winreg = None


class StartupManager:

    def list_startup_items(self) -> List[dict]:
        """Collects all startup items from the registry and autostart folders."""
        items = []

        if winreg is not None:
            # 1. HKCU Run
            self._read_reg_startup(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "User Registry (HKCU)", items)
            # 2. HKLM Run
            self._read_reg_startup(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "System Registry (HKLM)", items)

        # 3. Autostart folders (Startup folder, ~/.config/autostart, LaunchAgents)
        for folder in user_startup_dirs():
            self._read_folder_startup(folder, "User Startup Folder", items)
        for folder in system_startup_dirs():
            self._read_folder_startup(folder, "System Startup Folder", items)

        return items

    def _read_reg_startup(self, hive, key_path: str, location_label: str, results: list):
        if winreg is None:
            return
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
        if not folder or not folder.exists():
            return
        try:
            for item in folder.iterdir():
                if not item.is_file():
                    continue
                if not IS_WINDOWS and item.name.startswith("."):
                    # Hidden files are not executed by XDG autostart / LaunchAgents.
                    continue
                # Entries are marked disabled by renaming with a ".disabled" suffix.
                is_disabled = item.name.lower().endswith(".disabled")
                results.append({
                    "name": item.stem if item.suffix else item.name,
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
                if winreg is None:
                    return False, "Registry startup entries are only available on Windows."
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
                if enable and p.name.lower().endswith(".disabled"):
                    new_path = p.with_name(p.name[: -len(".disabled")])
                    p.rename(new_path)
                elif not enable and not p.name.lower().endswith(".disabled"):
                    new_path = p.with_name(p.name + ".disabled")
                    p.rename(new_path)
                return True, f"Startup file '{item['name']}' {'enabled' if enable else 'disabled'}."

        except PermissionError:
            return False, "Access denied. Elevated privileges are required to modify this startup entry."
        except Exception as e:
            return False, f"Error toggling item: {str(e)}"
        return False, "Unknown item type"


startup_manager = StartupManager()
