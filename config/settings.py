"""
Fikrado Security - Settings Manager
Handles loading, updating, and saving user configuration to AppData.
"""
import json
import logging
from typing import Any, Dict
from config.constants import SETTINGS_FILE

logger = logging.getLogger("FikradoSecurity.Settings")

DEFAULT_SETTINGS: Dict[str, Any] = {
    "app": {
        "start_with_windows": False,
        "minimize_to_tray": True,
        "auto_update_signatures": True,
        "notifications_enabled": True,
        "theme": "dark_nord",
    },
    "scanner": {
        "heuristic_level": "High",  # Low, Medium, High, Aggressive
        "entropy_threshold": 7.2,
        "max_scan_file_size_mb": 150,
        "scan_archives": True,
        "enable_yara": True,
        "enable_clamav": True,
        "clamscan_path": "clamscan.exe",
        "freshclam_path": "freshclam.exe",
        "virustotal_api_key": "",
        "auto_quarantine_critical": False,
    },
    "network": {
        "highlight_risky_ports": True,
        "default_scan_range": "192.168.1.1/24",
        "socket_timeout": 1.0,
    },
    "realtime": {
        "enabled": True,
        "scan_downloads": True,
        "scan_temp": True,
        "monitor_processes": True,
        "check_interval_seconds": 3,
    },
    "ai": {
        "active_provider": "gemini",  # openrouter, openai, anthropic, gemini, ollama, custom
        "models": {
            "gemini": "gemini-2.5-flash",
            "openai": "gpt-4o-mini",
            "anthropic": "claude-3-5-sonnet-20241022",
            "openrouter": "google/gemini-2.5-flash",
            "ollama": "llama3.2:latest",
            "custom": "default-model",
        },
        "endpoints": {
            "ollama": "http://localhost:11434",
            "custom": "https://api.openai.com/v1",
        },
        "cloud_consent_accepted": False,
        "privacy_mode": "metadata_only",  # metadata_only, snippets, full
    },
    "whitelist": {
        "hashes": [],
        "paths": [],
    },
    "stats": {
        "total_scanned_files": 0,
        "threats_blocked": 0,
        "last_scan_time": None,
        "last_scan_score": 88,
    }
}


class SettingsManager:
    """Singleton settings manager with automatic JSON persistence."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SettingsManager, cls).__new__(cls)
            cls._instance._data = {}
            cls._instance.load()
        return cls._instance

    def load(self):
        """Loads settings from JSON file or initializes with defaults."""
        if SETTINGS_FILE.exists():
            try:
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    user_data = json.load(f)
                self._data = self._deep_merge(DEFAULT_SETTINGS, user_data)
                return
            except Exception as e:
                logger.error(f"Failed to load settings from {SETTINGS_FILE}: {e}")
        self._data = json.loads(json.dumps(DEFAULT_SETTINGS))
        self.save()

    def _deep_merge(self, base: dict, override: dict) -> dict:
        result = dict(base)
        for k, v in override.items():
            if k in result and isinstance(result[k], dict) and isinstance(v, dict):
                result[k] = self._deep_merge(result[k], v)
            else:
                result[k] = v
        return result

    def get(self, section: str, key: str = None, default: Any = None) -> Any:
        if section not in self._data:
            return default
        if key is None:
            return self._data[section]
        return self._data[section].get(key, default)

    def set(self, section: str, key: str, value: Any, auto_save: bool = True):
        if section not in self._data:
            self._data[section] = {}
        self._data[section][key] = value
        if auto_save:
            self.save()

    def save(self):
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")

    def add_to_whitelist(self, item_type: str, item_value: str):
        if item_type in ("hashes", "paths"):
            items = self._data["whitelist"].get(item_type, [])
            if item_value not in items:
                items.append(item_value)
                self._data["whitelist"][item_type] = items
                self.save()

    def remove_from_whitelist(self, item_type: str, item_value: str):
        if item_type in ("hashes", "paths"):
            items = self._data["whitelist"].get(item_type, [])
            if item_value in items:
                items.remove(item_value)
                self._data["whitelist"][item_type] = items
                self.save()

    def is_whitelisted(self, file_hash: str = None, file_path: str = None) -> bool:
        if file_hash and file_hash.lower() in [h.lower() for h in self._data["whitelist"].get("hashes", [])]:
            return True
        if file_path:
            norm_path = file_path.lower().replace("/", "\\")
            for wp in self._data["whitelist"].get("paths", []):
                if norm_path == wp.lower().replace("/", "\\") or norm_path.startswith(wp.lower().replace("/", "\\") + "\\"):
                    return True
        return False
