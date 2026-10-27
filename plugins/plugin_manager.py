"""
Fikrado Security - AI Plugin Manager & Privacy Enforcement
Dynamically discovers and loads AI plugins from the plugins/ directory,
manages DPAPI-encrypted API keys, and enforces user privacy consent.
"""
import importlib
import inspect
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from config.constants import PLUGINS_DIR
from config.settings import SettingsManager
from core.crypto import decrypt_secret, encrypt_secret
from core.logger import logger
from plugins.base_plugin import BaseAIPlugin


class PluginManager:
    """Singleton manager for dynamic AI plugins and credentials."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PluginManager, cls).__new__(cls)
            cls._instance._plugins = {}
            cls._instance.settings = SettingsManager()
            cls._instance.load_plugins()
        return cls._instance

    def load_plugins(self):
        """Scans the plugins/ folder and registers all BaseAIPlugin implementations."""
        self._plugins.clear()

        # Import built-in plugins directly first
        from plugins.gemini_plugin import GeminiPlugin
        from plugins.openai_plugin import OpenAIPlugin
        from plugins.openrouter_plugin import OpenRouterPlugin
        from plugins.anthropic_plugin import AnthropicPlugin
        from plugins.ollama_plugin import OllamaPlugin
        from plugins.custom_plugin import CustomOpenAIPlugin

        builtins = [
            GeminiPlugin(),
            OpenAIPlugin(),
            OpenRouterPlugin(),
            AnthropicPlugin(),
            OllamaPlugin(),
            CustomOpenAIPlugin(),
        ]
        for p in builtins:
            self._plugins[p.plugin_id] = p

        # Dynamically scan plugins directory for external custom plugins
        if PLUGINS_DIR.exists():
            for file_path in PLUGINS_DIR.glob("*.py"):
                if file_path.name.startswith("__") or file_path.name == "base_plugin.py":
                    continue
                module_name = f"plugins.{file_path.stem}"
                try:
                    if module_name in sys.modules:
                        mod = importlib.reload(sys.modules[module_name])
                    else:
                        mod = importlib.import_module(module_name)

                    for _, obj in inspect.getmembers(mod, inspect.isclass):
                        if issubclass(obj, BaseAIPlugin) and obj is not BaseAIPlugin:
                            instance = obj()
                            self._plugins[instance.plugin_id] = instance
                            logger.info(f"Registered dynamic AI plugin: {instance.plugin_name} ({instance.plugin_id})")
                except Exception as e:
                    logger.debug(f"Could not load plugin from {file_path}: {e}")

        logger.info(f"Total AI plugins loaded: {len(self._plugins)}")

    def get_plugin(self, provider_id: str) -> Optional[BaseAIPlugin]:
        return self._plugins.get(provider_id)

    def get_all_plugins(self) -> List[BaseAIPlugin]:
        return list(self._plugins.values())

    def get_credentials(self, provider_id: str) -> Tuple[str, str, str]:
        """
        Retrieves decrypted API key, model name, and endpoint for a provider.
        Returns: (api_key, model_name, endpoint_url)
        """
        enc_keys = self.settings.get("ai", "encrypted_keys", {})
        encrypted_key = enc_keys.get(provider_id, "")
        api_key = decrypt_secret(encrypted_key) if encrypted_key else ""

        models = self.settings.get("ai", "models", {})
        model = models.get(provider_id, "")

        endpoints = self.settings.get("ai", "endpoints", {})
        endpoint = endpoints.get(provider_id, "")

        plugin = self.get_plugin(provider_id)
        if not model and plugin:
            model = plugin.default_model

        return api_key, model, endpoint

    def set_credentials(self, provider_id: str, api_key: str, model: str, endpoint: str = ""):
        """
        Saves API credentials with DPAPI encryption.
        Never stores plain-text API keys in settings.json or logs.
        """
        enc_keys = self.settings.get("ai", "encrypted_keys", {})
        if api_key:
            enc_keys[provider_id] = encrypt_secret(api_key)
        elif provider_id in enc_keys and api_key == "":
            del enc_keys[provider_id]
        self.settings.set("ai", "encrypted_keys", enc_keys, auto_save=False)

        models = self.settings.get("ai", "models", {})
        if model:
            models[provider_id] = model
        self.settings.set("ai", "models", models, auto_save=False)

        endpoints = self.settings.get("ai", "endpoints", {})
        if endpoint is not None:
            endpoints[provider_id] = endpoint
        self.settings.set("ai", "endpoints", endpoints, auto_save=True)

    def has_cloud_consent(self) -> bool:
        """Returns True if the user has consented to cloud AI transmission."""
        return bool(self.settings.get("ai", "cloud_consent_accepted", False))

    def set_cloud_consent(self, consent: bool):
        self.settings.set("ai", "cloud_consent_accepted", consent, auto_save=True)

    def prepare_file_for_ai(self, file_path: str, privacy_mode: str = "metadata_only") -> Tuple[dict, str]:
        """
        Extracts safe metadata and non-sensitive snippets for AI analysis
        based on the user's chosen privacy mode.
        """
        p = Path(file_path)
        if not p.exists():
            return {"error": "File does not exist"}, ""

        file_stat = p.stat()
        metadata = {
            "filename": p.name,
            "extension": p.suffix.lower(),
            "size_bytes": file_stat.st_size,
            "modified": file_stat.st_mtime,
        }

        # Calculate hash locally
        import hashlib
        try:
            with open(p, "rb") as f:
                head = f.read(64 * 1024)
                metadata["sha256_head"] = hashlib.sha256(head).hexdigest()
        except Exception:
            pass

        snippet = ""
        if privacy_mode == "metadata_only":
            snippet = "[Privacy Mode: Metadata only. No file content extracted or transmitted.]"

        elif privacy_mode in ("snippets", "full"):
            try:
                # If script or text file, extract initial lines
                if p.suffix.lower() in (".bat", ".cmd", ".ps1", ".vbs", ".js", ".py", ".sh", ".txt", ".json", ".xml"):
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        lines = [f.readline() for _ in range(50 if privacy_mode == "snippets" else 200)]
                        snippet = "".join(lines)
                else:
                    # Extract printable strings
                    with open(p, "rb") as f:
                        raw = f.read(16 * 1024 if privacy_mode == "snippets" else 64 * 1024)
                    chars = []
                    for b in raw:
                        if 32 <= b <= 126 or b in (10, 13):
                            chars.append(chr(b))
                        else:
                            chars.append(" ")
                    text = "".join(chars)
                    words = [w for w in text.split() if len(w) >= 5]
                    snippet = "Extracted Printable Strings:\n" + "\n".join(words[:100])
            except Exception as e:
                snippet = f"[Extraction error: {e}]"

        return metadata, snippet


plugin_manager = PluginManager()
