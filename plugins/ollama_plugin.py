"""
Fikrado Security - Ollama (Local AI) Plugin
Communicates with locally running Ollama instance (100% private, on-device).
"""
from typing import Tuple
import requests
from core.logger import logger
from plugins.base_plugin import BaseAIPlugin


class OllamaPlugin(BaseAIPlugin):

    @property
    def plugin_id(self) -> str:
        return "ollama"

    @property
    def plugin_name(self) -> str:
        return "Ollama (Local On-Device)"

    @property
    def description(self) -> str:
        return "Completely local, private LLM execution without sending any data over the internet."

    @property
    def default_model(self) -> str:
        return "llama3.2:latest"

    @property
    def is_local(self) -> bool:
        return True

    def test_connection(self, api_key: str, model: str, endpoint: str = "") -> Tuple[bool, str]:
        base_url = endpoint or "http://localhost:11434"
        try:
            url = f"{base_url.rstrip('/')}/api/tags"
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                models = [m.get("name") for m in resp.json().get("models", [])]
                model_str = f"Available models: {', '.join(models[:5])}" if models else "No models loaded."
                return True, f"Connected to local Ollama instance. {model_str}"
            return False, f"Ollama returned HTTP {resp.status_code}"
        except Exception as e:
            return False, f"Cannot reach Ollama at {base_url}. Ensure 'ollama serve' is running."

    def explain_threat(self, threat_info: dict, api_key: str, model: str, endpoint: str = "") -> str:
        prompt = f"Explain this security threat and remediation in plain language:\n\n{threat_info}"
        return self._send_prompt(prompt, api_key, model, endpoint)

    def analyze_file(self, metadata: dict, snippet: str, api_key: str, model: str, endpoint: str = "") -> str:
        prompt = f"Analyze file metadata and snippet for malicious indicators:\nMETADATA:\n{metadata}\nSNIPPET:\n{snippet}"
        return self._send_prompt(prompt, api_key, model, endpoint)

    def analyze_logs(self, scan_summary: dict, api_key: str, model: str, endpoint: str = "") -> str:
        prompt = f"Audit this endpoint scan report and provide prioritized actions:\n\n{scan_summary}"
        return self._send_prompt(prompt, api_key, model, endpoint)

    def _send_prompt(self, prompt: str, api_key: str, model: str, endpoint: str = "") -> str:
        base_url = endpoint or "http://localhost:11434"
        try:
            url = f"{base_url.rstrip('/')}/api/generate"
            payload = {
                "model": model or self.default_model,
                "prompt": f"System: You are Fikrado Security AI Assistant. Protect Windows endpoints.\nUser: {prompt}\nAssistant:",
                "stream": False,
                "options": {"temperature": 0.2}
            }
            resp = requests.post(url, json=payload, timeout=45)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("response", "No response received from local Ollama.")
            return f"Ollama Error (HTTP {resp.status_code}): {resp.text[:200]}"
        except Exception as e:
            return f"Failed to connect to local Ollama service: {str(e)}"
