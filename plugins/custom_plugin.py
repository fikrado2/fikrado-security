"""
Fikrado Security - Custom OpenAI-Compatible Endpoint Plugin
Supports any custom self-hosted vLLM, LM Studio, LocalAI, Groq, Mistral, or custom gateway.
"""
from typing import Tuple
import requests
from core.logger import logger
from plugins.base_plugin import BaseAIPlugin


class CustomOpenAIPlugin(BaseAIPlugin):

    @property
    def plugin_id(self) -> str:
        return "custom"

    @property
    def plugin_name(self) -> str:
        return "Custom OpenAI-Compatible Endpoint"

    @property
    def description(self) -> str:
        return "Connect to any custom OpenAI-compatible server (LM Studio, vLLM, Groq, Mistral, etc.)."

    @property
    def default_model(self) -> str:
        return "default-model"

    def test_connection(self, api_key: str, model: str, endpoint: str = "") -> Tuple[bool, str]:
        if not endpoint:
            return False, "Custom endpoint Base URL is required."
        try:
            url = endpoint.rstrip("/") + "/chat/completions"
            headers = {"Content-Type": "application/json"}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            payload = {
                "model": model or self.default_model,
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 5
            }
            resp = requests.post(url, headers=headers, json=payload, timeout=8)
            if resp.status_code == 200:
                return True, "Successfully connected to custom endpoint."
            return False, f"Server responded with HTTP {resp.status_code}: {resp.text[:150]}"
        except Exception as e:
            return False, f"Connection failed: {str(e)}"

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
        if not endpoint:
            return "Error: Custom endpoint Base URL is not configured. Please configure it in Settings."
        try:
            url = endpoint.rstrip("/") + "/chat/completions"
            headers = {"Content-Type": "application/json"}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            payload = {
                "model": model or self.default_model,
                "messages": [
                    {"role": "system", "content": "You are Fikrado Security AI Assistant."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.2,
                "max_tokens": 1024
            }
            resp = requests.post(url, headers=headers, json=payload, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"].strip()
            return f"Custom Endpoint Error ({resp.status_code}): {resp.text[:300]}"
        except Exception as e:
            return f"Failed to contact custom endpoint: {str(e)}"
