"""
Fikrado Security - OpenRouter AI Plugin
Provides access to hundreds of open-source and proprietary models through OpenRouter API.
"""
from typing import Tuple
import requests
from core.logger import logger
from plugins.base_plugin import BaseAIPlugin


class OpenRouterPlugin(BaseAIPlugin):

    @property
    def plugin_id(self) -> str:
        return "openrouter"

    @property
    def plugin_name(self) -> str:
        return "OpenRouter"

    @property
    def description(self) -> str:
        return "Unified router supporting DeepSeek, Claude, Llama 3, Mistral, and Gemini."

    @property
    def default_model(self) -> str:
        return "google/gemini-2.5-flash"

    def test_connection(self, api_key: str, model: str, endpoint: str = "") -> Tuple[bool, str]:
        if not api_key:
            return False, "OpenRouter API key is empty."
        try:
            url = "https://openrouter.ai/api/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "HTTP-Referer": "https://fikrado.security",
                "X-Title": "Fikrado Security",
                "Content-Type": "application/json"
            }
            payload = {
                "model": model or self.default_model,
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 5
            }
            resp = requests.post(url, headers=headers, json=payload, timeout=8)
            if resp.status_code == 200:
                return True, "Successfully connected to OpenRouter."
            return False, f"OpenRouter error (HTTP {resp.status_code}): {resp.text[:150]}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def explain_threat(self, threat_info: dict, api_key: str, model: str, endpoint: str = "") -> str:
        prompt = f"Explain this security threat and detail remediation:\n\n{threat_info}"
        return self._send_prompt(prompt, api_key, model, endpoint)

    def analyze_file(self, metadata: dict, snippet: str, api_key: str, model: str, endpoint: str = "") -> str:
        prompt = f"Analyze file metadata and snippet for malicious indicators:\nMETADATA:\n{metadata}\nSNIPPET:\n{snippet}"
        return self._send_prompt(prompt, api_key, model, endpoint)

    def analyze_logs(self, scan_summary: dict, api_key: str, model: str, endpoint: str = "") -> str:
        prompt = f"Review scan summary and propose mitigation steps:\n\n{scan_summary}"
        return self._send_prompt(prompt, api_key, model, endpoint)

    def _send_prompt(self, prompt: str, api_key: str, model: str, endpoint: str = "") -> str:
        if not api_key:
            return "Error: OpenRouter API key is not configured in Settings."
        try:
            url = "https://openrouter.ai/api/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "HTTP-Referer": "https://fikrado.security",
                "X-Title": "Fikrado Security",
                "Content-Type": "application/json"
            }
            payload = {
                "model": model or self.default_model,
                "messages": [
                    {"role": "system", "content": "You are Fikrado Security AI Assistant, specialized in Windows endpoint protection."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.2,
                "max_tokens": 1024
            }
            resp = requests.post(url, headers=headers, json=payload, timeout=25)
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"].strip()
            return f"OpenRouter API Error ({resp.status_code}): {resp.text[:300]}"
        except Exception as e:
            return f"Failed to contact OpenRouter: {str(e)}"
