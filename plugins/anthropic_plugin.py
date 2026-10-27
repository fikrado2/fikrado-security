"""
Fikrado Security - Anthropic Claude Plugin
Communicates with Anthropic Messages API using Claude 3.5 Sonnet / Haiku.
"""
from typing import Tuple
import requests
from core.logger import logger
from plugins.base_plugin import BaseAIPlugin


class AnthropicPlugin(BaseAIPlugin):

    @property
    def plugin_id(self) -> str:
        return "anthropic"

    @property
    def plugin_name(self) -> str:
        return "Anthropic Claude"

    @property
    def description(self) -> str:
        return "Claude 3.5 Sonnet advanced code comprehension and cybersecurity reasoning."

    @property
    def default_model(self) -> str:
        return "claude-3-5-sonnet-20241022"

    def test_connection(self, api_key: str, model: str, endpoint: str = "") -> Tuple[bool, str]:
        if not api_key:
            return False, "Anthropic API key is empty."
        try:
            url = "https://api.anthropic.com/v1/messages"
            headers = {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            }
            payload = {
                "model": model or self.default_model,
                "max_tokens": 10,
                "messages": [{"role": "user", "content": "hello"}]
            }
            resp = requests.post(url, headers=headers, json=payload, timeout=8)
            if resp.status_code == 200:
                return True, "Successfully authenticated with Anthropic Claude API."
            return False, f"Anthropic error (HTTP {resp.status_code}): {resp.text[:150]}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def explain_threat(self, threat_info: dict, api_key: str, model: str, endpoint: str = "") -> str:
        prompt = f"Explain this security threat and remediation in plain language:\n\n{threat_info}"
        return self._send_prompt(prompt, api_key, model, endpoint)

    def analyze_file(self, metadata: dict, snippet: str, api_key: str, model: str, endpoint: str = "") -> str:
        prompt = f"Analyze file metadata and snippet for malicious intent:\nMETADATA:\n{metadata}\nSNIPPET:\n{snippet}"
        return self._send_prompt(prompt, api_key, model, endpoint)

    def analyze_logs(self, scan_summary: dict, api_key: str, model: str, endpoint: str = "") -> str:
        prompt = f"Audit this endpoint scan report and provide prioritized actions:\n\n{scan_summary}"
        return self._send_prompt(prompt, api_key, model, endpoint)

    def _send_prompt(self, prompt: str, api_key: str, model: str, endpoint: str = "") -> str:
        if not api_key:
            return "Error: Anthropic API key is not configured. Please add your key in Settings."
        try:
            url = "https://api.anthropic.com/v1/messages"
            headers = {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            }
            payload = {
                "model": model or self.default_model,
                "max_tokens": 1024,
                "system": "You are Fikrado Security AI Assistant, specialized in Windows endpoint protection and malware analysis.",
                "messages": [{"role": "user", "content": prompt}]
            }
            resp = requests.post(url, headers=headers, json=payload, timeout=25)
            if resp.status_code == 200:
                data = resp.json()
                content = data.get("content", [])
                if content and isinstance(content, list):
                    return content[0].get("text", "No response text.")
                return "Empty response returned by Claude."
            return f"Anthropic API Error ({resp.status_code}): {resp.text[:300]}"
        except Exception as e:
            return f"Failed to contact Anthropic: {str(e)}"
