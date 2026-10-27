"""
Fikrado Security - OpenAI Plugin
Supports GPT-4o, GPT-4o-mini, and other OpenAI models for threat analysis.
"""
from typing import Tuple
import requests
from core.logger import logger
from plugins.base_plugin import BaseAIPlugin


class OpenAIPlugin(BaseAIPlugin):

    @property
    def plugin_id(self) -> str:
        return "openai"

    @property
    def plugin_name(self) -> str:
        return "OpenAI"

    @property
    def description(self) -> str:
        return "OpenAI GPT-4o series models for deep security reasoning and script analysis."

    @property
    def default_model(self) -> str:
        return "gpt-4o-mini"

    def test_connection(self, api_key: str, model: str, endpoint: str = "") -> Tuple[bool, str]:
        if not api_key:
            return False, "API key is empty."
        try:
            url = (endpoint.rstrip("/") + "/chat/completions") if endpoint else "https://api.openai.com/v1/chat/completions"
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            payload = {
                "model": model or self.default_model,
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 5
            }
            resp = requests.post(url, headers=headers, json=payload, timeout=8)
            if resp.status_code == 200:
                return True, "Successfully authenticated with OpenAI API."
            return False, f"OpenAI error (HTTP {resp.status_code}): {resp.text[:150]}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def explain_threat(self, threat_info: dict, api_key: str, model: str, endpoint: str = "") -> str:
        prompt = (
            "You are a Senior Windows Cybersecurity Analyst for Fikrado Security. "
            "Explain this detected threat clearly: 1) What it is, 2) Impact, 3) Remediation.\n\n"
            f"{threat_info}"
        )
        return self._send_prompt(prompt, api_key, model, endpoint)

    def analyze_file(self, metadata: dict, snippet: str, api_key: str, model: str, endpoint: str = "") -> str:
        prompt = (
            "Analyze the following file metadata and extracted code/script snippet. "
            "Output malicious probability (0-100%), MITRE ATT&CK techniques, and clear verdict:\n\n"
            f"METADATA:\n{metadata}\n\nSNIPPET:\n{snippet}"
        )
        return self._send_prompt(prompt, api_key, model, endpoint)

    def analyze_logs(self, scan_summary: dict, api_key: str, model: str, endpoint: str = "") -> str:
        prompt = f"Audit this endpoint scan report and provide prioritized remediation:\n\n{scan_summary}"
        return self._send_prompt(prompt, api_key, model, endpoint)

    def _send_prompt(self, prompt: str, api_key: str, model: str, endpoint: str = "") -> str:
        if not api_key:
            return "Error: OpenAI API key is not configured. Please add your key in Settings."
        try:
            url = (endpoint.rstrip("/") + "/chat/completions") if endpoint else "https://api.openai.com/v1/chat/completions"
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            payload = {
                "model": model or self.default_model,
                "messages": [
                    {"role": "system", "content": "You are Fikrado Security AI Assistant, specialized in endpoint defense."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.2,
                "max_tokens": 1024
            }
            resp = requests.post(url, headers=headers, json=payload, timeout=25)
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"].strip()
            return f"OpenAI API Error ({resp.status_code}): {resp.text[:300]}"
        except Exception as e:
            return f"Failed to contact OpenAI: {str(e)}"
