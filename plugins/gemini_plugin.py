"""
Fikrado Security - Google Gemini AI Plugin
Communicates directly with Google Gemini REST API.
"""
from typing import Tuple
import requests
from core.logger import logger
from plugins.base_plugin import BaseAIPlugin


class GeminiPlugin(BaseAIPlugin):

    @property
    def plugin_id(self) -> str:
        return "gemini"

    @property
    def plugin_name(self) -> str:
        return "Google Gemini"

    @property
    def description(self) -> str:
        return "Google Gemini multimodal intelligence for high-speed threat reasoning."

    @property
    def default_model(self) -> str:
        return "gemini-2.5-flash"

    def test_connection(self, api_key: str, model: str, endpoint: str = "") -> Tuple[bool, str]:
        if not api_key:
            return False, "API key is empty."
        try:
            m = model or self.default_model
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent?key={api_key}"
            payload = {
                "contents": [{"parts": [{"text": "Say 'OK' if you receive this."}]}],
                "generationConfig": {"maxOutputTokens": 10}
            }
            resp = requests.post(url, json=payload, timeout=8)
            if resp.status_code == 200:
                return True, "Successfully connected to Google Gemini API."
            return False, f"Gemini error (HTTP {resp.status_code}): {resp.text[:150]}"
        except Exception as e:
            return False, f"Connection failed: {str(e)}"

    def explain_threat(self, threat_info: dict, api_key: str, model: str, endpoint: str = "") -> str:
        prompt = (
            "You are a Senior Windows Cybersecurity Analyst for Fikrado Security. "
            "Explain this detected threat in clear, professional English for the user. "
            "Explain: 1) What it is, 2) Potential impact if executed, 3) Specific step-by-step remediation.\n\n"
            f"Threat Name: {threat_info.get('threat_name')}\n"
            f"Threat Type: {threat_info.get('threat_type')}\n"
            f"Severity: {threat_info.get('severity')}\n"
            f"File Path: {threat_info.get('file_path')}\n"
            f"Detection Engine: {threat_info.get('engine')}\n"
            f"Description: {threat_info.get('description')}\n"
        )
        return self._send_prompt(prompt, api_key, model, endpoint)

    def analyze_file(self, metadata: dict, snippet: str, api_key: str, model: str, endpoint: str = "") -> str:
        prompt = (
            "You are a Malware Reverse Engineer. Analyze the following extracted file metadata, "
            "PE imports, strings, or script contents. Provide: 1) Malicious probability score (0-100%), "
            "2) Identified TTPs / MITRE ATT&CK techniques, 3) Verdict (Benign, Suspicious, Malicious), "
            "4) Recommended immediate action.\n\n"
            f"FILE METADATA:\n{metadata}\n\n"
            f"EXTRACTED CONTENT SNIPPET:\n{snippet}"
        )
        return self._send_prompt(prompt, api_key, model, endpoint)

    def analyze_logs(self, scan_summary: dict, api_key: str, model: str, endpoint: str = "") -> str:
        prompt = (
            "You are a Chief Information Security Officer (CISO). Review this endpoint audit scan report "
            "and output an Executive Summary and Prioritized Action Checklist:\n\n"
            f"{scan_summary}"
        )
        return self._send_prompt(prompt, api_key, model, endpoint)

    def _send_prompt(self, prompt: str, api_key: str, model: str, endpoint: str = "") -> str:
        if not api_key:
            return "Error: Gemini API key is not configured. Please add your key in Settings."
        try:
            m = model or self.default_model
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent?key={api_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1024}
            }
            resp = requests.post(url, json=payload, timeout=25)
            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        return parts[0].get("text", "No response text received.")
                return "Empty response returned by Gemini."
            return f"Gemini API Error ({resp.status_code}): {resp.text[:300]}"
        except Exception as e:
            logger.error(f"Gemini API request failed: {e}")
            return f"Failed to contact Google Gemini: {str(e)}"
