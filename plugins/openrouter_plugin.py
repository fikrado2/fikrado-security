"""
Fikrado Security - OpenRouter AI Plugin v2
Provides AI-powered threat analysis via OpenRouter API with configurable v1 endpoint.
"""
from typing import Dict, List, Tuple
import requests
from core.logger import logger


class OpenRouterPlugin:
    """AI-powered threat analysis via OpenRouter with full v1 API support."""

    DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"

    @property
    def plugin_id(self) -> str:
        return "openrouter"

    @property
    def plugin_name(self) -> str:
        return "OpenRouter AI"

    @property
    def description(self) -> str:
        return (
            "AI-powered threat analysis via OpenRouter with configurable v1 endpoint. "
            "Supports DeepSeek, Claude, Llama, Mistral, Gemini, and 100+ models."
        )

    @property
    def default_model(self) -> str:
        return "google/gemini-2.5-flash"

    def test_connection(
        self,
        api_key: str,
        model: str,
        endpoint: str = "",
        base_url: str = "",
    ) -> Tuple[bool, str]:
        """
        Test the API connection using the configured endpoint or base URL.

        Args:
            api_key: API key for authentication
            model: Model to test (e.g. "google/gemini-2.5-flash")
            endpoint: Custom endpoint path (appended to base_url, e.g. "/v1/chat/completions")
            base_url: Custom base URL (overrides default openrouter.ai)
        """
        if not api_key:
            return False, "OpenRouter API key is empty."

        # Build URL: use custom base_url + endpoint, or default
        url_base = base_url.strip().rstrip("/") or self.DEFAULT_BASE_URL
        url_path = endpoint.strip() or "/v1/chat/completions"
        url = f"{url_base}{url_path}"

        headers = {
            "Authorization": f"Bearer {api_key}",
            "HTTP-Referer": "https://fikrado.security",
            "X-Title": "Fikrado Security",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model or self.default_model,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 5,
        }
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=12)
            if resp.status_code == 200:
                return True, f"Successfully connected to {url_base}{url_path}"
            return False, f"API error (HTTP {resp.status_code}): {resp.text[:200]}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def explain_threat(
        self,
        threat_info: dict,
        api_key: str,
        model: str,
        endpoint: str = "",
        base_url: str = "",
    ) -> str:
        """Explain a detected threat with AI and provide remediation."""
        prompt = f"""You are Fikrado Security AI — an expert cybersecurity analyst.

Analyze this detected threat and provide:
1. What it is and how it works
2. Risk severity (Critical/High/Medium/Low)
3. How it likely got onto this system
4. Step-by-step remediation steps
5. How to prevent it in the future

THREAT DETAILS:
{self._format_threat(threat_info)}"""
        return self._send_prompt(prompt, api_key, model, endpoint, base_url)

    def analyze_file(
        self,
        metadata: dict,
        snippet: str,
        api_key: str,
        model: str,
        endpoint: str = "",
        base_url: str = "",
    ) -> str:
        """Analyze file metadata and code snippet for malicious indicators."""
        prompt = f"""You are Fikrado Security AI — expert malware analyst.

Analyze this file for malicious indicators:

FILE METADATA:
{self._format_dict(metadata)}

CODE/HEX SNIPPET:
{snippet}

Provide:
1. Verdict: Malicious / Suspicious / Clean
2. Key indicators found
3. Recommended action
4. Additional context about this file type"""
        return self._send_prompt(prompt, api_key, model, endpoint, base_url)

    def analyze_logs(
        self,
        scan_summary: dict,
        api_key: str,
        model: str,
        endpoint: str = "",
        base_url: str = "",
    ) -> str:
        """Review scan summary and propose advanced mitigation steps."""
        prompt = f"""You are Fikrado Security AI — security operations advisor.

Review this scan summary and provide expert-level recommendations:

SCAN SUMMARY:
{self._format_dict(scan_summary)}

Provide:
1. Prioritized action items (top 5)
2. Any patterns suggesting a coordinated attack
3. Recommended additional scans
4. Hardening recommendations"""
        return self._send_prompt(prompt, api_key, model, endpoint, base_url)

    def analyze_bootkit(
        self,
        findings: List[dict],
        api_key: str,
        model: str,
        endpoint: str = "",
        base_url: str = "",
    ) -> str:
        """Analyze bootkit scan findings and prioritize response."""
        if not findings:
            return "No bootkit indicators found. System appears clean in boot sector integrity."
        findings_text = "\n".join(
            f"- [{f.get('severity','Unknown')}] {f.get('type','?')}: {f.get('detail','?')}"
            f" | Indicator: {f.get('indicator','?')[:80]}"
            for f in findings
        )
        prompt = f"""You are Fikrado Security AI — bootkit and firmware security expert.

Analyze these bootkit integrity findings and provide:
1. Risk prioritization (which findings are most critical)
2. Whether indicators suggest a sophisticated vs. commodity threat
3. Step-by-step incident response
4. Boot recovery procedure recommendations
5. How to verify bootkit was fully removed

FINDINGS:
{findings_text}"""
        return self._send_prompt(prompt, api_key, model, endpoint, base_url)

    def analyze_rootkit(
        self,
        findings: List[dict],
        api_key: str,
        model: str,
        endpoint: str = "",
        base_url: str = "",
    ) -> str:
        """Analyze rootkit scan findings and advise on remediation."""
        if not findings:
            return "No rootkit indicators found. System appears clean in kernel integrity."
        findings_text = "\n".join(
            f"- [{f.get('severity','Unknown')}] {f.get('type','?')}: {f.get('detail','?')}"
            f" | Indicator: {f.get('indicator','?')[:80]}"
            for f in findings
        )
        prompt = f"""You are Fikrado Security AI — rootkit detection and remediation expert.

Analyze these rootkit scan findings:
1. Severity assessment and threat actor implications
2. Recommended immediate containment steps
3. Full removal procedure (in order)
4. Post-remediation verification steps
5. Indicators of persistence to check

FINDINGS:
{findings_text}"""
        return self._send_prompt(prompt, api_key, model, endpoint, base_url)

    def _send_prompt(
        self,
        prompt: str,
        api_key: str,
        model: str,
        endpoint: str = "",
        base_url: str = "",
    ) -> str:
        if not api_key:
            return "Error: OpenRouter API key not configured. Go to Settings → AI Provider."

        url_base = base_url.strip().rstrip("/") or self.DEFAULT_BASE_URL
        url_path = endpoint.strip() or "/v1/chat/completions"
        url = f"{url_base}{url_path}"

        headers = {
            "Authorization": f"Bearer {api_key}",
            "HTTP-Referer": "https://fikrado.security",
            "X-Title": "Fikrado Security",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model or self.default_model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are Fikrado Security AI Assistant — a world-class cybersecurity expert. "
                    "Provide clear, actionable, technically precise analysis. Be direct and thorough.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 1536,
        }
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                if not content:
                    return "Received empty response from AI. Try a different model or check your API key."
                return content
            return f"OpenRouter API Error ({resp.status_code}): {resp.text[:300]}"
        except requests.exceptions.ConnectionError:
            return f"Connection failed to {url_base}. Check your network and base URL settings."
        except Exception as e:
            return f"Failed to contact OpenRouter: {str(e)}"

    def _format_threat(self, threat: dict) -> str:
        lines = [
            f"Threat Name: {threat.get('threat_name', 'Unknown')}",
            f"Type: {threat.get('threat_type', 'Unknown')}",
            f"Severity: {threat.get('severity', 'Unknown')}",
            f"Detection Engine: {threat.get('detection_engine', 'Unknown')}",
            f"File Path: {threat.get('file_path', 'N/A')}",
            f"Action Taken: {threat.get('action_taken', 'Flagged')}",
        ]
        return "\n".join(lines)

    def _format_dict(self, data: dict) -> str:
        return "\n".join(f"{k}: {v}" for k, v in data.items() if v)


# Alias for compatibility
openrouter_plugin = OpenRouterPlugin()
