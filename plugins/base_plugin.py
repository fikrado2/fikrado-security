"""
Fikrado Security - AI Plugin Base Interface
All AI providers (OpenRouter, OpenAI, Claude, Gemini, Ollama, Custom) implement this contract.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple


class BaseAIPlugin(ABC):
    """Abstract Base Class for security AI analysis providers."""

    @property
    @abstractmethod
    def plugin_id(self) -> str:
        """Unique internal identifier (e.g. 'gemini', 'openai')."""
        pass

    @property
    @abstractmethod
    def plugin_name(self) -> str:
        """User-friendly display name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Short summary of this AI provider."""
        pass

    @property
    @abstractmethod
    def default_model(self) -> str:
        """Default model name."""
        pass

    @property
    def is_local(self) -> bool:
        """True if the model runs completely on-device without cloud transmission."""
        return False

    @abstractmethod
    def test_connection(self, api_key: str, model: str, endpoint: str = "") -> Tuple[bool, str]:
        """Validates API credentials with a minimal prompt."""
        pass

    @abstractmethod
    def explain_threat(self, threat_info: dict, api_key: str, model: str, endpoint: str = "") -> str:
        """Translates a flagged file, signature, or heuristic alert into plain English with mitigation steps."""
        pass

    @abstractmethod
    def analyze_file(self, metadata: dict, snippet: str, api_key: str, model: str, endpoint: str = "") -> str:
        """Analyzes extracted strings, PE imports, and script contents for malicious intent."""
        pass

    @abstractmethod
    def analyze_logs(self, scan_summary: dict, api_key: str, model: str, endpoint: str = "") -> str:
        """Audits scan results and provides an executive remediation plan."""
        pass

    def analyze_ports_and_startup(self, port_items: list, startup_items: list, api_key: str, model: str, endpoint: str = "") -> str:
        """Evaluates open listening ports and registry startup items for stealth intrusion."""
        prompt = (
            "You are a Tier-3 Cybersecurity Incident Responder. Analyze the following open listening ports "
            "and startup persistence entries detected on a Windows endpoint. Highlight any anomalies, risky "
            "services, or persistence mechanisms and provide exact remediation instructions:\n\n"
            f"OPEN PORTS:\n{port_items}\n\n"
            f"STARTUP ITEMS:\n{startup_items}"
        )
        return self._send_prompt(prompt, api_key, model, endpoint)

    @abstractmethod
    def _send_prompt(self, prompt: str, api_key: str, model: str, endpoint: str = "") -> str:
        """Internal helper to communicate with the provider API."""
        pass
