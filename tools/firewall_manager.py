"""
Fikrado Security - Cross-Platform Firewall Manager
View and toggle firewall profiles (Domain, Private, Public), view active rules, and add rules.
Works on Windows, Linux, and macOS.
"""
from typing import Dict, List, Optional, Tuple
import os
from core.logger import logger
from core.subprocess_utils import run_hidden
from core.platforms import IS_WINDOWS, IS_MACOS, IS_LINUX
from core.system_info import get_firewall_profiles_status, get_firewall_enabled


class FirewallManager:

    def get_profiles_status(self, deep: bool = False) -> Dict[str, bool]:
        """Returns enabled state for Domain, Private, and Public profiles.
        On non-Windows, returns empty dict and informs user via get_firewall_enabled.
        """
        if IS_WINDOWS:
            return get_firewall_profiles_status(deep=deep)
        return {}

    def get_recent_rules(self, limit: int = 50) -> List[dict]:
        """Lists recent firewall rules.
        On non-Windows, returns empty list.
        """
        if IS_WINDOWS:
            rules = []
            try:
                cmd = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
                res = run_hidden(cmd, capture_output=True, text=True, timeout=10)
                if res.returncode == 0:
                    current_rule = {}
                    for line in res.stdout.splitlines():
                        line = line.strip()
                        if not line:
                            if current_rule and "Rule Name" in current_rule:
                                rules.append(current_rule)
                                current_rule = {}
                                if len(rules) >= limit:
                                    break
                            continue
                        if ":" in line:
                            parts = line.split(":", 1)
                            current_rule[parts[0].strip()] = parts[1].strip()
                    return rules[:limit]
                logger.debug(f"Error listing firewall rules: {res.stderr or res.stdout}")
            except Exception as e:
                logger.debug(f"Error listing firewall rules: {e}")
        return []

    def toggle_profile(self, profile: str, enable: bool) -> Tuple[bool, str]:
        """Toggles a specific profile or all profiles on/off.
        On non-Windows, returns failure message.
        """
        if IS_WINDOWS:
            prof_arg = profile.lower() if profile.lower() in ("domain", "private", "public") else "allprofiles"
            state_arg = "on" if enable else "off"
            try:
                cmd = ["netsh", "advfirewall", "set", prof_arg, "state", state_arg]
                res = run_hidden(cmd, capture_output=True, text=True, timeout=6)
                if res.returncode == 0:
                    return True, f"Firewall profile '{profile}' set to {state_arg.upper()}."
                return False, f"netsh error: {res.stderr or res.stdout}"
            except Exception as e:
                return False, f"Failed to execute netsh: {str(e)}"
        return False, "Firewall profile toggling is only available on Windows platforms."

    def add_block_rule(self, name: str, port: int, protocol: str = "TCP") -> Tuple[bool, str]:
        """Adds an inbound block rule.
        On non-Windows, returns platform-notice.
        """
        if IS_WINDOWS:
            try:
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={name}",
                    "dir=in",
                    "action=block",
                    f"protocol={protocol}",
                    f"localport={port}"
                ]
                res = run_hidden(cmd, capture_output=True, text=True, timeout=6)
                if res.returncode == 0 and "Ok." in res.stdout:
                    return True, f"Blocked {protocol} port {port} under rule '{name}'."
                return False, f"Failed: {res.stderr or res.stdout}"
            except Exception as e:
                return False, str(e)
        return False, "Firewall rule management is only available on Windows platforms."

    def get_firewall_enabled(self, deep: bool = False):
        """Cross-platform single firewall verdict.
        Returns True/False when the host firewall state can be determined, or None when no supported firewall backend is available.
        """
        if IS_WINDOWS:
            profiles = get_firewall_profiles_status(deep=deep)
            return all(profiles.values()) if profiles else None

        if IS_MACOS:
            socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
            if os.path.exists(socketfilterfw):
                try:
                    res = run_hidden([socketfilterfw, "--getglobalstate"], timeout=5)
                    if res.returncode == 0:
                        return "enabled" in res.stdout.lower()
                except Exception as exc:
                    logger.debug(f"socketfilterfw probe failed: {exc}")
            return None

        # Linux: prefer a firewall manager CLI, then fall back to the raw backends.
        probes = (
            (["ufw", "status"], lambda out: out.strip().startswith("Status: active")),
            (["firewall-cmd", "--state"], lambda out: out.strip() == "running"),
            (["nft", "list", "ruleset"], lambda out: bool(out.strip())),
            (["iptables", "-S"], lambda out: bool(out.strip())),
        )
        for cmd, predicate in probes:
            try:
                res = run_hidden(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0 and predicate(res.stdout):
                    return True
            except Exception as exc:
                logger.debug(f"Firewall probe failed: {exc}")
        return None


firewall_manager = FirewallManager()