"""
Fikrado Security - Windows Firewall Manager
View and toggle firewall profiles (Domain, Private, Public), view active rules, and add rules.
"""
from typing import Dict, List, Tuple
from core.subprocess_utils import run_hidden
from core.logger import logger


class FirewallManager:

    def get_profiles_status(self) -> Dict[str, bool]:
        """Returns enabled state for Domain, Private, and Public profiles."""
        status = {"Domain": True, "Private": True, "Public": True}
        try:
            res = run_hidden(["netsh", "advfirewall", "show", "allprofiles", "state"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                current_profile = None
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if "Domain Profile Settings" in line:
                        current_profile = "Domain"
                    elif "Private Profile Settings" in line:
                        current_profile = "Private"
                    elif "Public Profile Settings" in line:
                        current_profile = "Public"
                    elif current_profile and "State" in line:
                        status[current_profile] = "ON" in line.upper()
        except Exception as e:
            logger.error(f"Error querying firewall profiles: {e}")
        return status

    def toggle_profile(self, profile: str, enable: bool) -> Tuple[bool, str]:
        """Toggles a specific profile or all profiles on/off."""
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

    def get_recent_rules(self, limit: int = 50) -> List[dict]:
        """Lists recent Windows Firewall rules."""
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
        except Exception as e:
            logger.debug(f"Error listing firewall rules: {e}")
        return rules

    def add_block_rule(self, name: str, port: int, protocol: str = "TCP") -> Tuple[bool, str]:
        """Adds an inbound block rule."""
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


firewall_manager = FirewallManager()
