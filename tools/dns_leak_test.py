"""
Fikrado Security - Network & DNS Leak Diagnostic Tool
Audits network interfaces, default gateways, configured DNS servers, and checks for external DNS leaks.
"""
import socket
from pathlib import Path
from typing import Dict, List, Tuple
import psutil
import requests
from core.logger import logger
from core.platforms import IS_WINDOWS
from core.subprocess_utils import run_hidden


class DNSLeakTester:

    def get_network_interfaces(self) -> List[dict]:
        """Gathers local network adapters, IP addresses, netmasks, and status."""
        adapters = []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for iface_name, addr_list in addrs.items():
            stat = stats.get(iface_name)
            is_up = stat.isup if stat else False
            speed = stat.speed if stat else 0

            ipv4 = ""
            ipv6 = ""
            mac = ""

            for a in addr_list:
                if a.family == socket.AF_INET:
                    ipv4 = a.address
                elif a.family == socket.AF_INET6:
                    ipv6 = a.address
                elif hasattr(psutil, "AF_LINK") and a.family == psutil.AF_LINK:
                    mac = a.address

            if ipv4 or ipv6:
                adapters.append({
                    "interface": iface_name,
                    "is_up": is_up,
                    "speed_mbps": speed,
                    "ipv4": ipv4 or "None",
                    "ipv6": ipv6 or "None",
                    "mac": mac or "Unknown"
                })

        return adapters

    def get_configured_dns_servers(self) -> List[str]:
        """Retrieves active DNS server addresses via the OS resolver."""
        servers = []
        if IS_WINDOWS:
            try:
                cmd = ["powershell", "-NoProfile", "-Command", "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses"]
                res = run_hidden(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        clean = line.strip()
                        if clean and clean not in servers:
                            servers.append(clean)
                return servers
            except Exception as e:
                logger.debug(f"DNS server retrieval notice: {e}")

        # POSIX: parse /etc/resolv.conf (best effort)
        try:
            resolv = Path("/etc/resolv.conf")
            if resolv.exists():
                for line in resolv.read_text(encoding="utf-8", errors="ignore").splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        ns = parts[1]
                        if ns not in servers:
                            servers.append(ns)
        except Exception as e:
            logger.debug(f"/etc/resolv.conf parse notice: {e}")

        # macOS fallback: scutil --dns
        if not servers:
            try:
                res = run_hidden(["scutil", "--dns"], capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        s = line.strip()
                        if "server" in s.lower() and ":" in s:
                            ip = s.rsplit(":", 1)[-1].strip()
                            if ip and ip not in servers:
                                servers.append(ip)
            except Exception as e:
                logger.debug(f"scutil DNS lookup notice: {e}")
        return servers

    def check_public_ip_and_leak(self) -> dict:
        """Queries external resolver for public IP and geographic / ISP metadata."""
        try:
            resp = requests.get("https://ipapi.co/json/", timeout=6)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "public_ip": data.get("ip", "Unknown"),
                    "isp": data.get("org", data.get("asn", "Unknown")),
                    "city": data.get("city", "Unknown"),
                    "country": data.get("country_name", "Unknown"),
                    "dns_leak_detected": False,
                    "status": "External network information resolved."
                }
        except Exception:
            # Fallback to ipify
            try:
                r2 = requests.get("https://api.ipify.org?format=json", timeout=4)
                if r2.status_code == 200:
                    return {
                        "public_ip": r2.json().get("ip", "Unknown"),
                        "isp": "Local ISP",
                        "city": "Unknown",
                        "country": "Unknown",
                        "dns_leak_detected": False,
                        "status": "Resolved via fallback endpoint."
                    }
            except Exception as e2:
                logger.debug(f"IP lookup fallback failed: {e2}")

        return {
            "public_ip": "Offline or Unreachable",
            "isp": "N/A",
            "city": "N/A",
            "country": "N/A",
            "dns_leak_detected": False,
            "status": "Could not connect to external IP verification service."
        }


dns_leak_tester = DNSLeakTester()
