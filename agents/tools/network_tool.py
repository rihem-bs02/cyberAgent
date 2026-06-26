"""
Network Utility Tools
Lightweight tools for DNS resolution, WHOIS, connectivity checks.
No external dependencies beyond stdlib + requests.
"""
import socket
import subprocess
import requests
import ipaddress
import os, sys
from loguru import logger


class NetworkTool:

    def resolve_hostname(self, hostname: str) -> list[str]:
        """Resolve hostname to IP addresses."""
        try:
            results = socket.getaddrinfo(hostname, None)
            ips = list({r[4][0] for r in results})
            logger.info(f"Resolved {hostname} → {ips}")
            return ips
        except Exception as e:
            logger.warning(f"DNS resolution failed for {hostname}: {e}")
            return []

    def reverse_dns(self, ip: str) -> str:
        """Reverse DNS lookup."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return ""

    def is_alive(self, host: str, timeout: int = 2) -> bool:
        """Quick ping check using TCP connect to port 80 or 443."""
        for port in [80, 443, 22, 445]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    return True
            except Exception:
                continue
        return False

    def expand_cidr(self, cidr: str) -> list[str]:
        """Expand CIDR notation to list of IPs (capped at 256)."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
            logger.info(f"CIDR {cidr} expanded to {len(hosts)} hosts")
            return hosts[:256]
        except ValueError:
            return [cidr]

    def parse_target(self, target_input: str) -> dict:
        """
        Parse any target input format into structured dict.
        Handles: IP, CIDR, hostname, IP range (192.168.1.1-50)
        """
        result = {
            "raw":      target_input,
            "type":     "unknown",
            "hosts":    [],
            "is_range": False,
        }

        target = target_input.strip()

        # CIDR
        if "/" in target:
            result["type"]     = "cidr"
            result["is_range"] = True
            result["hosts"]    = self.expand_cidr(target)
            return result

        # IP range (192.168.1.1-50)
        if "-" in target and target.replace(".", "").replace("-", "").isdigit():
            parts  = target.split("-")
            base   = ".".join(parts[0].split(".")[:3])
            start  = int(parts[0].split(".")[-1])
            end    = int(parts[1])
            result["type"]     = "range"
            result["is_range"] = True
            result["hosts"]    = [f"{base}.{i}" for i in range(start, end + 1)]
            return result

        # Single IP
        try:
            ipaddress.ip_address(target)
            result["type"]  = "ip"
            result["hosts"] = [target]
            return result
        except ValueError:
            pass

        # Hostname
        result["type"]  = "hostname"
        ips = self.resolve_hostname(target)
        result["hosts"] = ips if ips else [target]
        return result

    def check_port(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Quick TCP port check."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def grab_banner(self, host: str, port: int, timeout: float = 3.0) -> str:
        """Grab service banner from open port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            return banner[:500]
        except Exception:
            return ""
