"""
Nmap Tool Wrapper
Real network scanning using python-nmap.
Requires nmap installed on the system:
  Windows: https://nmap.org/download.html
  Add nmap to PATH after install.
"""
import nmap
import socket
import ipaddress
import os, sys
from loguru import logger
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class NmapTool:
    """
    Wraps python-nmap for agent use.
    All scans return structured dicts that feed directly into CampaignState.
    """

    def __init__(self):
        try:
            self.scanner = nmap.PortScanner()
            logger.success("Nmap initialized successfully")
        except nmap.PortScannerError as e:
            logger.error(f"Nmap not found: {e}")
            logger.error("Install nmap from https://nmap.org/download.html and add to PATH")
            self.scanner = None

    def is_available(self) -> bool:
        return self.scanner is not None

    def ping_sweep(self, target: str) -> list[str]:
        """
        Phase 1 — discover live hosts.
        Returns list of active IP addresses.
        target: IP, subnet (192.168.1.0/24), or range
        """
        if not self.is_available():
            logger.warning("Nmap unavailable — returning target as single host")
            return [target]

        logger.info(f"Ping sweep: {target}")
        try:
            self.scanner.scan(
                hosts=target,
                arguments="-sn -T4 --min-rate 1000"
            )
            hosts = []
            for host in self.scanner.all_hosts():
                if self.scanner[host].state() == "up":
                    hosts.append(host)
            logger.success(f"Ping sweep complete: {len(hosts)} hosts up")
            return hosts
        except Exception as e:
            logger.error(f"Ping sweep failed: {e}")
            return [target]

    def port_scan(
        self,
        host: str,
        stealth: str = "high",
        ports: str = "1-1024,3306,3389,5432,5900,8080,8443,9200,27017"
    ) -> dict:
        """
        Phase 2 — scan ports and detect services on a single host.
        stealth: high → SYN scan slow | medium → SYN normal | low → aggressive
        Returns structured dict: {port: {state, service, version, product}}
        """
        if not self.is_available():
            logger.warning("Nmap unavailable — returning empty port scan")
            return {}

        # Stealth-based scan arguments
        stealth_args = {
            "high":   f"-sS -T2 -p {ports} -sV --version-intensity 3 --open",
            "medium": f"-sS -T3 -p {ports} -sV --open",
            "low":    f"-sS -T4 -p {ports} -sV -sC --open",
        }
        args = stealth_args.get(stealth, stealth_args["high"])

        logger.info(f"Port scan: {host} | stealth={stealth}")
        try:
            self.scanner.scan(hosts=host, arguments=args)

            if host not in self.scanner.all_hosts():
                logger.warning(f"Host {host} not responding")
                return {}

            results = {}
            tcp = self.scanner[host].get("tcp", {})
            for port, data in tcp.items():
                if data.get("state") == "open":
                    results[port] = {
                        "state":   data.get("state", ""),
                        "service": data.get("name", ""),
                        "version": data.get("version", ""),
                        "product": data.get("product", ""),
                        "extra":   data.get("extrainfo", ""),
                        "cpe":     data.get("cpe", ""),
                    }

            logger.success(f"Port scan {host}: {len(results)} open ports")
            return results

        except Exception as e:
            logger.error(f"Port scan failed on {host}: {e}")
            return {}

    def os_detection(self, host: str) -> dict:
        """
        Detect OS on target host.
        Requires root/admin privileges for OS detection.
        """
        if not self.is_available():
            return {"os": "unknown", "accuracy": 0}

        logger.info(f"OS detection: {host}")
        try:
            self.scanner.scan(hosts=host, arguments="-O --osscan-guess -T3")
            os_matches = self.scanner[host].get("osmatch", [])
            if os_matches:
                best = os_matches[0]
                return {
                    "os":       best.get("name", "unknown"),
                    "accuracy": best.get("accuracy", "0"),
                    "type":     best.get("osclass", [{}])[0].get("type", ""),
                    "vendor":   best.get("osclass", [{}])[0].get("vendor", ""),
                    "family":   best.get("osclass", [{}])[0].get("osfamily", ""),
                }
            return {"os": "unknown", "accuracy": 0}
        except Exception as e:
            logger.error(f"OS detection failed: {e}")
            return {"os": "unknown", "accuracy": 0}

    def vuln_scan(self, host: str, ports: list[int]) -> dict:
        """
        Run nmap vuln scripts on specific open ports.
        Uses nmap NSE scripts: vuln, auth, default categories.
        """
        if not self.is_available():
            return {}

        port_str = ",".join(str(p) for p in ports[:20])  # cap at 20 ports
        logger.info(f"Vuln scan: {host} ports={port_str}")
        try:
            self.scanner.scan(
                hosts=host,
                arguments=f"-sV -p {port_str} --script=vuln,auth -T3"
            )
            results = {}
            tcp = self.scanner[host].get("tcp", {})
            for port, data in tcp.items():
                scripts = data.get("script", {})
                if scripts:
                    results[port] = {
                        "service": data.get("name", ""),
                        "scripts": scripts,
                    }
            logger.success(f"Vuln scan {host}: {len(results)} ports with findings")
            return results
        except Exception as e:
            logger.error(f"Vuln scan failed: {e}")
            return {}

    def service_fingerprint(self, host: str, port: int) -> dict:
        """
        Deep service fingerprinting on a single port.
        Used by exploitation agent to get exact version for CVE matching.
        """
        if not self.is_available():
            return {}

        logger.info(f"Fingerprinting {host}:{port}")
        try:
            self.scanner.scan(
                hosts=host,
                arguments=f"-sV -p {port} --version-intensity 9 -sC"
            )
            tcp = self.scanner[host].get("tcp", {})
            data = tcp.get(port, {})
            return {
                "port":    port,
                "service": data.get("name", ""),
                "product": data.get("product", ""),
                "version": data.get("version", ""),
                "extra":   data.get("extrainfo", ""),
                "cpe":     data.get("cpe", ""),
                "scripts": data.get("script", {}),
            }
        except Exception as e:
            logger.error(f"Fingerprint failed {host}:{port}: {e}")
            return {}
