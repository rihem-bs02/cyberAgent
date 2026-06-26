"""
Scanning Agent — Layer 2
Real vulnerability scanning: matches discovered services to CVEs,
runs nmap vuln scripts, populates state.findings[].
"""
import os, sys
from rich.console import Console
from rich.table import Table
from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from agents.base_agent   import BaseAgent
from core.campaign_state import CampaignState, Finding
from tools.nmap_tool     import NmapTool
from tools.cve_tool      import CVETool

console = Console()

SCANNING_SYSTEM = """You are an expert vulnerability assessment AI for red team operations.
Analyze service banners and CVE data to identify the most exploitable vulnerabilities.
Prioritize by: CVSS score, exploitability, relevance to healthcare infrastructure.
Output valid JSON only."""


class ScanningAgent(BaseAgent):

    def __init__(self, llm, rag, engine):
        super().__init__("ScanningAgent", llm, rag, engine)
        self.nmap = NmapTool()
        self.cve  = CVETool(rag_retriever=rag)

    def run(self, state: CampaignState) -> bool:
        console.print("\n  [bold cyan]ScanningAgent[/bold cyan] starting...")
        state.log_step("ScanningAgent: starting vulnerability scanning")

        if not state.target.hosts:
            self.log("No hosts to scan — recon must run first")
            return False

        # ── Query RAG for scanning intelligence ───────────────────
        rag_context = self.query_rag(
            phase="scanning",
            context="vulnerability scanning healthcare medical devices CVE CISA",
            top_k=4,
        )

        all_vulns = []

        for host in state.target.hosts:
            ports   = state.target.open_ports.get(host, [])
            services = state.target.services.get(host, {})

            if not ports:
                continue

            console.print(f"  [dim]Scanning {host} ({len(ports)} ports)...[/dim]")

            # ── Nmap vuln scripts ─────────────────────────────────
            if self.nmap.is_available() and ports:
                vuln_results = self.nmap.vuln_scan(host, list(ports)[:10])
                for port, data in vuln_results.items():
                    for script_name, script_out in data.get("scripts", {}).items():
                        if any(k in script_out.lower() for k in ["vuln", "cve-", "vulnerable"]):
                            all_vulns.append({
                                "host":    host,
                                "port":    port,
                                "service": data.get("service", ""),
                                "source":  "nmap_script",
                                "title":   script_name,
                                "details": script_out[:400],
                                "cvss":    7.0,  # default for nmap findings
                            })

            # ── CVE matching per service ──────────────────────────
            for port in ports:
                svc_data = services.get(port, {})
                product  = svc_data.get("product", "")
                version  = svc_data.get("version", "")
                service  = svc_data.get("service", "")

                if not (product or service):
                    # Try by port number
                    cves = self.cve.lookup_port_service(port, service)
                else:
                    cves = self.cve.lookup_service(
                        product=product or service,
                        version=version,
                        top_k=3,
                    )

                for cve in cves:
                    if cve.get("cvss_score", 0) >= 7.0:
                        all_vulns.append({
                            "host":    host,
                            "port":    port,
                            "service": service,
                            "source":  cve["source"],
                            "cve_id":  cve.get("cve_id", ""),
                            "title":   cve.get("title", ""),
                            "details": cve.get("description", ""),
                            "cvss":    cve.get("cvss_score", 0),
                            "severity":cve.get("severity", ""),
                        })

        if not all_vulns:
            self.log("No vulnerabilities found — trying broader scan")
            # Last resort: query RAG for generic healthcare vulns
            rag_vulns = self.rag.query(
                "healthcare DICOM HL7 medical device vulnerability exploit",
                phase="scanning", top_k=5
            )
            state.rag_context["scanning_fallback"] = rag_vulns
            # Still return True — we have RAG context for exploitation
            return True

        # ── LLM prioritization of findings ───────────────────────
        vuln_summary = "\n".join([
            f"- {v['host']}:{v['port']} {v.get('cve_id','')} {v.get('title','')} CVSS={v['cvss']}"
            for v in all_vulns[:15]
        ])

        priority_prompt = f"""
Vulnerabilities discovered:
{vuln_summary}

RAG Intelligence:
{rag_context[:600]}

Campaign objective: {state.objective}

Prioritize these for exploitation. Select top 5 most exploitable.
Respond with JSON:
{{
  "top_vulns": [
    {{
      "host": "...",
      "port": 0,
      "cve_id": "...",
      "title": "...",
      "reason": "why this is best to exploit",
      "technique_id": "T1XXX",
      "severity": "critical|high|medium",
      "cvss": 0.0
    }}
  ]
}}"""

        priorities = self.llm.decide(SCANNING_SYSTEM, priority_prompt)
        top_vulns  = priorities.get("top_vulns", [])

        # ── Populate state.findings[] ─────────────────────────────
        for vuln in top_vulns:
            state.add_finding(
                phase        = "scanning",
                title        = vuln.get("title", "Unknown vulnerability"),
                description  = vuln.get("reason", vuln.get("title", "")),
                severity     = vuln.get("severity", "high"),
                host         = vuln.get("host", ""),
                technique_id = vuln.get("technique_id", "T1190"),
                evidence     = f"CVE: {vuln.get('cve_id','')} | CVSS: {vuln.get('cvss',0)}",
                remediation  = "Patch to latest version and apply vendor security advisories",
            )

        state.rag_context["top_vulns"] = str(top_vulns)
        state.log_step(f"Scanning complete: {len(all_vulns)} vulns found, {len(top_vulns)} prioritized")

        # ── Print findings table ──────────────────────────────────
        self._print_findings(state, top_vulns)
        console.print(f"  [green]✓ Scanning complete — {len(state.findings)} findings added[/green]")
        return True

    def _print_findings(self, state: CampaignState, top_vulns: list):
        if not top_vulns:
            return
        table = Table(title="Vulnerability Findings", show_lines=True)
        table.add_column("Host",     style="cyan")
        table.add_column("Port",     style="yellow")
        table.add_column("CVE",      style="red")
        table.add_column("Severity", style="bold")
        table.add_column("CVSS")

        for v in top_vulns:
            sev   = v.get("severity", "?")
            color = {"critical":"bold red","high":"red","medium":"yellow","low":"dim"}.get(sev,"white")
            table.add_row(
                v.get("host",""),
                str(v.get("port","")),
                v.get("cve_id",""),
                f"[{color}]{sev}[/{color}]",
                str(v.get("cvss","")),
            )
        console.print(table)
