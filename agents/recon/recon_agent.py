"""
Recon Agent — Layer 2
Real network reconnaissance using nmap + network tools.
Populates state.target with discovered hosts, ports, services, OS info.
"""
import os, sys
from rich.console import Console
from rich.table import Table
from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from agents.base_agent       import BaseAgent
from core.campaign_state     import CampaignState, Finding
from tools.nmap_tool         import NmapTool
from tools.network_tool      import NetworkTool

console = Console()

RECON_SYSTEM = """You are an expert red team reconnaissance specialist AI.
You analyze network scan results and decide the best next recon action.
Think like an APT actor — be methodical, stealthy, and thorough.
Output valid JSON only."""


class ReconAgent(BaseAgent):

    def __init__(self, llm, rag, engine):
        super().__init__("ReconAgent", llm, rag, engine)
        self.nmap    = NmapTool()
        self.network = NetworkTool()

    def run(self, state: CampaignState) -> bool:
        console.print("\n  [bold cyan]ReconAgent[/bold cyan] starting...")
        state.log_step("ReconAgent: starting real network reconnaissance")

        # ── Step 1: Parse target input ────────────────────────────
        parsed = self.network.parse_target(state.target_input)
        self.log(f"Target parsed: type={parsed['type']} hosts={len(parsed['hosts'])}")
        state.log_step(f"Target type: {parsed['type']} | potential hosts: {len(parsed['hosts'])}")

        # ── Step 2: Query RAG for recon context ───────────────────
        rag_context = self.query_rag(
            phase="recon",
            context=f"healthcare network reconnaissance {state.target_input} medical devices DICOM HL7",
            top_k=4,
        )
        state.rag_context["recon_knowledge"] = rag_context

        # ── Step 3: Autonomous recon strategy decision ────────────
        decision = self.decide(
            question=f"Best recon strategy for target: {state.target_input} (type={parsed['type']})",
            context=rag_context,
            state=state,
        )
        self.log(f"Strategy decided: {decision.get('action','?')}")
        console.print(f"  Strategy: [yellow]{decision.get('action','?')}[/yellow]")
        console.print(f"  Technique: [dim]{decision.get('technique_id','?')} | {decision.get('tool','?')}[/dim]")
        state.log_step(f"Recon strategy: {decision.get('action','?')} [{decision.get('technique_id','')}]")

        # ── Step 4: Ping sweep — discover live hosts ──────────────
        console.print(f"  [dim]Running ping sweep on {state.target_input}...[/dim]")

        if self.nmap.is_available():
            live_hosts = self.nmap.ping_sweep(state.target_input)
        else:
            # Fallback: TCP connect sweep
            console.print("  [yellow]Nmap not available — using TCP connect sweep[/yellow]")
            potential = parsed["hosts"][:50]  # limit for speed
            live_hosts = [h for h in potential if self.network.is_alive(h)]

        if not live_hosts:
            self.log("No live hosts found")
            state.log_step("Recon: no live hosts discovered")
            return False

        state.target.hosts = live_hosts
        self.log(f"Live hosts: {live_hosts}")
        state.log_step(f"Discovered {len(live_hosts)} live hosts: {live_hosts}")
        console.print(f"  [green]✓ {len(live_hosts)} live host(s) found[/green]")

        # ── Step 5: Port scan each live host ─────────────────────
        for host in live_hosts:
            console.print(f"  [dim]Port scanning {host}...[/dim]")

            if self.nmap.is_available():
                ports = self.nmap.port_scan(host, stealth=state.stealth_level)
            else:
                # Manual TCP check on common ports
                common_ports = [21,22,23,25,80,110,135,139,143,443,445,
                                1433,1521,3306,3389,5432,5900,8080,8443,9200,27017]
                ports = {}
                for p in common_ports:
                    if self.network.check_port(host, p):
                        banner = self.network.grab_banner(host, p)
                        ports[p] = {
                            "state": "open", "service": "", "version": "",
                            "product": "", "extra": banner[:100], "cpe": ""
                        }

            if ports:
                state.target.open_ports[host] = list(ports.keys())
                state.target.services[host]   = ports
                self.log(f"Host {host}: {len(ports)} open ports: {list(ports.keys())}")
                state.log_step(f"{host}: open ports {list(ports.keys())}")

                # Detect web endpoints
                for port, data in ports.items():
                    svc = data.get("service", "").lower()
                    if any(s in svc for s in ["http", "https", "web"]) or port in [80, 443, 8080, 8443]:
                        proto = "https" if port in [443, 8443] else "http"
                        state.target.web_endpoints.append(f"{proto}://{host}:{port}")

                # Detect ICS/medical devices
                for port, data in ports.items():
                    svc = data.get("service", "").lower()
                    extra = data.get("extra", "").lower()
                    if any(s in svc+extra for s in ["dicom", "hl7", "modbus", "dnp3", "bacnet", "104"]):
                        state.target.ics_devices.append(f"{host}:{port}")
                        state.log_step(f"ICS/Medical device detected: {host}:{port} ({svc})")

        # ── Step 6: OS detection on first host ────────────────────
        if live_hosts and self.nmap.is_available():
            primary = live_hosts[0]
            console.print(f"  [dim]OS detection on {primary}...[/dim]")
            os_info = self.nmap.os_detection(primary)
            if os_info.get("os") != "unknown":
                state.target.os_info[primary] = os_info
                state.log_step(f"OS detected on {primary}: {os_info.get('os','?')}")

        # ── Step 7: LLM analysis of recon results ────────────────
        recon_summary = self._build_summary(state)
        analysis_prompt = f"""
Analyze these recon results for a healthcare infrastructure attack:

{recon_summary}

RAG Intelligence:
{rag_context[:800]}

Identify:
1. Most valuable targets
2. Likely attack vectors
3. Healthcare-specific risks (DICOM, HL7, medical devices)
4. Recommended next phase focus

Respond as JSON:
{{
  "priority_target": "IP:port",
  "attack_vectors": ["vector1", "vector2"],
  "healthcare_risks": ["risk1"],
  "next_focus": "what to scan/exploit first",
  "technique_ids": ["T1046", "T1018"]
}}"""

        analysis = self.llm.decide(RECON_SYSTEM, analysis_prompt)
        state.rag_context["recon_analysis"] = str(analysis)

        # Add ATT&CK techniques used
        for tid in analysis.get("technique_ids", ["T1046", "T1018"]):
            if tid not in state.attck_mapping:
                state.attck_mapping.append(tid)

        # ── Step 8: Print recon table ─────────────────────────────
        self._print_results(state)

        state.log_step(f"Recon complete: {len(live_hosts)} hosts, priority={analysis.get('priority_target','?')}")
        console.print(f"  [green]✓ Recon complete — {len(live_hosts)} hosts, {sum(len(p) for p in state.target.open_ports.values())} open ports[/green]")
        return True

    def _build_summary(self, state: CampaignState) -> str:
        lines = [f"Live hosts: {state.target.hosts}"]
        for host in state.target.hosts:
            ports = state.target.open_ports.get(host, [])
            svcs  = state.target.services.get(host, {})
            os_i  = state.target.os_info.get(host, {})
            lines.append(f"\n{host}:")
            if os_i.get("os"):
                lines.append(f"  OS: {os_i['os']} (accuracy={os_i.get('accuracy','?')}%)")
            for p in ports:
                d = svcs.get(p, {})
                lines.append(f"  Port {p}: {d.get('service','')} {d.get('product','')} {d.get('version','')}")
        if state.target.web_endpoints:
            lines.append(f"\nWeb endpoints: {state.target.web_endpoints}")
        if state.target.ics_devices:
            lines.append(f"ICS/Medical devices: {state.target.ics_devices}")
        return "\n".join(lines)

    def _print_results(self, state: CampaignState):
        table = Table(title="Recon Results", show_lines=True)
        table.add_column("Host",    style="cyan")
        table.add_column("OS",      style="dim")
        table.add_column("Ports",   style="yellow")
        table.add_column("Services")

        for host in state.target.hosts:
            ports = state.target.open_ports.get(host, [])
            svcs  = state.target.services.get(host, {})
            os_i  = state.target.os_info.get(host, {})
            os_str = os_i.get("os", "unknown")[:30]
            port_str = ", ".join(str(p) for p in ports[:8])
            svc_str  = ", ".join(
                f"{p}/{svcs[p].get('service','?')}" for p in list(ports)[:6]
            )
            table.add_row(host, os_str, port_str, svc_str)

        console.print(table)
