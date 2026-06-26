"""
Agno Campaign Orchestrator — Layer 1
The master controller of the entire red team campaign.
Accepts one input → runs full autonomous kill chain → outputs report.

Usage:
    orchestrator = CampaignOrchestrator(qdrant_path="C:/Users/rihem/Desktop/datasetAGENT/qdrant")
    orchestrator.run("192.168.1.0/24")
"""
import uuid, json, os, sys, time
from datetime import datetime
from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.campaign_state  import CampaignState, CampaignPhase, PhaseStatus, TargetInfo
from core.llm_client      import LLMClient
from core.decision_engine import AutonomousDecisionEngine
from knowledge.qdrant.rag_retriever import RAGRetriever
from config.settings import STEALTH_LEVEL, REPORTS_DIR

console = Console()

ORCHESTRATOR_SYSTEM = """You are the master Campaign Orchestrator for an authorized red team operation
against MedFlow healthcare infrastructure. You control all agents autonomously.
Your decisions are final — no human interaction occurs at any point.
Think like an APT. Be methodical, stealthy, and mission-focused.
Output valid JSON only when asked."""


class CampaignOrchestrator:
    """
    Layer 1 — Agno Campaign Orchestrator.
    Manages the full kill chain lifecycle autonomously.
    """

    def __init__(self, qdrant_path: str, stealth_level: str = STEALTH_LEVEL):
        self.qdrant_path    = qdrant_path
        self.stealth_level  = stealth_level

        logger.info("Initializing Campaign Orchestrator...")
        self.llm     = LLMClient()
        self.rag     = RAGRetriever(qdrant_path=qdrant_path)
        self.engine  = AutonomousDecisionEngine(llm=self.llm)

        # Agent registry — populated lazily as phases are needed
        self._agents = {}

        logger.success("Orchestrator ready.")

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, target_input: str, objective: str = "") -> CampaignState:
        """
        Main entry point.
        target_input: IP, subnet, hostname, CIDR, or mix
        objective: optional override (default: full compromise)
        """
        state = self._init_campaign(target_input, objective)

        console.print(Panel.fit(
            f"[bold red]RED TEAM CAMPAIGN STARTED[/bold red]\n"
            f"Target : [cyan]{target_input}[/cyan]\n"
            f"Objective: [yellow]{state.objective}[/yellow]\n"
            f"Stealth: [green]{self.stealth_level}[/green]\n"
            f"ID: {state.campaign_id}",
            border_style="red",
        ))

        # ── Autonomous planning ───────────────────────────────────────────────
        self._plan_campaign(state)

        # ── Execute kill chain ────────────────────────────────────────────────
        phase_runners = {
            CampaignPhase.RECON:         self._run_recon,
            CampaignPhase.SCANNING:      self._run_scanning,
            CampaignPhase.EXPLOITATION:  self._run_exploitation,
            CampaignPhase.PRIVESC:       self._run_privesc,
            CampaignPhase.PERSISTENCE:   self._run_persistence,
            CampaignPhase.LATERAL:       self._run_lateral,
            CampaignPhase.EXFIL:         self._run_exfil,
            CampaignPhase.REPORTING:     self._run_reporting,
        }

        while state.current_phase not in (CampaignPhase.COMPLETE, CampaignPhase.FAILED):
            phase = state.current_phase
            runner = phase_runners.get(phase)

            if not runner:
                logger.error(f"No runner for phase: {phase}")
                state.current_phase = CampaignPhase.FAILED
                break

            console.print(f"\n[bold yellow]▶ Phase: {phase.value.upper()}[/bold yellow]")
            state.phase_status = PhaseStatus.RUNNING

            try:
                success = runner(state)
            except Exception as e:
                logger.error(f"Phase {phase.value} crashed: {e}")
                success = False

            if success:
                state.phase_status = PhaseStatus.SUCCESS
                if state.current_phase not in (CampaignPhase.COMPLETE, CampaignPhase.FAILED):
                    next_phase = self.engine.select_next_phase(state)
                    state.advance_phase(next_phase)
            else:
                # Autonomous pivot decision
                pivot = self.engine.should_pivot(state, f"{phase.value} phase failed")
                decision = pivot.get("decision", "abort")

                if decision == "pivot_technique":
                    state.mark_blocked(pivot.get("reason", ""))
                    console.print(f"[orange]↩ Pivoting technique: {pivot.get('notes','')}[/orange]")
                    # Retry same phase with new technique hint stored in state
                    state.rag_context[f"{phase.value}_pivot"] = pivot.get("next_technique", "")

                elif decision == "pivot_host":
                    state.mark_blocked(pivot.get("reason", ""))
                    console.print(f"[orange]↩ Pivoting to host: {pivot.get('next_host','')}[/orange]")

                elif decision == "pivot_phase":
                    next_phase = self.engine.select_next_phase(state)
                    state.advance_phase(next_phase)
                    console.print(f"[orange]↩ Skipping phase → {next_phase.value}[/orange]")

                else:  # abort
                    if phase == CampaignPhase.RECON:
                        console.print("[red]✗ Recon failed — cannot continue without target info[/red]")
                        state.current_phase = CampaignPhase.FAILED
                    else:
                        # Still generate report with what we have
                        state.advance_phase(CampaignPhase.REPORTING)

                if state.pivot_attempts >= state.max_pivots:
                    logger.warning("Max pivots reached — moving to reporting")
                    state.advance_phase(CampaignPhase.REPORTING)

        self._print_summary(state)
        return state

    # ── Campaign initialization ────────────────────────────────────────────────

    def _init_campaign(self, target_input: str, objective: str) -> CampaignState:
        campaign_id = f"RT-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
        state = CampaignState(
            campaign_id=campaign_id,
            target_input=target_input,
            objective=objective or "Full compromise: access patient records, achieve domain admin, exfiltrate sensitive data",
            stealth_level=self.stealth_level,
            started_at=datetime.now().isoformat(),
            current_phase=CampaignPhase.RECON,
        )
        state.target = TargetInfo(raw_input=target_input)
        state.log_step(f"Campaign initialized | target={target_input}")
        return state

    # ── Campaign planning ─────────────────────────────────────────────────────

    def _plan_campaign(self, state: CampaignState):
        """
        Orchestrator reasons over the target and creates an initial attack plan.
        Queries RAG for relevant techniques before planning.
        """
        console.print("[dim]Orchestrator: planning campaign...[/dim]")

        # Query RAG for healthcare-specific attack context
        rag_context = self.rag.query_phase(
            phase="ics",
            context=f"healthcare infrastructure attack {state.target_input} patient records",
            top_k=4,
        )
        state.rag_context["planning"] = rag_context

        plan_prompt = f"""
Target: {state.target_input}
Objective: {state.objective}
Stealth level: {state.stealth_level}
Environment: MedFlow healthcare infrastructure (may include HL7, DICOM, medical devices, AD)

Intelligence context:
{rag_context[:1500]}

Create an autonomous attack plan. Respond with JSON:
{{
  "attack_plan": "brief campaign strategy",
  "priority_targets": ["target1", "target2"],
  "likely_vulnerabilities": ["vuln1", "vuln2"],
  "recommended_techniques": ["T1XXX", "T1XXX"],
  "stealth_notes": "how to stay undetected",
  "phase_overrides": {{}}
}}"""

        plan = self.llm.decide(ORCHESTRATOR_SYSTEM, plan_prompt)
        state.rag_context["attack_plan"] = plan
        state.log_step(f"Attack plan created: {plan.get('attack_plan','?')[:100]}")
        console.print(f"[dim green]Plan: {plan.get('attack_plan','?')[:120]}[/dim green]")

    # ── Phase runners (stubs — replaced by specialist agents in later layers) ─

    def _run_recon(self, state: CampaignState) -> bool:
        """Recon phase — will be replaced by ReconAgent in Layer 2."""
        rag = self.rag.query_phase("recon", f"reconnaissance {state.target_input}", top_k=5)
        state.rag_context["recon"] = rag

        decision = self.engine.debate_and_decide(
            question=f"What is the best recon strategy for target: {state.target_input}?",
            context=rag,
            state=state,
        )
        state.log_step(f"Recon strategy decided: {decision['action']}")
        console.print(f"  [cyan]Recon:[/cyan] {decision['action']}")
        console.print(f"  [dim]Technique: {decision['technique_id']} | Tool: {decision['tool']}[/dim]")

        # Simulate discovering hosts (Layer 2 will do real nmap)
        state.target.hosts = [state.target_input]
        state.log_step(f"Recon complete — discovered {len(state.target.hosts)} host(s)")
        return True

    def _run_scanning(self, state: CampaignState) -> bool:
        """Scanning phase — will be replaced by ScanningAgent in Layer 2."""
        rag = self.rag.query_phase("scanning", f"vulnerability scanning {' '.join(state.target.hosts)}", top_k=5)
        state.rag_context["scanning"] = rag

        decision = self.engine.debate_and_decide(
            question="What vulnerability scanning approach should we use?",
            context=rag,
            state=state,
        )
        state.log_step(f"Scanning strategy: {decision['action']}")
        console.print(f"  [cyan]Scanning:[/cyan] {decision['action']}")
        return True

    def _run_exploitation(self, state: CampaignState) -> bool:
        """Exploitation phase — will be replaced by ExploitAgent in Layer 2."""
        rag = self.rag.query_phase("exploitation", "exploit vulnerability remote code execution", top_k=5)
        state.rag_context["exploitation"] = rag

        decision = self.engine.debate_and_decide(
            question="Select the best exploit for initial access.",
            context=rag,
            state=state,
        )
        state.log_step(f"Exploitation: {decision['action']}")
        console.print(f"  [cyan]Exploit:[/cyan] {decision['action']}")
        console.print(f"  [dim]OPSEC: {decision['opsec_notes']}[/dim]")
        return True

    def _run_privesc(self, state: CampaignState) -> bool:
        rag = self.rag.query_phase("privesc", "privilege escalation windows linux", top_k=5)
        state.rag_context["privesc"] = rag
        decision = self.engine.debate_and_decide(
            question="How do we escalate privileges on the compromised host?",
            context=rag, state=state,
        )
        state.log_step(f"PrivEsc: {decision['action']}")
        console.print(f"  [cyan]PrivEsc:[/cyan] {decision['action']}")
        return True

    def _run_persistence(self, state: CampaignState) -> bool:
        rag = self.rag.query_phase("persistence", "persistence backdoor scheduled task", top_k=5)
        state.rag_context["persistence"] = rag
        decision = self.engine.debate_and_decide(
            question="Establish persistence without triggering detection.",
            context=rag, state=state,
        )
        state.log_step(f"Persistence: {decision['action']}")
        console.print(f"  [cyan]Persist:[/cyan] {decision['action']}")
        return True

    def _run_lateral(self, state: CampaignState) -> bool:
        rag = self.rag.query_phase("exploitation", "lateral movement pass the hash SMB WMI", top_k=5)
        state.rag_context["lateral"] = rag
        decision = self.engine.debate_and_decide(
            question="Move laterally to high-value targets (domain controller, patient DB).",
            context=rag, state=state,
        )
        state.log_step(f"Lateral: {decision['action']}")
        console.print(f"  [cyan]Lateral:[/cyan] {decision['action']}")
        return True

    def _run_exfil(self, state: CampaignState) -> bool:
        rag = self.rag.query_phase("exfil", "data exfiltration C2 covert channel", top_k=5)
        state.rag_context["exfil"] = rag
        decision = self.engine.debate_and_decide(
            question="Exfiltrate patient records and sensitive data covertly.",
            context=rag, state=state,
        )
        state.log_step(f"Exfil: {decision['action']}")
        console.print(f"  [cyan]Exfil:[/cyan] {decision['action']}")
        return True

    def _run_reporting(self, state: CampaignState) -> bool:
        """Generate final report — will be enriched by ReportingAgent in Layer 3."""
        os.makedirs(REPORTS_DIR, exist_ok=True)
        report_path = os.path.join(
            REPORTS_DIR, f"{state.campaign_id}_report.json"
        )

        report = {
            "campaign_id":   state.campaign_id,
            "target":        state.target_input,
            "objective":     state.objective,
            "started_at":    state.started_at,
            "completed_at":  datetime.now().isoformat(),
            "findings":      [vars(f) for f in state.findings],
            "credentials":   [vars(c) for c in state.credentials],
            "attck_mapping": state.attck_mapping,
            "attack_path":   state.attack_path,
            "rag_summary":   {k: v[:300] for k, v in state.rag_context.items()},
        }

        import json
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        state.report_path = report_path
        state.current_phase = CampaignPhase.COMPLETE
        state.log_step(f"Report saved: {report_path}")
        console.print(f"\n[green]✓ Report saved:[/green] {report_path}")
        return True

    # ── Summary ───────────────────────────────────────────────────────────────

    def _print_summary(self, state: CampaignState):
        table = Table(title=f"Campaign Summary — {state.campaign_id}", show_lines=True)
        table.add_column("Field",  style="cyan")
        table.add_column("Value")
        table.add_row("Target",     state.target_input)
        table.add_row("Status",     state.current_phase.value)
        table.add_row("Findings",   str(len(state.findings)))
        table.add_row("Credentials",str(len(state.credentials)))
        table.add_row("ATT&CK IDs", ", ".join(state.attck_mapping) or "none yet")
        table.add_row("Steps",      str(len(state.attack_path)))
        table.add_row("Report",     state.report_path or "not generated")
        console.print(table)
