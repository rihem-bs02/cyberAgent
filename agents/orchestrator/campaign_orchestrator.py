"""
Agno Campaign Orchestrator — Layer 1 + Layer 2 wired
Replaces all stub phase runners with real specialist agents.
"""
import uuid, json, os, sys
from datetime import datetime
from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from core.campaign_state  import CampaignState, CampaignPhase, PhaseStatus, TargetInfo
from core.llm_client      import LLMClient
from core.decision_engine import AutonomousDecisionEngine
from knowledge.qdrant.rag_retriever import RAGRetriever
from config.settings import STEALTH_LEVEL, REPORTS_DIR

# ── Layer 2 specialist agents ─────────────────────────────────────────────────
from agents.recon.recon_agent               import ReconAgent
from agents.scanning.scanning_agent         import ScanningAgent
from agents.exploitation.exploitation_agent import ExploitationAgent
from agents.phase_agents import (
    PrivEscAgent, PersistenceAgent, LateralMovementAgent, ExfilAgent
)

console = Console()

ORCHESTRATOR_SYSTEM = """You are the master Campaign Orchestrator for an authorized red team operation
against MedFlow healthcare infrastructure. You control all agents autonomously.
Your decisions are final — no human interaction occurs at any point.
Think like an APT. Be methodical, stealthy, and mission-focused.
Output valid JSON only when asked."""


class CampaignOrchestrator:

    def __init__(self, qdrant_path: str, stealth_level: str = STEALTH_LEVEL):
        self.qdrant_path   = qdrant_path
        self.stealth_level = stealth_level

        logger.info("Initializing Campaign Orchestrator...")
        self.llm    = LLMClient()
        self.rag    = RAGRetriever(qdrant_path=qdrant_path)
        self.engine = AutonomousDecisionEngine(llm=self.llm)

        # ── Instantiate all Layer 2 agents ────────────────────────
        self.agents = {
            CampaignPhase.RECON:         ReconAgent(self.llm, self.rag, self.engine),
            CampaignPhase.SCANNING:      ScanningAgent(self.llm, self.rag, self.engine),
            CampaignPhase.EXPLOITATION:  ExploitationAgent(self.llm, self.rag, self.engine),
            CampaignPhase.PRIVESC:       PrivEscAgent(self.llm, self.rag, self.engine),
            CampaignPhase.PERSISTENCE:   PersistenceAgent(self.llm, self.rag, self.engine),
            CampaignPhase.LATERAL:       LateralMovementAgent(self.llm, self.rag, self.engine),
            CampaignPhase.EXFIL:         ExfilAgent(self.llm, self.rag, self.engine),
        }

        logger.success("Orchestrator ready — all Layer 2 agents loaded.")

    def run(self, target_input: str, objective: str = "") -> CampaignState:
        state = self._init_campaign(target_input, objective)

        console.print(Panel.fit(
            f"[bold red]RED TEAM CAMPAIGN STARTED[/bold red]\n"
            f"Target    : [cyan]{target_input}[/cyan]\n"
            f"Objective : [yellow]{state.objective}[/yellow]\n"
            f"Stealth   : [green]{self.stealth_level}[/green]\n"
            f"ID        : {state.campaign_id}",
            border_style="red",
        ))

        self._plan_campaign(state)

        # ── Kill chain loop ───────────────────────────────────────
        while state.current_phase not in (CampaignPhase.COMPLETE, CampaignPhase.FAILED):
            phase  = state.current_phase
            agent  = self.agents.get(phase)

            if not agent:
                # Reporting phase — no specialist agent
                if phase == CampaignPhase.REPORTING:
                    self._run_reporting(state)
                    break
                logger.error(f"No agent for phase: {phase}")
                state.current_phase = CampaignPhase.FAILED
                break

            console.print(f"\n[bold yellow]▶ Phase: {phase.value.upper()}[/bold yellow]")
            state.phase_status = PhaseStatus.RUNNING

            try:
                success = agent.run(state)
            except Exception as e:
                logger.error(f"Phase {phase.value} crashed: {e}")
                import traceback
                traceback.print_exc()
                success = False

            if success:
                state.phase_status = PhaseStatus.SUCCESS
                next_phase = self.engine.select_next_phase(state)
                state.advance_phase(next_phase)
            else:
                pivot = self.engine.should_pivot(state, f"{phase.value} failed")
                decision = pivot.get("decision", "pivot_phase")

                if decision == "pivot_technique":
                    state.mark_blocked(pivot.get("reason", ""))
                    state.rag_context[f"{phase.value}_pivot"] = pivot.get("next_technique", "")
                elif decision == "pivot_host":
                    state.mark_blocked(pivot.get("reason", ""))
                elif decision in ("pivot_phase", "abort"):
                    next_phase = self.engine.select_next_phase(state)
                    state.advance_phase(next_phase)

                if state.pivot_attempts >= state.max_pivots:
                    state.advance_phase(CampaignPhase.REPORTING)

        self._run_reporting(state)
        self._print_summary(state)
        return state

    def _init_campaign(self, target_input: str, objective: str) -> CampaignState:
        campaign_id = f"RT-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
        state = CampaignState(
            campaign_id    = campaign_id,
            target_input   = target_input,
            objective      = objective or "Full compromise: access patient records, achieve domain admin, exfiltrate sensitive data",
            stealth_level  = self.stealth_level,
            started_at     = datetime.now().isoformat(),
            current_phase  = CampaignPhase.RECON,
        )
        state.target = TargetInfo(raw_input=target_input)
        state.log_step(f"Campaign initialized | target={target_input}")
        return state

    def _plan_campaign(self, state: CampaignState):
        console.print("[dim]Orchestrator: planning campaign...[/dim]")
        rag_context = self.rag.query_phase(
            phase="ics",
            context=f"healthcare infrastructure attack {state.target_input}",
            top_k=4,
        )
        state.rag_context["planning"] = rag_context

        plan = self.llm.decide(ORCHESTRATOR_SYSTEM, f"""
Target: {state.target_input}
Objective: {state.objective}
Stealth: {state.stealth_level}
Environment: MedFlow healthcare (HL7, DICOM, medical devices, AD)

Intelligence:
{rag_context[:1200]}

Create attack plan. JSON:
{{
  "attack_plan": "...",
  "priority_targets": [],
  "likely_vulnerabilities": [],
  "recommended_techniques": [],
  "stealth_notes": "..."
}}""")
        state.rag_context["attack_plan"] = plan
        state.log_step(f"Attack plan: {str(plan.get('attack_plan','?'))[:120]}")
        console.print(f"[dim green]Plan: {str(plan.get('attack_plan','?'))[:120]}[/dim green]")

    def _run_reporting(self, state: CampaignState):
        os.makedirs(REPORTS_DIR, exist_ok=True)
        report_path = os.path.join(REPORTS_DIR, f"{state.campaign_id}_report.json")

        report = {
            "campaign_id":      state.campaign_id,
            "target":           state.target_input,
            "objective":        state.objective,
            "started_at":       state.started_at,
            "completed_at":     datetime.now().isoformat(),
            "hosts_discovered": state.target.hosts,
            "open_ports":       {str(k): v for k, v in state.target.open_ports.items()},
            "web_endpoints":    state.target.web_endpoints,
            "ics_devices":      state.target.ics_devices,
            "compromised":      state.compromised_hosts,
            "findings":         [vars(f) for f in state.findings],
            "credentials":      [vars(c) for c in state.credentials],
            "attck_mapping":    state.attck_mapping,
            "attack_path":      state.attack_path,
            "failed_techniques":state.failed_techniques,
        }

        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        state.report_path   = report_path
        state.current_phase = CampaignPhase.COMPLETE
        state.log_step(f"Report saved: {report_path}")
        console.print(f"\n[green]✓ Report:[/green] {report_path}")

    def _print_summary(self, state: CampaignState):
        table = Table(title=f"Campaign Summary — {state.campaign_id}", show_lines=True)
        table.add_column("Field",      style="cyan")
        table.add_column("Value")
        table.add_row("Target",        state.target_input)
        table.add_row("Status",        state.current_phase.value)
        table.add_row("Hosts found",   str(len(state.target.hosts)))
        table.add_row("Compromised",   str(state.compromised_hosts or "none"))
        table.add_row("Findings",      str(len(state.findings)))
        table.add_row("Credentials",   str(len(state.credentials)))
        table.add_row("ATT&CK IDs",    ", ".join(state.attck_mapping) or "none")
        table.add_row("Web endpoints", str(state.target.web_endpoints or "none"))
        table.add_row("ICS devices",   str(state.target.ics_devices or "none"))
        table.add_row("Report",        state.report_path or "not generated")
        console.print(table)
