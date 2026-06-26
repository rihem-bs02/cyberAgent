"""
Campaign Orchestrator — Layer 1
Controls the full kill chain. Each phase is run by an autonomous ReAct agent
that uses real tool execution (nmap, sqlmap, curl, msfconsole) and feeds actual
output back into the LLM for the next reasoning step.

Layer 2: ReActAgent — Observe → Think → Act loop per phase
Layer 3: AttackGraph (Neo4j) + LettaMemory (cross-campaign recall)
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

# ── Layer 2 — ReAct + Tool Registry ──────────────────────────────────────────
from agents.autonomous_agent   import ReActAgent, build_react_summary
from agents.tools.tool_registry import ToolRegistry

# ── Layer 3 — Attack Graph + Memory ──────────────────────────────────────────
from graph.attack_graph   import AttackGraph
from memory.letta_memory  import LettaMemory

console = Console(force_terminal=True)

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

        # ── Core services ─────────────────────────────────────────────────────
        self.llm    = LLMClient()
        self.rag    = RAGRetriever(qdrant_path=qdrant_path)
        self.engine = AutonomousDecisionEngine(llm=self.llm)

        # ── Layer 2: Tool execution ───────────────────────────────────────────
        self.tools  = ToolRegistry()
        logger.success("ToolRegistry ready — real command execution enabled")

        # ── Layer 3: Persistent intelligence ─────────────────────────────────
        self.graph  = AttackGraph()
        self.memory = LettaMemory()
        mem_status  = self.memory.status_report()
        logger.info(
            f"LettaMemory: {mem_status['backend']} | "
            f"{mem_status['campaigns_stored']} campaigns | "
            f"{mem_status['techniques_known']} techniques | "
            f"{mem_status['credentials_stored']} creds"
        )

        # Kill chain phases that get a full ReAct loop
        self.react_phases = [
            CampaignPhase.RECON,
            CampaignPhase.SCANNING,
            CampaignPhase.EXPLOITATION,
            CampaignPhase.PRIVESC,
            CampaignPhase.PERSISTENCE,
            CampaignPhase.LATERAL,
            CampaignPhase.EXFIL,
        ]

        # Steps per phase — more for critical phases
        self.phase_max_steps = {
            CampaignPhase.RECON:        6,
            CampaignPhase.SCANNING:     8,
            CampaignPhase.EXPLOITATION: 10,
            CampaignPhase.PRIVESC:      8,
            CampaignPhase.PERSISTENCE:  6,
            CampaignPhase.LATERAL:      8,
            CampaignPhase.EXFIL:        6,
        }

        logger.success("Orchestrator ready.")

    # ── Main campaign loop ─────────────────────────────────────────────────────

    def run(self, target_input: str, objective: str = "") -> CampaignState:
        state = self._init_campaign(target_input, objective)

        # ── Pre-campaign: recall historical intelligence ───────────────────────
        historical_context = self.memory.get_context_for_phase("planning", target_input)
        if historical_context:
            state.rag_context["historical_memory"] = historical_context
            console.print(f"[dim green]Memory: {historical_context[:200]}[/dim green]")

        # Initialize attack graph for this campaign
        self.graph.init_campaign(state.campaign_id, target_input, state.objective)

        console.print(Panel.fit(
            f"[bold red]RED TEAM CAMPAIGN STARTED[/bold red]\n"
            f"Target    : [cyan]{target_input}[/cyan]\n"
            f"Objective : [yellow]{state.objective}[/yellow]\n"
            f"Stealth   : [green]{self.stealth_level}[/green]\n"
            f"ID        : {state.campaign_id}",
            border_style="red",
        ))

        self._plan_campaign(state)

        # ── Kill chain loop ────────────────────────────────────────────────────
        while state.current_phase not in (CampaignPhase.COMPLETE, CampaignPhase.FAILED):
            phase = state.current_phase

            if phase == CampaignPhase.REPORTING:
                self._run_reporting(state)
                break

            if phase not in self.react_phases:
                logger.error(f"Unknown phase: {phase}")
                state.current_phase = CampaignPhase.FAILED
                break

            console.print(f"\n[bold yellow]>> Phase: {phase.value.upper()}[/bold yellow]")
            state.phase_status = PhaseStatus.RUNNING

            # ── Pre-phase memory recall ────────────────────────────────────────
            mem_context = self.memory.get_context_for_phase(phase.value, target_input)
            if mem_context:
                state.rag_context[f"{phase.value}_memory"] = mem_context

            # ── Build and run ReAct agent for this phase ───────────────────────
            try:
                react_agent = ReActAgent(
                    phase         = phase.value,
                    llm           = self.llm,
                    tool_registry = self.tools,
                    rag           = self.rag,
                    engine        = self.engine,
                    max_steps     = self.phase_max_steps.get(phase, 6),
                )
                success = react_agent.run(state)

            except Exception as e:
                logger.error(f"Phase {phase.value} crashed: {e}")
                import traceback
                traceback.print_exc()
                success = False

            # ── Post-phase: sync graph ─────────────────────────────────────────
            try:
                self.graph.sync_from_state(state.campaign_id, state)
            except Exception as e:
                logger.warning(f"Graph sync failed: {e}")

            # ── Advance or pivot ───────────────────────────────────────────────
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
                    logger.warning("Max pivots reached — moving to reporting")
                    state.advance_phase(CampaignPhase.REPORTING)

        # ── Close out ─────────────────────────────────────────────────────────
        self._run_reporting(state)
        self._print_summary(state)

        # ── Post-campaign: store in memory for future recall ──────────────────
        try:
            self.memory.store_campaign(state)
        except Exception as e:
            logger.warning(f"Failed to store campaign in memory: {e}")

        # Cleanup
        try:
            self.rag.close()
            self.graph.close()
        except Exception:
            pass

        return state

    # ── Campaign initialization ────────────────────────────────────────────────

    def _init_campaign(self, target_input: str, objective: str) -> CampaignState:
        campaign_id = f"RT-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
        state = CampaignState(
            campaign_id   = campaign_id,
            target_input  = target_input,
            objective     = objective or (
                "Full compromise: access patient records, achieve domain admin, exfiltrate sensitive data"
            ),
            stealth_level = self.stealth_level,
            started_at    = datetime.now().isoformat(),
            current_phase = CampaignPhase.RECON,
        )
        state.target     = TargetInfo(raw_input=target_input)
        state.log_step(f"Campaign initialized | target={target_input}")
        return state

    # ── Attack planning ────────────────────────────────────────────────────────

    def _plan_campaign(self, state: CampaignState):
        console.print("[dim]Orchestrator: planning campaign...[/dim]")

        rag_context = self.rag.query_phase(
            phase   = "ics",
            context = f"healthcare infrastructure attack {state.target_input}",
            top_k   = 4,
        )
        state.rag_context["planning"] = rag_context

        # Enrich with historical memory
        historical = state.rag_context.get("historical_memory", "")
        past_techs = ""
        if historical:
            past_techs = f"\nHistorical intelligence:\n{historical[:400]}"

        plan = self.llm.decide(ORCHESTRATOR_SYSTEM, f"""
Target: {state.target_input}
Objective: {state.objective}
Stealth: {state.stealth_level}
Environment: MedFlow healthcare (HL7, DICOM, medical devices, AD)

Threat intelligence:
{rag_context[:1200]}
{past_techs}

Create attack plan. JSON:
{{
  "attack_plan": "...",
  "priority_targets": [],
  "likely_vulnerabilities": [],
  "recommended_techniques": [],
  "stealth_notes": "..."
}}""")

        state.rag_context["attack_plan"] = plan
        state.log_step(f"Attack plan: {str(plan.get('attack_plan', '?'))[:150]}")
        console.print(f"[dim green]Plan: {str(plan.get('attack_plan', '?'))[:150]}[/dim green]")

    # ── Reporting ──────────────────────────────────────────────────────────────

    def _run_reporting(self, state: CampaignState):
        """Generate the final professional JSON report, enriched with graph and ReAct trace."""
        os.makedirs(REPORTS_DIR, exist_ok=True)
        report_path = os.path.join(REPORTS_DIR, f"{state.campaign_id}_report.json")

        # Get graph summary
        try:
            graph_summary = self.graph.get_summary(state.campaign_id)
            attack_graph  = self.graph.get_attack_path(state.campaign_id)
        except Exception:
            graph_summary = {}
            attack_graph  = []

        # Export GraphML for visualization
        try:
            graphml_path = os.path.join(
                REPORTS_DIR, f"{state.campaign_id}_graph.graphml"
            )
            self.graph.export_graphml(graphml_path, state.campaign_id)
        except Exception:
            graphml_path = ""

        # Build ReAct trace summary
        react_traces = getattr(state, "react_traces", {})
        react_summary = build_react_summary(react_traces)

        report = {
            "metadata": {
                "campaign_id":   state.campaign_id,
                "target":        state.target_input,
                "objective":     state.objective,
                "stealth_level": state.stealth_level,
                "started_at":    state.started_at,
                "completed_at":  datetime.now().isoformat(),
                "status":        state.current_phase.value,
                "report_version":"2.0",
            },
            "target_info": {
                "hosts":         state.target.hosts,
                "open_ports":    {str(k): v for k, v in state.target.open_ports.items()},
                "services":      {str(k): v for k, v in state.target.services.items()},
                "os_info":       state.target.os_info,
                "domain":        state.target.domain,
                "dc_host":       state.target.dc_host,
                "web_endpoints": state.target.web_endpoints,
                "ics_devices":   state.target.ics_devices,
            },
            "execution": {
                "attack_path":       state.attack_path,
                "compromised_hosts": state.compromised_hosts,
                "attck_mapping":     state.attck_mapping,
                "failed_techniques": state.failed_techniques,
                "pivot_count":       state.pivot_attempts,
                "react_trace":       react_summary,
            },
            "results": {
                "findings":    [vars(f) for f in state.findings],
                "credentials": [vars(c) for c in state.credentials],
            },
            "graph": {
                "summary":      graph_summary,
                "attack_path":  attack_graph,
                "graphml_file": graphml_path,
            },
        }

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        state.report_path   = report_path
        state.current_phase = CampaignPhase.COMPLETE
        state.log_step(f"Report saved: {report_path}")
        console.print(f"\n[bold green]Report saved:[/bold green] {report_path}")
        if graphml_path:
            console.print(f"[bold green]Graph exported:[/bold green] {graphml_path}")

    # ── Summary table ──────────────────────────────────────────────────────────

    def _print_summary(self, state: CampaignState):
        react_traces = getattr(state, "react_traces", {})
        total_steps  = sum(len(v) for v in react_traces.values())
        mem_status   = self.memory.status_report()

        table = Table(title=f"Campaign Summary -- {state.campaign_id}", show_lines=True)
        table.add_column("Field",   style="cyan")
        table.add_column("Value",   style="white")
        table.add_row("Target",         state.target_input)
        table.add_row("Status",         state.current_phase.value)
        table.add_row("Hosts found",    str(len(state.target.hosts)))
        table.add_row("Compromised",    ", ".join(state.compromised_hosts) or "none")
        table.add_row("Findings",       str(len(state.findings)))
        table.add_row("Credentials",    str(len(state.credentials)))
        table.add_row("ATT&CK IDs",     ", ".join(state.attck_mapping[:8]) or "none")
        table.add_row("ReAct steps",    str(total_steps))
        table.add_row("Memory backend", mem_status["backend"])
        table.add_row("Past campaigns", str(mem_status["campaigns_stored"]))
        table.add_row("Report",         state.report_path or "not generated")
        console.print(table)
