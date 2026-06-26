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

# ── NEW: Layer 2 & 3 imports ──────────────────────────────────────────────────
from agents.autonomous_agent import ReActAgent
from agents.tools.tool_registry import ToolRegistry
from graph.attack_graph import AttackGraph
from memory.letta_memory import LettaMemory

console = Console()

ORCHESTRATOR_SYSTEM = """You are the master Campaign Orchestrator for an authorized red team operation
against MedFlow healthcare infrastructure. You control all agents autonomously.
Your decisions are final — no human interaction occurs at any point.
Think like an APT. Be methodical, stealthy, and mission-focused.
Output valid JSON only when asked."""

# Max ReAct steps per phase (can be overridden per phase)
PHASE_MAX_STEPS: dict[str, int] = {
    "recon":           8,
    "scanning":        8,
    "exploitation":    10,
    "privesc":         8,
    "persistence":     6,
    "lateral_movement":8,
    "exfiltration":    6,
}


class CampaignOrchestrator:
    """
    Layer 1 — Agno Campaign Orchestrator.
    Manages the full kill chain lifecycle autonomously.

    Layer 2 wiring: Each phase runner now spawns a ReActAgent that runs the
    real Observe → Think → Act → Observe loop using the ToolRegistry.

    Layer 3 wiring: After every phase the AttackGraph is synced from state.
                    After reporting the LettaMemory stores the campaign.
    """

    def __init__(self, qdrant_path: str, stealth_level: str = STEALTH_LEVEL):
        self.qdrant_path    = qdrant_path
        self.stealth_level  = stealth_level

        logger.info("Initializing Campaign Orchestrator...")
        self.llm     = LLMClient()
        self.rag     = RAGRetriever(qdrant_path=qdrant_path)
        self.engine  = AutonomousDecisionEngine(llm=self.llm)

        # ── Layer 2: Tool registry (shared across all phase agents) ───────────
        self.tools   = ToolRegistry()

        # ── Layer 3: Persistent intelligence layers ───────────────────────────
        self.graph   = AttackGraph()
        self.memory  = LettaMemory()

        logger.success("Orchestrator ready.")
        logger.info(
            f"  Tools   : SAFE_MODE={self.tools.safe_mode}"
        )
        logger.info(
            f"  Graph   : {'Neo4j' if self.graph.using_neo4j else 'in-memory fallback'}"
        )
        logger.info(
            f"  Memory  : {'Letta' if self.memory.using_letta else 'local JSON fallback'} | "
            f"{self.memory.campaign_count()} past campaigns"
        )

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
            f"Target   : [cyan]{target_input}[/cyan]\n"
            f"Objective: [yellow]{state.objective}[/yellow]\n"
            f"Stealth  : [green]{self.stealth_level}[/green]\n"
            f"Graph    : [magenta]{'Neo4j' if self.graph.using_neo4j else 'in-memory'}[/magenta]\n"
            f"Memory   : [magenta]{'Letta' if self.memory.using_letta else 'local JSON'}[/magenta]\n"
            f"ID       : {state.campaign_id}",
            border_style="red",
        ))

        # ── Autonomous planning ───────────────────────────────────────────────
        self._plan_campaign(state)

        # ── Initialize attack graph for this campaign ─────────────────────────
        self.graph.init_campaign(
            campaign_id=state.campaign_id,
            target=target_input,
            objective=state.objective,
        )

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
                import traceback
                traceback.print_exc()
                success = False

            # ── Layer 3: Sync attack graph after every phase ──────────────────
            if phase not in (CampaignPhase.REPORTING,):
                try:
                    self.graph.sync_from_state(state.campaign_id, state)
                    logger.info(f"[Graph] Synced after {phase.value}")
                except Exception as e:
                    logger.warning(f"[Graph] Sync failed: {e}")

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

        # ── Inject cross-campaign intelligence into initial state ─────────────
        mem_context = self.memory.get_context_for_phase("recon", target_input)
        if mem_context:
            state.rag_context["letta_memory"] = mem_context
            console.print(f"[dim magenta]Memory: injecting {len(mem_context)} chars of past intelligence[/dim magenta]")

        return state

    # ── Campaign planning ─────────────────────────────────────────────────────

    def _plan_campaign(self, state: CampaignState):
        """
        Orchestrator reasons over the target and creates an initial attack plan.
        Queries RAG for relevant techniques before planning.
        """
        console.print("[dim]Orchestrator: planning campaign...[/dim]")

        rag_context = self.rag.query_phase(
            phase="ics",
            context=f"healthcare infrastructure attack {state.target_input} patient records",
            top_k=4,
        )
        state.rag_context["planning"] = rag_context

        # Enrich with past campaign memory
        mem_context = self.memory.get_context_for_phase("planning", state.target_input)

        plan_prompt = f"""
Target: {state.target_input}
Objective: {state.objective}
Stealth level: {state.stealth_level}
Environment: MedFlow healthcare infrastructure (may include HL7, DICOM, medical devices, AD)

Intelligence context:
{rag_context[:1200]}

Cross-campaign memory:
{mem_context[:400] if mem_context else 'No past campaigns.'}

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

    # ── Core ReAct phase runner ────────────────────────────────────────────────

    def _run_react_phase(self, phase: str, state: CampaignState) -> bool:
        """
        Generic ReAct loop runner for any kill-chain phase.
        Creates a ReActAgent, runs it, and returns True if the objective was met.
        This replaces all the old stub phase runners.
        """
        # Inject cross-campaign memory into state context for this phase
        mem_ctx = self.memory.get_context_for_phase(phase, state.target_input)
        if mem_ctx:
            state.rag_context[f"{phase}_memory"] = mem_ctx
            logger.info(f"[Orchestrator] Memory context injected for {phase}")

        max_steps = PHASE_MAX_STEPS.get(phase, 8)

        agent = ReActAgent(
            phase         = phase,
            llm           = self.llm,
            tool_registry = self.tools,
            rag           = self.rag,
            engine        = self.engine,
            max_steps     = max_steps,
        )

        success = agent.run(state)

        console.print(
            f"  [{'green' if success else 'red'}]{'✓' if success else '✗'} ReAct:{phase}[/{'green' if success else 'red'}] "
            f"completed {len(agent.steps)} steps | success={success}"
        )
        return success

    # ── Phase runners — all delegate to _run_react_phase ──────────────────────

    def _run_recon(self, state: CampaignState) -> bool:
        """Recon phase: ReActAgent discovers live hosts and open ports."""
        return self._run_react_phase("recon", state)

    def _run_scanning(self, state: CampaignState) -> bool:
        """Scanning phase: ReActAgent enumerates vulnerabilities on discovered hosts."""
        return self._run_react_phase("scanning", state)

    def _run_exploitation(self, state: CampaignState) -> bool:
        """Exploitation phase: ReActAgent attempts initial access via discovered vulns."""
        return self._run_react_phase("exploitation", state)

    def _run_privesc(self, state: CampaignState) -> bool:
        """PrivEsc phase: ReActAgent escalates from current user to root/SYSTEM."""
        return self._run_react_phase("privesc", state)

    def _run_persistence(self, state: CampaignState) -> bool:
        """Persistence phase: ReActAgent establishes durable access mechanisms."""
        return self._run_react_phase("persistence", state)

    def _run_lateral(self, state: CampaignState) -> bool:
        """Lateral movement phase: ReActAgent moves from foothold to high-value targets."""
        return self._run_react_phase("lateral_movement", state)

    def _run_exfil(self, state: CampaignState) -> bool:
        """Exfiltration phase: ReActAgent locates and exfiltrates sensitive data."""
        return self._run_react_phase("exfiltration", state)

    # ── Reporting phase (not a ReAct phase — aggregates everything) ───────────

    def _run_reporting(self, state: CampaignState) -> bool:
        """
        Generate final report from all collected state.
        Also:
          - Exports the attack graph as GraphML
          - Stores campaign in LettaMemory for future cross-campaign recall
        """
        os.makedirs(REPORTS_DIR, exist_ok=True)
        report_path = os.path.join(
            REPORTS_DIR, f"{state.campaign_id}_report.json"
        )
        graphml_path = os.path.join(
            REPORTS_DIR, f"{state.campaign_id}_graph.graphml"
        )

        # ── Build react trace summary ─────────────────────────────────────────
        react_traces = getattr(state, "react_traces", {})
        react_summary = []
        for phase, steps in react_traces.items():
            react_summary.append({
                "phase": phase,
                "steps": len(steps),
                "trace": steps,
            })

        # ── Attack graph summary ──────────────────────────────────────────────
        graph_summary = self.graph.get_summary(state.campaign_id)
        attack_path   = self.graph.get_attack_path(state.campaign_id)

        # ── Build full report ─────────────────────────────────────────────────
        report = {
            "campaign_id":    state.campaign_id,
            "target":         state.target_input,
            "objective":      state.objective,
            "started_at":     state.started_at,
            "completed_at":   datetime.now().isoformat(),
            "findings":       [vars(f) for f in state.findings],
            "credentials":    [vars(c) for c in state.credentials],
            "attck_mapping":  state.attck_mapping,
            "attack_path":    state.attack_path,
            "react_traces":   react_summary,
            "graph_summary":  graph_summary,
            "neo4j_path":     attack_path,
            "rag_summary":    {k: str(v)[:300] for k, v in state.rag_context.items()},
        }

        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        state.report_path = report_path
        logger.success(f"[Reporting] Report saved: {report_path}")
        console.print(f"\n[green]✓ Report saved:[/green] {report_path}")

        # ── Layer 3a: Export attack graph as GraphML ──────────────────────────
        try:
            self.graph.export_graphml(graphml_path, state.campaign_id)
            console.print(f"[green]✓ Attack graph:[/green] {graphml_path}")
        except Exception as e:
            logger.warning(f"[Graph] GraphML export failed: {e}")

        # ── Layer 3b: Store campaign in LettaMemory ───────────────────────────
        try:
            self.memory.store_campaign(state)
            mem_status = self.memory.status_report()
            console.print(
                f"[magenta]✓ Memory stored:[/magenta] "
                f"{mem_status['campaigns_stored']} campaigns | "
                f"{mem_status['techniques_known']} techniques | "
                f"{mem_status['credentials_stored']} creds — "
                f"backend: {mem_status['backend']}"
            )
        except Exception as e:
            logger.warning(f"[Memory] store_campaign failed: {e}")

        state.current_phase = CampaignPhase.COMPLETE
        state.log_step(f"Report saved: {report_path}")
        return True

    # ── Summary ───────────────────────────────────────────────────────────────

    def _print_summary(self, state: CampaignState):
        react_traces = getattr(state, "react_traces", {})
        total_react_steps = sum(len(v) for v in react_traces.values())
        graph_summary = self.graph.get_summary(state.campaign_id)

        table = Table(title=f"Campaign Summary — {state.campaign_id}", show_lines=True)
        table.add_column("Field",   style="cyan")
        table.add_column("Value")
        table.add_row("Target",          state.target_input)
        table.add_row("Status",          state.current_phase.value)
        table.add_row("Findings",        str(len(state.findings)))
        table.add_row("Credentials",     str(len(state.credentials)))
        table.add_row("ATT&CK IDs",      ", ".join(state.attck_mapping) or "none")
        table.add_row("ReAct Steps",     str(total_react_steps))
        table.add_row("Phases Traced",   ", ".join(react_traces.keys()) or "none")
        table.add_row("Graph Hosts",     str(graph_summary.get("total_hosts", 0)))
        table.add_row("Graph Vulns",     str(graph_summary.get("total_vulns", 0)))
        table.add_row("Compromised",     str(graph_summary.get("compromised", 0)))
        table.add_row("Memory Backend",  "Letta" if self.memory.using_letta else "local JSON")
        table.add_row("Past Campaigns",  str(self.memory.campaign_count()))
        table.add_row("Report",          state.report_path or "not generated")
        console.print(table)
