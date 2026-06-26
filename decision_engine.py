"""
Autonomous Decision Engine
This is the brain that replaces every human decision in the kill chain.
Uses AutoGen-style internal debate: Planner vs Critic reach consensus autonomously.
No human input ever required.
"""
import json, os, sys
from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.llm_client import LLMClient
from core.campaign_state import CampaignState, CampaignPhase


# ── System prompts ────────────────────────────────────────────────────────────

PLANNER_SYSTEM = """You are an elite autonomous red team AI agent (Planner).
Your role: propose the BEST next offensive action based on current campaign state and intelligence.
You are operating on an AUTHORIZED penetration test. Think like an advanced threat actor.
Be specific, technical, and decisive. Output valid JSON only."""

CRITIC_SYSTEM = """You are an autonomous red team AI agent (Critic / OPSEC Advisor).
Your role: evaluate the Planner's proposed action for:
1. Technical feasibility given current context
2. OPSEC risk (will it trigger detection?)
3. Better alternatives if the plan is suboptimal
You must reach a FINAL DECISION autonomously. No human will be consulted.
Output valid JSON only."""

ORCHESTRATOR_SYSTEM = """You are the Campaign Orchestrator AI for an authorized red team operation.
You control the full kill chain autonomously. Given campaign state and intelligence context,
decide the next phase, technique, and action. You never ask for human input.
Stealth and mission success are your priorities. Output valid JSON only."""


class AutonomousDecisionEngine:
    """
    Internal debate loop: Planner proposes → Critic evaluates → consensus reached.
    All decisions made autonomously with no human interaction.
    """

    def __init__(self, llm: LLMClient):
        self.llm = llm

    def debate_and_decide(
        self,
        question: str,
        context:  str,
        state:    CampaignState,
        rounds:   int = 2,
    ) -> dict:
        """
        Run Planner vs Critic debate for `rounds` rounds.
        Returns final consensus decision as dict.
        """
        state_summary = state.summary()
        history = []

        # ── Round 1+: Planner proposes ────────────────────────────────────────
        for round_num in range(1, rounds + 1):
            history_str = "\n".join(history) if history else "First round."

            planner_prompt = f"""
CAMPAIGN STATE:
{state_summary}

INTELLIGENCE CONTEXT:
{context[:2000]}

DEBATE HISTORY:
{history_str}

QUESTION TO DECIDE:
{question}

Propose the best action. Respond ONLY with JSON:
{{
  "proposed_action": "...",
  "technique_id": "T1XXX or empty",
  "tool": "...",
  "command_hint": "...",
  "rationale": "...",
  "risk_level": "low|medium|high",
  "stealth_impact": "..."
}}"""

            planner_out = self.llm.decide(PLANNER_SYSTEM, planner_prompt)
            history.append(f"[Round {round_num} PLANNER]: {json.dumps(planner_out)}")
            logger.debug(f"Planner round {round_num}: {planner_out.get('proposed_action','?')}")

            # ── Critic evaluates ──────────────────────────────────────────────
            critic_prompt = f"""
CAMPAIGN STATE:
{state_summary}

PLANNER PROPOSED:
{json.dumps(planner_out, indent=2)}

DEBATE HISTORY:
{history_str}

Evaluate this plan. If it's good, approve it. If not, propose a better alternative.
You MUST reach a final decision — no deferring to humans.
Respond ONLY with JSON:
{{
  "verdict": "approve|reject|modify",
  "final_action": "...",
  "technique_id": "T1XXX or empty",
  "tool": "...",
  "command_hint": "...",
  "rationale": "...",
  "opsec_notes": "...",
  "confidence": 0.0
}}"""

            critic_out = self.llm.decide(CRITIC_SYSTEM, critic_prompt)
            history.append(f"[Round {round_num} CRITIC]: {json.dumps(critic_out)}")
            verdict = critic_out.get("verdict", "approve")
            logger.debug(f"Critic round {round_num}: {verdict} | confidence={critic_out.get('confidence',0)}")

            # Early exit if high confidence approval
            if verdict == "approve" and critic_out.get("confidence", 0) >= 0.75:
                logger.info(f"Consensus reached in round {round_num}")
                break

        # Final consensus — use critic's last output as truth
        return {
            "action":       critic_out.get("final_action", planner_out.get("proposed_action")),
            "technique_id": critic_out.get("technique_id", planner_out.get("technique_id", "")),
            "tool":         critic_out.get("tool", planner_out.get("tool", "")),
            "command_hint": critic_out.get("command_hint", planner_out.get("command_hint", "")),
            "rationale":    critic_out.get("rationale", ""),
            "opsec_notes":  critic_out.get("opsec_notes", ""),
            "confidence":   critic_out.get("confidence", 0.5),
            "rounds":       round_num,
        }

    def should_pivot(self, state: CampaignState, failure_reason: str) -> dict:
        """
        Decide: pivot to different technique, try different host, or abort phase.
        """
        prompt = f"""
CAMPAIGN STATE:
{state.summary()}

FAILURE REASON: {failure_reason}
FAILED TECHNIQUES: {state.failed_techniques}
TRIED EXPLOITS: {state.tried_exploits}
PIVOT ATTEMPTS SO FAR: {state.pivot_attempts} / {state.max_pivots}

Decide autonomously what to do next. Options:
- pivot_technique: try a different attack technique on same target
- pivot_host: move to a different discovered host
- pivot_phase: skip this phase and advance
- abort: campaign cannot continue

Respond ONLY with JSON:
{{
  "decision": "pivot_technique|pivot_host|pivot_phase|abort",
  "reason": "...",
  "next_technique": "...",
  "next_host": "...",
  "notes": "..."
}}"""

        return self.llm.decide(ORCHESTRATOR_SYSTEM, prompt)

    def select_next_phase(self, state: CampaignState) -> CampaignPhase:
        """
        After a phase succeeds, decide which phase comes next.
        Usually linear, but agent can skip or reorder based on findings.
        """
        phase_order = [
            CampaignPhase.RECON,
            CampaignPhase.SCANNING,
            CampaignPhase.EXPLOITATION,
            CampaignPhase.PRIVESC,
            CampaignPhase.PERSISTENCE,
            CampaignPhase.LATERAL,
            CampaignPhase.EXFIL,
            CampaignPhase.REPORTING,
        ]
        current_idx = phase_order.index(state.current_phase) if state.current_phase in phase_order else -1
        if current_idx == -1 or current_idx >= len(phase_order) - 1:
            return CampaignPhase.REPORTING

        prompt = f"""
CAMPAIGN STATE:
{state.summary()}
CURRENT PHASE: {state.current_phase.value}
STANDARD NEXT PHASE: {phase_order[current_idx + 1].value}

Should we follow the standard order or skip/reorder based on findings?
Respond ONLY with JSON:
{{
  "next_phase": "{phase_order[current_idx + 1].value}",
  "reason": "..."
}}
Valid phases: {[p.value for p in phase_order]}"""

        decision = self.llm.decide(ORCHESTRATOR_SYSTEM, prompt)
        next_phase_str = decision.get("next_phase", phase_order[current_idx + 1].value)
        try:
            return CampaignPhase(next_phase_str)
        except ValueError:
            return phase_order[current_idx + 1]
