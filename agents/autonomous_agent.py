"""
Autonomous ReAct Agent
Implements Reason + Act loop: Observe → Think → Act → Observe → ...

Each iteration:
  1. LLM receives: goal, current observation, history, available tools
  2. LLM outputs: Thought (reasoning) + Action (tool + args)
  3. Tool executes — real output becomes next observation
  4. Loop until: "done": true  OR  max_steps reached

Every Thought/Action/Observation triple is recorded in CampaignState.attack_path.
"""
import os
import sys
import json
import re
from dataclasses import dataclass
from typing import Optional
from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from core.campaign_state  import CampaignState, Finding
from core.llm_client      import LLMClient
from core.decision_engine import AutonomousDecisionEngine
from agents.tools.tool_registry import ToolRegistry, ToolResult
from knowledge.qdrant.rag_retriever import RAGRetriever


# ── Essential ports list (shared constant — must match tool_registry) ────────
# 33 ports covering the most critical attack surfaces without timeout risk.
# The LLM is instructed to use ONLY these — never 1-65535 or 1-1024.
ESSENTIAL_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,443,445,"
    "512,513,514,993,995,1433,1521,2049,3306,3389,"
    "5432,5900,5985,6379,8080,8443,8888,9200,27017"
)

# ── Phase system prompts ───────────────────────────────────────────────────────

PHASE_SYSTEM_PROMPTS: dict[str, str] = {
    "recon": f"""You are an expert network reconnaissance AI pentester.

Your goal: discover live hosts and open services on the target network.

STRICT WORKFLOW — follow in order:
  Step 1 — nmap_ping_sweep on the provided target. If the target is a subnet (e.g., /24), scan the entire subnet to find live hosts. If the target is a single host, scan ONLY this host and do NOT scan the subnet behind it.
  Step 2 — nmap_port_scan on EACH live host individually.
  Step 3 — If web ports (80/443/8080/8443) are found, run http_probe.
  Step 4 — Set done=true once you have service info for all live hosts.

PORT SCAN RULES — MANDATORY:
  - ALWAYS pass stealth="medium" (T3, fast enough, not flagged).
  - NEVER pass ports="1-65535" or ports="1-1024" — these ALWAYS timeout.
  - You MAY omit the "ports" argument entirely to use the safe default.
  - If you want specific ports, use a short comma-separated list only, e.g.:
      "ports": "22,80,443,3306,8080"
  - The safe default already covers: {ESSENTIAL_PORTS}

REMEMBER: A timed-out scan gives zero data. Short focused scans give real data.""",

    "scanning": """You are an expert vulnerability scanning AI pentester.
Your goal: identify exploitable vulnerabilities on discovered hosts.
Use nmap_vuln_scan on open ports, http_probe to fingerprint web apps, nikto for web vulns.
Correlate findings with CVEs. When you have actionable vulnerabilities, set done=true.

PORT RULES: Use only specific open ports discovered in RECON — never scan 1-65535.""",

    "exploitation": """You are an expert exploitation AI pentester.
Your goal: gain initial access by exploiting discovered vulnerabilities.
Use run_command with msfconsole or curl for web exploits. Try sqlmap on web forms.
If one exploit fails, pivot to the next. When you have a shell or confirmed access, set done=true.""",

    "privesc": """You are an expert privilege escalation AI pentester.
Your goal: escalate from current user to root/SYSTEM on compromised hosts.
Use run_command to enumerate local privesc opportunities (sudo -l, SUID, services, kernel).
Execute the best privesc technique. When you have elevated privileges, set done=true.""",

    "persistence": """You are an expert persistence AI pentester.
Your goal: establish durable access that survives reboots on compromised hosts.
Use run_command to create backdoors: scheduled tasks, registry keys, SSH keys, web shells.
Confirm persistence mechanism is active. When established, set done=true.""",

    "lateral_movement": """You are an expert lateral movement AI pentester.
Your goal: move from initial foothold to high-value targets using credentials and trust relationships.
Use run_command with crackmapexec, impacket, or smbclient. Spray harvested credentials.
When you've accessed new hosts, set done=true.""",

    "exfiltration": """You are an expert data exfiltration AI pentester.
Your goal: locate and exfiltrate sensitive data (patient records, credentials, PII).
Use run_command to find and compress target data, then exfil via DNS tunnel, HTTP, or ICMP.
Confirm data received at C2. When data is out, set done=true.""",
}

REACT_SYSTEM_BASE = """You are an autonomous AI red team agent running a real penetration test.
You must use the provided tools to actually probe the target — do NOT fabricate outputs.

{phase_prompt}

{tools_schema}

══════════════════════════════════════════════
⚠  HARD CONSTRAINTS — VIOLATING THESE CAUSES TIMEOUTS AND WASTED STEPS:
1. NEVER use ports="1-65535" or ports="1-1024". These ALWAYS timeout (300s+).
2. NEVER scan multiple comma-separated hosts in one nmap_port_scan call — scan one host at a time.
3. For nmap_port_scan, OMIT the "ports" arg to use the safe 33-port default, OR pass a
   short specific list: e.g. "ports": "22,80,443,8080".
4. Use stealth="medium" (T3) unless the campaign explicitly requires "high" (T2 — slow).
5. Do NOT repeat the same scan you already ran — check action history before acting.
══════════════════════════════════════════════

You must respond with valid JSON only:
{{
  "thought": "<your reasoning about what you observed and what to do next>",
  "tool": "<tool name>",
  "args": {{<tool arguments as dict>}},
  "done": false,
  "finding": null
}}

When done=true, include a finding if significant:
{{
  "thought": "<final analysis>",
  "tool": "none",
  "args": {{}},
  "done": true,
  "finding": {{
    "title": "<short title>",
    "description": "<detailed description>",
    "severity": "critical|high|medium|low",
    "technique_id": "<ATT&CK ID>",
    "evidence": "<exact tool output snippet>",
    "remediation": "<how to fix>"
  }}
}}
"""


# ── Thought/Action/Observation record ─────────────────────────────────────────

@dataclass
class ReActStep:
    step:        int
    thought:     str
    tool:        str
    args:        dict
    observation: str
    success:     bool
    duration:    float = 0.0

    def to_narrative(self) -> str:
        return (
            f"[Step {self.step}] Thought: {self.thought[:200]}\n"
            f"  Action: {self.tool}({json.dumps(self.args)[:150]})\n"
            f"  Observation: {self.observation[:300]}"
        )

    def to_dict(self) -> dict:
        return {
            "step":        self.step,
            "thought":     self.thought,
            "tool":        self.tool,
            "args":        self.args,
            "observation": self.observation[:2000],
            "success":     self.success,
            "duration":    round(self.duration, 2),
        }



# ── Main ReAct Agent ───────────────────────────────────────────────────────────

class ReActAgent:
    """
    Autonomous agent that runs a Reason+Act loop for a given kill-chain phase.
    Wires together: LLM reasoning, real tool execution, RAG context, campaign state.
    """

    def __init__(
        self,
        phase:         str,
        llm:           LLMClient,
        tool_registry: ToolRegistry,
        rag:           RAGRetriever,
        engine:        AutonomousDecisionEngine,
        max_steps:     int = 8,
    ):
        self.phase         = phase
        self.llm           = llm
        self.tools         = tool_registry
        self.rag           = rag
        self.engine        = engine
        self.max_steps     = max_steps
        self.steps: list[ReActStep] = []

    # ── Entry point ────────────────────────────────────────────────────────────

    def run(self, state: CampaignState) -> bool:
        """
        Execute the ReAct loop for this phase.
        Returns True if the phase objective was achieved, False to trigger pivot.
        """
        logger.info(f"[ReAct:{self.phase}] Starting loop (max_steps={self.max_steps})")
        self.steps = []

        # Build initial observation from state + RAG context
        rag_context = self.rag.query_phase(
            phase   = self.phase,
            context = f"{self.phase} {state.target_input}",
            top_k   = 4,
        )
        observation = self._build_initial_observation(state, rag_context)

        # Build system prompt
        phase_prompt  = PHASE_SYSTEM_PROMPTS.get(self.phase, "Execute the current penetration test phase.")
        tools_schema  = self.tools.available_tools_schema()
        system_prompt = REACT_SYSTEM_BASE.format(
            phase_prompt=phase_prompt,
            tools_schema=tools_schema,
        )

        history: list[dict] = []
        succeeded = False

        for step_num in range(1, self.max_steps + 1):
            logger.info(f"[ReAct:{self.phase}] Step {step_num}/{self.max_steps}")

            # Build user message with current observation and history
            user_msg = self._build_step_message(
                step=step_num,
                observation=observation,
                history=history,
                state=state,
            )

            # LLM decides next action
            raw_response = self.llm.complete(
                system  = system_prompt,
                user    = user_msg,
                model   = "heavy",
                json_mode=True,
                max_tokens=1024,
            )

            # Parse the LLM response
            action = self._parse_action(raw_response, step_num)
            if action is None:
                logger.warning(f"[ReAct:{self.phase}] Failed to parse action at step {step_num}")
                break

            thought = action.get("thought", "")
            tool    = action.get("tool", "none").lower()
            args    = action.get("args", {})
            done    = action.get("done", False)
            finding = action.get("finding")

            logger.info(f"[ReAct:{self.phase}] Thought: {thought[:100]}")
            logger.info(f"[ReAct:{self.phase}] Action: {tool}({str(args)[:100]})")

            # Print live to console
            from rich.console import Console
            console = Console(force_terminal=True)
            console.print(f"  [dim cyan][Step {step_num}][/dim cyan] [yellow]{tool}[/yellow]: {thought[:120]}")

            # Execute tool
            if tool and tool != "none":
                tool_result = self.tools.dispatch(tool, args)
                observation = tool_result.text(max_chars=3000)
                console.print(f"  [dim]Result ({len(observation)} chars): {observation[:150]}...[/dim]")
            else:
                tool_result = ToolResult(tool="none", command="", stdout="[No tool executed]")
                observation = "[No tool executed — agent reasoning only]"

            # Record step
            react_step = ReActStep(
                step        = step_num,
                thought     = thought,
                tool        = tool,
                args        = args,
                observation = observation,
                success     = tool_result.success,
                duration    = tool_result.duration,
            )
            self.steps.append(react_step)
            history.append({
                "step":        step_num,
                "thought":     thought,
                "tool":        tool,
                "args":        args,
                "observation": observation[:800],
            })

            # Log to campaign state (keeping attack_path clean for the final report timeline)
            pass

            # Update state from tool output
            self._update_state_from_observation(state, tool, tool_result, args)

            # Record finding if provided
            if finding and isinstance(finding, dict):
                state.add_finding(
                    phase        = self.phase,
                    title        = finding.get("title", f"{self.phase} finding"),
                    description  = finding.get("description", ""),
                    severity     = finding.get("severity", "medium"),
                    host         = self._extract_host(args, state),
                    technique_id = finding.get("technique_id", ""),
                    evidence     = finding.get("evidence", observation[:300]),
                    remediation  = finding.get("remediation", ""),
                )
                tid = finding.get("technique_id", "")
                if tid and tid not in state.attck_mapping:
                    state.attck_mapping.append(tid)

            if done:
                logger.success(f"[ReAct:{self.phase}] Phase complete at step {step_num}")
                succeeded = True
                break

        # Write full trace to campaign log
        state.log_step(
            f"[ReAct:{self.phase}] Completed {len(self.steps)} steps | "
            f"success={succeeded}"
        )

        # Store react trace in state for reporting (using structured dictionary format)
        if not hasattr(state, "react_traces"):
            state.react_traces = {}
        state.react_traces[self.phase] = [s.to_dict() for s in self.steps]

        return succeeded

    # ── Message construction ───────────────────────────────────────────────────

    def _build_initial_observation(self, state: CampaignState, rag_context: str) -> str:
        """Build the first observation fed to the agent."""
        parts = [
            f"TARGET: {state.target_input}",
            f"OBJECTIVE: {state.objective}",
            f"STEALTH LEVEL: {state.stealth_level}",
            f"PHASE: {self.phase.upper()}",
        ]

        if state.target.hosts:
            parts.append(f"KNOWN HOSTS: {', '.join(state.target.hosts[:10])}")
        if state.target.open_ports:
            for host, ports in list(state.target.open_ports.items())[:3]:
                parts.append(f"OPEN PORTS on {host}: {ports}")
        if state.target.services:
            for host, svcs in list(state.target.services.items())[:3]:
                parts.append(f"SERVICES on {host}: {svcs}")
        if state.compromised_hosts:
            parts.append(f"COMPROMISED HOSTS: {', '.join(state.compromised_hosts)}")
        if state.credentials:
            cred_list = [f"{c.username}@{c.host}" for c in state.credentials[:5]]
            parts.append(f"CAPTURED CREDENTIALS: {', '.join(cred_list)}")
        if state.failed_techniques:
            parts.append(f"FAILED TECHNIQUES (do not retry): {', '.join(state.failed_techniques[-5:])}")
        if rag_context and rag_context != "No relevant knowledge found.":
            parts.append(f"\nRAG KNOWLEDGE BASE CONTEXT:\n{rag_context[:1500]}")

        return "\n".join(parts)

    def _build_step_message(
        self,
        step: int,
        observation: str,
        history: list[dict],
        state: CampaignState,
    ) -> str:
        """Build the user message for each ReAct step."""
        msg_parts = []

        if step == 1:
            msg_parts.append("=== INITIAL STATE ===")
            msg_parts.append(observation)
        else:
            msg_parts.append(f"=== STEP {step} — OBSERVATION FROM LAST ACTION ===")
            msg_parts.append(observation[:2000])

        if history:
            msg_parts.append(f"\n=== ACTION HISTORY (last {min(3, len(history))} steps) ===")
            for h in history[-3:]:
                msg_parts.append(
                    f"Step {h['step']}: [{h['tool']}] {h['thought'][:100]}\n"
                    f"  -> {h['observation'][:200]}"
                )

        msg_parts.append(f"\n=== YOUR TURN: Step {step} ===")
        msg_parts.append(
            "Analyze the observation above. Choose the best next tool action.\n"
            "If the phase objective is complete, set done=true.\n"
            "Respond with JSON only."
        )

        return "\n".join(msg_parts)

    # ── Response parsing ───────────────────────────────────────────────────────

    def _parse_action(self, raw: str, step: int) -> Optional[dict]:
        """Parse LLM JSON response, handling wrapped/malformed output."""
        if not raw:
            return None

        # Strip markdown code fences
        raw = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("```").strip()

        # Try direct parse
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass

        # Try extracting first JSON object
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass

        logger.warning(f"[ReAct:{self.phase}] Could not parse step {step} response: {raw[:200]}")
        # Return a safe fallback
        return {
            "thought": "Failed to parse LLM response — pausing",
            "tool":    "none",
            "args":    {},
            "done":    False,
            "finding": None,
        }

    # ── State enrichment from tool output ─────────────────────────────────────

    def _update_state_from_observation(
        self,
        state: CampaignState,
        tool:  str,
        result: ToolResult,
        args:  dict,
    ):
        """
        Parse tool output and update CampaignState with discovered information.
        """
        if not result.success or not result.stdout:
            return

        output = result.stdout

        if tool in ("nmap_ping_sweep", "nmap_scan") and "Host is up" in output:
            # Extract live hosts from nmap ping sweep output
            import re
            found_hosts = re.findall(r"Nmap scan report for (\S+)", output)
            for h in found_hosts:
                # Strip hostname, keep IP
                ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", h)
                host_ip = ip_match.group(1) if ip_match else h
                if host_ip not in state.target.hosts:
                    state.target.hosts.append(host_ip)
                    logger.info(f"[ReAct] Discovered host: {host_ip}")

        elif tool in ("nmap_port_scan", "nmap_vuln_scan") and "/tcp" in output:
            target_host = args.get("host", "")
            if target_host:
                import re
                # Extract open ports
                open_ports = re.findall(r"(\d+)/tcp\s+open\s+(\S+)", output)
                port_list  = [int(p) for p, _ in open_ports]
                svc_dict   = {int(p): s for p, s in open_ports}

                if port_list:
                    state.target.open_ports[target_host] = port_list
                    state.target.services[target_host]   = svc_dict
                    logger.info(f"[ReAct] {target_host} ports: {port_list[:10]}")

                # Mark host as seen
                if target_host not in state.target.hosts:
                    state.target.hosts.append(target_host)

    @staticmethod
    def _extract_host(args: dict, state: CampaignState) -> str:
        """Best-effort extract target host from args."""
        for key in ("host", "target", "url"):
            val = args.get(key, "")
            if val:
                return str(val)
        return state.target.hosts[0] if state.target.hosts else state.target_input


# ── Summary helper ─────────────────────────────────────────────────────────────

def build_react_summary(traces: dict) -> list[dict]:
    """
    Convert per-phase react traces into a clean list for the final report.
    """
    summary = []
    for phase, steps in traces.items():
        summary.append({
            "phase": phase,
            "steps": len(steps),
            "trace": steps,
        })
    return summary
