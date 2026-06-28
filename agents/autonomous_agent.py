"""
Autonomous Red Team Agent — Fixed ReAct Loop
Key fixes:
  1. Simpler JSON schema (3 fields: thought, tool, args)
  2. Concrete few-shot examples stop placeholder hallucination
  3. Groq primary (json_mode=True enforces valid JSON)
  4. Multi-strategy JSON parser
  5. Placeholder detector
  6. Loop detection
"""
import json, os, sys, re
from datetime import datetime
from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.llm_client import LLMClient
from tools.tool_registry import execute_tool, get_tool_descriptions

console = Console()
MAX_STEPS = 40

AGENT_SYSTEM = """You are an autonomous red team AI agent on an authorized penetration test.

TARGET: {target}
OBJECTIVE: {objective}
STEALTH: {stealth}

AVAILABLE TOOLS:
{tools}

YOU MUST RESPOND WITH ONLY THIS JSON — NO OTHER TEXT:
{{"thought": "reason here", "tool": "tool_name", "args": {{}}}}

EXAMPLES:

Scan ports:
{{"thought": "Start recon by scanning ports.", "tool": "nmap_port_scan", "args": {{"host": "192.168.1.1", "ports": "1-1000"}}}}

Probe web app:
{{"thought": "Port 80 open, probing web app.", "tool": "http_probe", "args": {{"url": "http://192.168.1.1:80"}}}}

Run command:
{{"thought": "Fingerprint web tech.", "tool": "run_command", "args": {{"command": "whatweb http://192.168.1.1", "timeout": 30}}}}

Search exploits:
{{"thought": "Found Apache 2.4.49, searching exploits.", "tool": "search_exploits", "args": {{"query": "Apache 2.4.49"}}}}

Record finding:
{{"thought": "SQL injection confirmed.", "tool": "report_finding", "args": {{"title": "SQL Injection", "severity": "critical", "host": "192.168.1.1", "description": "Login form vulnerable", "technique_id": "T1190"}}}}

Done:
{{"thought": "Campaign complete, all findings recorded.", "tool": "done", "args": {{}}}}

RULES:
- Never output placeholder text like <tool_name> or <your reasoning>
- Always use real tool names from the list
- Always use real values in args, not placeholders
- If a tool fails, try a different approach
- When finished, use tool: "done"
"""

class AutonomousAgent:

    def __init__(self, qdrant_path: str):
        self.qdrant_path = qdrant_path
        self.llm         = LLMClient()
        self.target      = ""
        self.objective   = ""
        self.stealth     = "high"
        self.campaign_id = ""
        self.steps       = []
        self.findings    = []
        self.tried       = {}

    def run(self, target: str, objective: str = "", stealth: str = "high") -> dict:
        self.target      = target
        self.objective   = objective or f"Fully compromise {target}"
        self.stealth     = stealth
        self.campaign_id = f"RT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        console.print(Panel.fit(
            f"[bold red]AUTONOMOUS RED TEAM AGENT[/bold red]\n"
            f"Target    : [cyan]{target}[/cyan]\n"
            f"Objective : [yellow]{self.objective[:80]}[/yellow]\n"
            f"Stealth   : [green]{stealth}[/green]\n"
            f"ID        : {self.campaign_id}",
            border_style="red",
        ))

        system = AGENT_SYSTEM.format(
            target    = self.target,
            objective = self.objective,
            stealth   = self.stealth,
            tools     = get_tool_descriptions(),
        )

        history = []
        history.append({
            "role": "user",
            "content": (
                f"Begin penetration test against: {target}\n"
                f"Start with port scanning. Respond ONLY with valid JSON."
            )
        })

        parse_failures   = 0
        MAX_PARSE_FAIL   = 3

        for step_num in range(1, MAX_STEPS + 1):
            console.print(f"\n[dim]--- Step {step_num}/{MAX_STEPS} ---[/dim]")

            context = self._build_context(history)

            try:
                raw = self.llm.complete(
                    system_prompt = system,
                    user_prompt   = context,
                    max_tokens    = 400,
                    temperature   = 0.05,
                    json_mode     = True,
                )
            except Exception as e:
                logger.error(f"LLM call failed: {e}")
                break

            parsed = self._parse_strict(raw)

            if not parsed:
                parse_failures += 1
                logger.warning(f"Parse failure {parse_failures}/{MAX_PARSE_FAIL} | raw={raw[:200]}")
                if parse_failures >= MAX_PARSE_FAIL:
                    history = history[-4:]
                    history.append({
                        "role": "user",
                        "content": f'{{"thought": "scan the target", "tool": "nmap_port_scan", "args": {{"host": "{target}"}}}}\n\nCopy this exact format and fill in your own values.'
                    })
                    parse_failures = 0
                else:
                    history.append({"role": "assistant", "content": raw})
                    history.append({
                        "role": "user",
                        "content": f'Invalid JSON. Use this exact format: {{"thought": "I will scan the target", "tool": "nmap_port_scan", "args": {{"host": "{target}"}}}}'
                    })
                continue

            parse_failures = 0
            thought = str(parsed.get("thought", ""))
            tool    = str(parsed.get("tool", ""))
            args    = parsed.get("args", {})
            if not isinstance(args, dict):
                args = {}

            if self._is_placeholder(tool) or self._is_placeholder(thought):
                logger.warning(f"Placeholder detected: tool={tool[:40]}")
                history.append({"role": "assistant", "content": raw})
                history.append({
                    "role": "user",
                    "content": f'You used placeholder text. Use a real tool. Example: {{"thought": "scanning target", "tool": "nmap_port_scan", "args": {{"host": "{target}"}}}}'
                })
                continue

            console.print(f"[bold cyan]Thought:[/bold cyan] {thought[:160]}")
            console.print(f"[bold yellow]Action:[/bold yellow]  {tool}({json.dumps(args)[:100]})")

            if tool in ("done", "complete", "finish", "end"):
                console.print("[bold green]Agent: campaign complete[/bold green]")
                break

            key = f"{tool}:{json.dumps(args, sort_keys=True)[:60]}"
            self.tried[key] = self.tried.get(key, 0) + 1
            if self.tried[key] > 2:
                observation = f"Already tried {tool} with same args {self.tried[key]} times. Use a different tool or different args."
                console.print(f"[dim red]Loop detected — forcing change[/dim red]")
            else:
                if tool == "rag_query":
                    args["qdrant_path"] = self.qdrant_path
                observation = execute_tool(tool, args)

            if tool == "report_finding":
                try:
                    result = json.loads(observation)
                    if result.get("recorded"):
                        f = result["finding"]
                        self.findings.append(f)
                        sev = f.get("severity","?")
                        console.print(f"  [bold red]FINDING [{sev.upper()}]:[/bold red] {f.get('title','?')}")
                except Exception:
                    pass

            obs_short = observation[:250].replace('\n', ' ')
            console.print(f"[bold green]Result:[/bold green]  {obs_short}")

            self.steps.append({
                "step":        step_num,
                "thought":     thought,
                "tool":        tool,
                "args":        args,
                "observation": observation[:600],
            })

            history.append({"role": "assistant", "content": raw})
            history.append({
                "role": "user",
                "content": (
                    f"Result from {tool}:\n{observation[:600]}\n\n"
                    f"What is your next action? Respond with JSON only."
                )
            })

        return self._save_report()

    def _build_context(self, history: list) -> str:
        parts = []
        for msg in history[-8:]:
            role = "Agent" if msg["role"] == "assistant" else "User"
            parts.append(f"{role}: {msg['content'][:300]}")
        return "\n\n".join(parts)

    def _parse_strict(self, raw: str) -> dict | None:
        if not raw or not raw.strip():
            return None
        clean = re.sub(r"```(?:json)?", "", raw).strip().strip("`").strip()
        try:
            r = json.loads(clean)
            if isinstance(r, dict) and "tool" in r:
                return r
        except Exception:
            pass
        match = re.search(r'\{[^{}]*"tool"\s*:[^{}]*\}', clean, re.DOTALL)
        if match:
            try:
                r = json.loads(match.group())
                if "tool" in r:
                    return r
            except Exception:
                pass
        match = re.search(r'\{.*\}', clean, re.DOTALL)
        if match:
            try:
                r = json.loads(match.group())
                if isinstance(r, dict):
                    return r
            except Exception:
                pass
        m = re.search(r'"tool"\s*:\s*"([a-zA-Z_]+)"', raw)
        if m:
            tool = m.group(1)
            m2 = re.search(r'"thought"\s*:\s*"([^"]{5,})"', raw)
            thought = m2.group(1) if m2 else "Continuing pentest"
            return {"thought": thought, "tool": tool, "args": {}}
        return None

    def _is_placeholder(self, text: str) -> bool:
        if not text:
            return True
        bad = ["<", "tool_name", "your reasoning", "choose next",
               "pass args", "key_1", "placeholder", "<tool", "<action",
               "analyze observation", "next tool action"]
        t = text.lower()
        return any(b in t for b in bad)

    def _save_report(self) -> dict:
        os.makedirs("reports", exist_ok=True)
        path = f"reports/{self.campaign_id}_report.json"
        report = {
            "campaign_id": self.campaign_id,
            "target":      self.target,
            "objective":   self.objective,
            "total_steps": len(self.steps),
            "findings":    self.findings,
            "attack_path": [
                f"Step {s['step']}: {s['tool']}({json.dumps(s['args'])[:50]})"
                for s in self.steps
            ],
        }
        with open(path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        table = Table(title=f"Summary — {self.campaign_id}", show_lines=True)
        table.add_column("Field", style="cyan")
        table.add_column("Value")
        table.add_row("Target",      self.target)
        table.add_row("Steps",       str(len(self.steps)))
        table.add_row("Findings",    str(len(self.findings)))
        for f in self.findings:
            sev = f.get("severity","?")
            c = {"critical":"bold red","high":"red","medium":"yellow","low":"dim"}.get(sev,"white")
            table.add_row(f"  [{c}]{sev.upper()}[/{c}]", f.get("title","?"))
        table.add_row("Report", path)
        console.print(table)
        return report
