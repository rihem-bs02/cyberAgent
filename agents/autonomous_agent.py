import json
import os
import sys
import re
import time
import hashlib
import traceback
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict

from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.tree import Tree
from rich import box

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.llm_client import LLMClient
from tools.tool_registry import execute_tool, get_tool_descriptions

console = Console()

# ============================================================
# CONFIGURATION & CONSTANTS
# ============================================================

MAX_STEPS = 40
MAX_CONTEXT_WINDOW = 8000
MAX_PARSE_FAILURES = 5
MAX_LOOP_DETECTION = 3
OBSERVATION_MAX_LENGTH = 800
RAG_QUERY_LIMIT = 3  # Reduced to prevent too many queries

# ============================================================
# DATA STRUCTURES
# ============================================================

class CampaignStatus(Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"

@dataclass
class Finding:
    title: str
    severity: str
    host: str
    description: str
    technique_id: str = ""
    mitigation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    related_steps: List[int] = field(default_factory=list)

@dataclass
class AttackStep:
    step_number: int
    thought: str
    tool: str
    args: Dict[str, Any]
    observation: str
    success: bool
    execution_time: float = 0.0
    rag_context: Optional[str] = None

# ============================================================
# KNOWLEDGE BASE (Singleton - loads only once)
# ============================================================

class KnowledgeBase:
    """Singleton RAG integration that loads model only once"""
    
    _instance = None
    
    def __new__(cls, qdrant_path: str = None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, qdrant_path: str = None):
        if self._initialized:
            return
        
        self.qdrant_path = qdrant_path or os.getenv("QDRANT_PATH", "./qdrant")
        self.query_cache = {}
        self.query_count = 0
        self._initialized = True
        
        # Don't load RAG here - it will be loaded on first query
        logger.info("Knowledge Base initialized (lazy loading)")
    
    def query(self, context: str, query_type: str = "general") -> Dict[str, Any]:
        """Query RAG system with caching"""
        cache_key = hashlib.md5(f"{context[:100]}:{query_type}".encode()).hexdigest()
        
        if cache_key in self.query_cache:
            logger.debug(f"RAG cache hit for: {context[:80]}")
            return self.query_cache[cache_key]
        
        try:
            results = execute_tool("rag_query", {
                "qdrant_path": self.qdrant_path,
                "query": context,
                "top_k": RAG_QUERY_LIMIT
            })
            
            if isinstance(results, str):
                try:
                    parsed = json.loads(results)
                except:
                    parsed = {"results": [{"text": results[:200]}]}
            else:
                parsed = results
            
            self.query_cache[cache_key] = parsed
            self.query_count += 1
            
            return parsed
            
        except Exception as e:
            logger.error(f"RAG query failed: {e}")
            return {"results": []}

# ============================================================
# AUTONOMOUS AGENT
# ============================================================

class AutonomousAgent:
    """Fully autonomous red team agent with RAG integration"""
    
    def __init__(self, qdrant_path: str):
        # Core components - use singleton KnowledgeBase
        self.kb = KnowledgeBase(qdrant_path)
        self.llm = LLMClient()
        
        # Campaign state
        self.target = ""
        self.objective = ""
        self.stealth = "high"
        self.campaign_id = ""
        self.status = CampaignStatus.RUNNING
        self.steps: List[AttackStep] = []
        self.findings: List[Finding] = []
        
        # Tracking
        self.tool_usage = defaultdict(int)
        self.error_count = 0
        self.parse_failures = 0
        self.rag_queries = 0
        self.start_time = 0
        
    def run(self, target: str, objective: str = "", stealth: str = "high") -> dict:
        """Main execution method"""
        
        self.start_time = time.time()
        self.target = target
        self.objective = objective or f"Complete security assessment of {target}"
        self.stealth = stealth
        self.campaign_id = f"RT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Display banner
        self._display_banner()
        
        # Build system prompt
        system_prompt = self._build_system_prompt()
        
        # Initialize history
        history = [{
            "role": "user",
            "content": f"Begin penetration test against {target}. Start with reconnaissance using nmap_port_scan."
        }]
        
        # Phase tracking
        phases = {
            1: ("🔍 RECONNAISSANCE", "cyan"),
            10: ("🎯 VULNERABILITY DISCOVERY", "yellow"),
            20: ("💥 EXPLOITATION", "red"),
            30: ("🔑 POST-EXPLOITATION", "magenta")
        }
        
        current_phase = 1
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Executing attack chain...", total=MAX_STEPS)
            
            for step_num in range(1, MAX_STEPS + 1):
                # Check phase transitions
                for phase_num, (phase_name, phase_color) in phases.items():
                    if step_num == phase_num:
                        current_phase = phase_num
                        console.print(f"\n[bold {phase_color}]{phase_name} PHASE[/bold {phase_color}]")
                
                # Check termination
                if self._should_terminate():
                    break
                
                try:
                    # Get RAG context
                    rag_context = self._get_rag_context(history)
                    
                    # Build context
                    context = self._build_context(history, rag_context)
                    
                    # Get LLM decision
                    raw_response = self.llm.complete(
                        system_prompt=system_prompt,
                        user_prompt=context,
                        max_tokens=500,
                        temperature=0.05,
                        json_mode=True
                    )
                    
                    # Parse response
                    parsed = self._parse_response(raw_response)
                    
                    if not parsed:
                        self._handle_parse_failure(raw_response, history)
                        continue
                    
                    thought = parsed.get("thought", "Continuing pentest")
                    tool_name = parsed.get("tool", "")
                    args = parsed.get("args", {})
                    
                    # Validate tool choice
                    if not self._validate_tool_choice(tool_name, args, history):
                        continue
                    
                    # Display step
                    self._display_step(step_num, thought, tool_name, args)
                    
                    # Execute tool
                    execution_start = time.time()
                    
                    if tool_name == "done":
                        self.status = CampaignStatus.COMPLETED
                        console.print("[bold green]✅ Campaign completed![/bold green]")
                        break
                    
                    observation = execute_tool(tool_name, args)
                    execution_time = time.time() - execution_start
                    
                    # Process findings
                    if tool_name == "report_finding":
                        self._process_finding(observation, step_num)
                    
                    # Track usage
                    tool_key = f"{tool_name}:{json.dumps(args, sort_keys=True)[:60]}"
                    self.tool_usage[tool_key] += 1
                    self.rag_queries += 1
                    
                    # Record step
                    step = AttackStep(
                        step_number=step_num,
                        thought=thought,
                        tool=tool_name,
                        args=args,
                        observation=observation[:OBSERVATION_MAX_LENGTH],
                        success=self._determine_success(observation),
                        execution_time=execution_time,
                        rag_context=rag_context[:200] if rag_context else None
                    )
                    self.steps.append(step)
                    
                    # Display observation
                    obs_short = observation[:200].replace('\n', ' ')
                    console.print(f"[bold green]📊 Result:[/bold green] {obs_short}")
                    
                    # Update history
                    history = self._update_history(history, raw_response, observation, tool_name)
                    
                    progress.update(task, advance=1)
                    
                except Exception as e:
                    logger.error(f"Step {step_num} failed: {e}")
                    logger.error(traceback.format_exc())
                    self.error_count += 1
                    
                    if self.error_count > 10:
                        logger.error("Too many errors, aborting")
                        break
        
        # Generate report
        return self._generate_report()
    
    def _build_system_prompt(self) -> str:
        """Build system prompt"""
        return f"""You are an autonomous penetration testing AI agent.

TARGET: {self.target}
OBJECTIVE: {self.objective}
STEALTH LEVEL: {self.stealth}

AVAILABLE TOOLS:
{get_tool_descriptions()}

RESPOND WITH ONLY THIS JSON FORMAT:
{{"thought": "your reasoning here", "tool": "tool_name", "args": {{"param": "value"}}}}

RULES:
1. Start with reconnaissance (nmap_port_scan, http_probe)
2. Then vulnerability discovery (search_exploits)
3. Then exploitation attempts
4. Record all findings with report_finding
5. Use 'done' when complete
6. NEVER use placeholder text
7. ALWAYS use real tool names and values"""
    
    def _get_rag_context(self, history: List[Dict]) -> str:
        """Get RAG context for current state"""
        try:
            # Extract recent actions
            recent = []
            for msg in history[-3:]:
                if msg["role"] == "user":
                    recent.append(msg["content"][:150])
            
            context = " ".join(recent) if recent else f"Starting pentest against {self.target}"
            
            # Query RAG
            results = self.kb.query(context)
            
            if results.get("results"):
                insights = [r.get("text", "")[:150] for r in results["results"][:2] if r.get("text")]
                return " | ".join(insights)
        except Exception as e:
            logger.debug(f"RAG query optional: {e}")
        
        return ""
    
    def _build_context(self, history: List[Dict], rag_insights: str) -> str:
        """Build context for LLM"""
        parts = []
        
        if rag_insights:
            parts.append(f"KNOWLEDGE BASE: {rag_insights}\n")
        
        parts.append(f"Progress: {len(self.steps)}/{MAX_STEPS} steps, {len(self.findings)} findings")
        
        for msg in history[-6:]:
            role = "Agent" if msg["role"] == "assistant" else "Result"
            parts.append(f"{role}: {msg['content'][:300]}")
        
        parts.append("What is your next action? Respond with JSON only.")
        
        return "\n\n".join(parts)
    
    def _parse_response(self, raw: str) -> Optional[Dict]:
        """Parse LLM response with multiple strategies"""
        if not raw or not raw.strip():
            return None
        
        clean = re.sub(r"```(?:json)?", "", raw).strip().strip("`").strip()
        
        # Strategy 1: Direct parse
        try:
            parsed = json.loads(clean)
            if isinstance(parsed, dict) and "tool" in parsed:
                return parsed
        except:
            pass
        
        # Strategy 2: Find JSON with tool key
        match = re.search(r'\{[^{}]*"tool"\s*:\s*"[^"]+"[^{}]*\}', clean, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except:
                pass
        
        # Strategy 3: Extract tool name
        tool_match = re.search(r'"tool"\s*:\s*"([a-zA-Z_]+)"', raw)
        if tool_match:
            thought_match = re.search(r'"thought"\s*:\s*"([^"]{5,})"', raw)
            return {
                "thought": thought_match.group(1) if thought_match else "Continuing",
                "tool": tool_match.group(1),
                "args": {}
            }
        
        return None
    
    def _validate_tool_choice(self, tool_name: str, args: Dict, history: List[Dict]) -> bool:
        """Validate tool choice"""
        
        # Check for placeholder text
        if self._is_placeholder(tool_name):
            logger.warning(f"Placeholder detected: {tool_name}")
            history.append({
                "role": "user",
                "content": f"'{tool_name}' is a placeholder. Use a real tool name from the list."
            })
            return False
        
        # Check for loops
        tool_key = f"{tool_name}:{json.dumps(args, sort_keys=True)[:60]}"
        if self.tool_usage.get(tool_key, 0) >= MAX_LOOP_DETECTION:
            logger.warning(f"Loop detected: {tool_name}")
            history.append({
                "role": "user",
                "content": f"You've used {tool_name} with same args multiple times. Try a different approach."
            })
            return False
        
        # Check dangerous commands
        if tool_name == "run_command" and "command" in args:
            if self._is_dangerous_command(args["command"]):
                logger.warning(f"Dangerous command blocked: {args['command'][:50]}")
                return False
        
        return True
    
    def _is_placeholder(self, text: str) -> bool:
        """Check if text contains placeholder patterns"""
        if not text:
            return True
        
        placeholders = [
            "<", ">", "tool_name", "your reasoning", "choose", "placeholder",
            "analyze", "next tool", "select tool", "decide", "consider"
        ]
        
        text_lower = text.lower()
        return any(p in text_lower for p in placeholders)
    
    def _is_dangerous_command(self, command: str) -> bool:
        """Check for dangerous commands"""
        dangerous = [
            "rm -rf /", "dd if=/dev/zero", "mkfs.", "> /dev/sda",
            "chmod 777 /", ":(){ :|:& };:", "wget -O - | sh", "curl | bash"
        ]
        return any(d in command.lower() for d in dangerous)
    
    def _process_finding(self, observation: str, step_num: int):
        """Process and record finding"""
        try:
            result = json.loads(observation) if isinstance(observation, str) else observation
            
            if result.get("recorded"):
                finding_data = result.get("finding", {})
                
                finding = Finding(
                    title=finding_data.get("title", "Untitled Finding"),
                    severity=finding_data.get("severity", "medium"),
                    host=finding_data.get("host", self.target),
                    description=finding_data.get("description", ""),
                    technique_id=finding_data.get("technique_id", ""),
                    related_steps=[step_num]
                )
                
                self.findings.append(finding)
                
                # Display finding
                severity_colors = {
                    "critical": "bold red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "dim"
                }
                color = severity_colors.get(finding.severity, "white")
                
                console.print(Panel(
                    f"[{color}]🔴 {finding.title}[/{color}]\n"
                    f"Severity: [{color}]{finding.severity.upper()}[/{color}]\n"
                    f"Host: {finding.host}\n"
                    f"Technique: {finding.technique_id}",
                    title="[bold red]FINDING RECORDED[/bold red]",
                    border_style=color.split()[-1] if " " in color else color
                ))
        except Exception as e:
            logger.error(f"Failed to process finding: {e}")
    
    def _should_terminate(self) -> bool:
        """Check termination conditions"""
        if self.status == CampaignStatus.COMPLETED:
            return True
        if self.error_count > 10:
            logger.error("Too many errors")
            self.status = CampaignStatus.FAILED
            return True
        if self.parse_failures > MAX_PARSE_FAILURES:
            logger.error("Too many parse failures")
            self.status = CampaignStatus.FAILED
            return True
        return False
    
    def _display_banner(self):
        """Display campaign banner"""
        console.print(Panel(
            f"[bold red]⚡ AUTONOMOUS RED TEAM AGENT ⚡[/bold red]\n\n"
            f"[cyan]Target:[/cyan] {self.target}\n"
            f"[yellow]Objective:[/yellow] {self.objective[:100]}\n"
            f"[green]Stealth:[/green] {self.stealth.upper()}\n"
            f"[blue]Campaign:[/blue] {self.campaign_id}\n"
            f"[magenta]RAG:[/magenta] Integrated\n"
            f"[dim]Max Steps: {MAX_STEPS}[/dim]",
            title="[bold red]🔴 OPERATION STARTED 🔴[/bold red]",
            border_style="red"
        ))
    
    def _display_step(self, step_num: int, thought: str, tool: str, args: Dict):
        """Display step information"""
        console.print(f"\n[dim]━━━ Step {step_num}/{MAX_STEPS} ━━━[/dim]")
        console.print(f"[bold cyan]💭 {thought[:150]}[/bold cyan]")
        console.print(f"[bold yellow]🔧 {tool}[/bold yellow] {json.dumps(args)[:80]}")
    
    def _initialize_history(self) -> List[Dict]:
        """Initialize conversation history"""
        return [{
            "role": "user",
            "content": f"Begin penetration test against {self.target}. Start with port scanning using nmap_port_scan."
        }]
    
    def _update_history(self, history: List[Dict], response: str, observation: str, tool: str) -> List[Dict]:
        """Update conversation history"""
        history.append({"role": "assistant", "content": response[:500]})
        history.append({
            "role": "user",
            "content": f"Result from {tool}:\n{observation[:500]}\n\nWhat is your next action? Respond with JSON only."
        })
        
        # Keep history manageable
        if len(history) > 16:
            history = [history[0]] + history[-14:]
        
        return history
    
    def _handle_parse_failure(self, raw: str, history: List[Dict]):
        """Handle parse failures"""
        self.parse_failures += 1
        logger.warning(f"Parse failure {self.parse_failures}/{MAX_PARSE_FAILURES}")
        
        if self.parse_failures >= MAX_PARSE_FAILURES:
            history.clear()
            history.append({
                "role": "user",
                "content": (
                    f'You MUST respond with ONLY valid JSON. Example:\n'
                    f'{{"thought": "I will scan the target", '
                    f'"tool": "nmap_port_scan", '
                    f'"args": {{"host": "{self.target}", "ports": "1-1000"}}}}\n\n'
                    f'Begin reconnaissance now.'
                )
            })
            self.parse_failures = 0
    
    def _determine_success(self, observation: str) -> bool:
        """Determine if tool execution was successful"""
        if not observation:
            return False
        failure_keywords = ["error", "failed", "timeout", "refused", "permission denied"]
        return not any(kw in observation.lower() for kw in failure_keywords)
    
    def _generate_report(self) -> dict:
        """Generate final report"""
        duration = time.time() - self.start_time
        
        report = {
            "campaign_id": self.campaign_id,
            "target": self.target,
            "objective": self.objective,
            "duration_seconds": duration,
            "status": self.status.value,
            "statistics": {
                "total_steps": len(self.steps),
                "successful_steps": sum(1 for s in self.steps if s.success),
                "findings_count": len(self.findings),
                "critical_findings": sum(1 for f in self.findings if f.severity == "critical"),
                "high_findings": sum(1 for f in self.findings if f.severity == "high"),
                "rag_queries": self.rag_queries,
                "errors": self.error_count
            },
            "findings": [asdict(f) for f in self.findings],
            "attack_timeline": [
                {
                    "step": s.step_number,
                    "tool": s.tool,
                    "thought": s.thought[:100],
                    "success": s.success,
                    "execution_time": s.execution_time
                }
                for s in self.steps
            ]
        }
        
        # Save report
        os.makedirs("reports", exist_ok=True)
        report_path = f"reports/{self.campaign_id}_report.json"
        
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        # Display summary
        table = Table(title=f"🎯 Summary - {self.campaign_id}", box=box.HEAVY)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="bold")
        
        stats = report["statistics"]
        table.add_row("Status", f"[green]{self.status.value.upper()}[/green]")
        table.add_row("Duration", f"{duration:.2f}s")
        table.add_row("Steps", str(stats["total_steps"]))
        table.add_row("Findings", str(stats["findings_count"]))
        table.add_row("Critical", f"[bold red]{stats['critical_findings']}[/bold red]")
        table.add_row("High", f"[red]{stats['high_findings']}[/red]")
        table.add_row("Report", report_path)
        
        console.print("\n")
        console.print(table)
        
        # Display findings tree
        if self.findings:
            tree = Tree("[bold red]🔍 Findings[/bold red]")
            for f in self.findings:
                icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(f.severity, "⚪")
                tree.add(f"{icon} [{f.severity.upper()}] {f.title}")
            console.print(tree)
        
        return report


# ============================================================
# MAIN EXECUTION
# ============================================================

if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    
    # Resolve Qdrant path
    qdrant_path = os.getenv("QDRANT_PATH")
    if not qdrant_path:
        possible_paths = [
            "./qdrant", "../qdrant", "/dataset/qdrant", 
            "/app/data/qdrant", "/app/qdrant_data"
        ]
        for p in possible_paths:
            if os.path.exists(p):
                qdrant_path = p
                break
        else:
            qdrant_path = "./qdrant"
    
    print(f"Using Qdrant path: {qdrant_path}")
    
    # Initialize agent
    agent = AutonomousAgent(qdrant_path=qdrant_path)
    
    # Run campaign
    report = agent.run(
        target="192.168.171.129",
        objective="Complete security assessment to identify and document all vulnerabilities",
        stealth="high"
    )
    
    print(f"\n✅ Campaign completed: {report['campaign_id']}")
    print(f"📊 Total findings: {report['statistics']['findings_count']}")
    print(f"📁 Report: reports/{report['campaign_id']}_report.json")