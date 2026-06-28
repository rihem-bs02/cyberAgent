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
from rich.syntax import Syntax
from rich.tree import Tree
from rich.live import Live
from rich.layout import Layout
from rich import box

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.llm_client import LLMClient
from tools.tool_registry import execute_tool, get_tool_descriptions

console = Console()

# ============================================================
# CONFIGURATION & CONSTANTS
# ============================================================

MAX_STEPS = 50
MAX_CONTEXT_WINDOW = 8000
MAX_PARSE_FAILURES = 5
MAX_LOOP_DETECTION = 3
OBSERVATION_MAX_LENGTH = 800
RAG_QUERY_LIMIT = 5
DYNAMIC_TOOL_GENERATION_ENABLED = True

# ============================================================
# DATA STRUCTURES
# ============================================================

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class CampaignStatus(Enum):
    RUNNING = "running"
    PAUSED = "paused"
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
    cvss_score: float = 0.0
    evidence: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    related_steps: List[int] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class AttackStep:
    step_number: int
    thought: str
    tool: str
    args: Dict[str, Any]
    observation: str
    success: bool
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    execution_time: float = 0.0
    error: Optional[str] = None
    rag_context: Optional[str] = None
    
    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class CampaignConfig:
    target: str
    objective: str
    stealth_level: str = "high"
    max_steps: int = MAX_STEPS
    enable_auto_exploitation: bool = True
    enable_rag: bool = True
    enable_dynamic_tools: bool = True
    scan_intensity: str = "comprehensive"
    report_format: str = "json"

# ============================================================
# KNOWLEDGE BASE INTEGRATION
# ============================================================

class KnowledgeBase:
    """Enhanced RAG integration with mandatory usage tracking"""
    
    def __init__(self, qdrant_path: str):
        self.qdrant_path = qdrant_path
        self.query_cache = {}
        self.query_history = []
        self.used_contexts = set()
        
    def query(self, context: str, query_type: str = "auto") -> Dict[str, Any]:
        """Mandatory RAG query before any decision making"""
        cache_key = hashlib.md5(f"{context}:{query_type}".encode()).hexdigest()
        
        if cache_key in self.query_cache:
            logger.debug(f"RAG cache hit for: {context[:100]}")
            return self.query_cache[cache_key]
        
        try:
            results = execute_tool("rag_query", {
                "qdrant_path": self.qdrant_path,
                "query": context,
                "top_k": RAG_QUERY_LIMIT,
                "query_type": query_type
            })
            
            parsed_results = json.loads(results) if isinstance(results, str) else results
            
            # Track usage
            self.query_history.append({
                "timestamp": datetime.now().isoformat(),
                "context": context[:200],
                "query_type": query_type,
                "results_count": len(parsed_results.get("results", []))
            })
            
            # Cache results
            self.query_cache[cache_key] = parsed_results
            
            return parsed_results
            
        except Exception as e:
            logger.error(f"RAG query failed: {e}")
            return {"results": [], "error": str(e)}
    
    def get_relevant_techniques(self, finding: str) -> List[Dict]:
        """Get MITRE ATT&CK techniques relevant to a finding"""
        results = self.query(f"MITRE ATT&CK technique for: {finding}", "technique")
        return results.get("results", [])
    
    def get_exploit_suggestions(self, vulnerability: str) -> List[Dict]:
        """Get exploitation suggestions based on vulnerability"""
        results = self.query(f"Exploitation techniques for: {vulnerability}", "exploit")
        return results.get("results", [])
    
    def get_defense_evasion(self, technique: str) -> List[Dict]:
        """Get defense evasion techniques"""
        results = self.query(f"Defense evasion for: {technique}", "evasion")
        return results.get("results", [])

# ============================================================
# DYNAMIC TOOL GENERATOR
# ============================================================

class DynamicToolGenerator:
    """Generates and validates dynamic tools based on RAG knowledge"""
    
    def __init__(self, llm_client: LLMClient, knowledge_base: KnowledgeBase):
        self.llm = llm_client
        self.kb = knowledge_base
        self.generated_tools = {}
        
    def generate_tool(self, requirement: str, context: Dict[str, Any]) -> Optional[Dict]:
        """Dynamically generate a tool based on requirements and RAG knowledge"""
        
        # First, query knowledge base for similar tools/techniques
        kb_results = self.kb.query(f"Tool or command for: {requirement}", "tool_generation")
        
        generation_prompt = f"""Based on the following pentest context and knowledge, generate a tool/command specification:

REQUIREMENT: {requirement}
TARGET: {context.get('target', 'unknown')}
CURRENT FINDINGS: {json.dumps(context.get('findings', []))[:500]}

KNOWLEDGE BASE INSIGHTS:
{json.dumps(kb_results.get('results', [])[:3], indent=2)}

Generate a JSON tool specification with:
1. Tool name (descriptive, lowercase with underscores)
2. Command or script to execute
3. Expected parameters
4. Safety checks
5. Timeout and resource limits
6. Parsing logic for results

Respond ONLY with JSON:
{{"tool_name": "...", "command": "...", "parameters": {{}}, "timeout": 60, "safety_checks": [], "result_parser": "..."}}"""

        try:
            response = self.llm.complete(
                system_prompt="You are an expert penetration testing tool generator. Generate safe, effective tools.",
                user_prompt=generation_prompt,
                max_tokens=500,
                temperature=0.1,
                json_mode=True
            )
            
            tool_spec = json.loads(self._extract_json(response))
            
            # Validate tool specification
            if self._validate_tool_spec(tool_spec):
                self.generated_tools[tool_spec['tool_name']] = tool_spec
                logger.success(f"Generated dynamic tool: {tool_spec['tool_name']}")
                return tool_spec
                
        except Exception as e:
            logger.error(f"Dynamic tool generation failed: {e}")
            
        return None
    
    def _validate_tool_spec(self, spec: Dict) -> bool:
        """Validate generated tool specification for safety and completeness"""
        required_fields = ['tool_name', 'command', 'parameters', 'timeout']
        
        if not all(field in spec for field in required_fields):
            return False
            
        # Safety checks
        dangerous_patterns = ['rm -rf', 'dd if=', 'mkfs', ':(){', 'chmod 777']
        if any(pattern in spec['command'] for pattern in dangerous_patterns):
            logger.warning(f"Generated tool contains dangerous pattern, rejected")
            return False
            
        # Timeout limits
        if spec['timeout'] > 300:  # Max 5 minutes
            spec['timeout'] = 300
            
        return True
    
    def _extract_json(self, text: str) -> str:
        """Extract JSON from text"""
        match = re.search(r'\{.*\}', text, re.DOTALL)
        return match.group() if match else text

# ============================================================
# ENHANCED AUTONOMOUS AGENT
# ============================================================

class AutonomousAgent:
    """Fully autonomous red team agent with mandatory RAG and dynamic capabilities"""
    
    def __init__(self, qdrant_path: str):
        # Core components
        self.kb = KnowledgeBase(qdrant_path)
        self.llm = LLMClient()
        self.tool_generator = DynamicToolGenerator(self.llm, self.kb)
        
        # Campaign state
        self.config: Optional[CampaignConfig] = None
        self.campaign_id = ""
        self.status = CampaignStatus.RUNNING
        self.steps: List[AttackStep] = []
        self.findings: List[Finding] = []
        
        # Tracking
        self.tool_usage = defaultdict(int)
        self.error_count = 0
        self.parse_failures = 0
        self.rag_queries = 0
        
        # Performance
        self.start_time = 0
        self.total_execution_time = 0
        
        # Enhanced logging
        logger.remove()
        logger.add(
            sys.stderr,
            format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
            level="DEBUG"
        )
        logger.add(
            "logs/agent_{time}.log",
            rotation="500 MB",
            retention="10 days",
            level="TRACE"
        )
        
    def run(self, target: str, objective: str = "", stealth: str = "high") -> dict:
        """Main execution method with enhanced logic"""
        
        self.start_time = time.time()
        
        # Initialize campaign
        self.config = CampaignConfig(
            target=target,
            objective=objective or self._generate_objective(target),
            stealth_level=stealth
        )
        self.campaign_id = f"RT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Display enhanced banner
        self._display_banner()
        
        # Phase 1: Pre-engagement Intelligence
        console.print("\n[bold cyan]🔍 Phase 1: Pre-engagement Intelligence[/bold cyan]")
        initial_intel = self._gather_initial_intelligence()
        
        # Phase 2: Vulnerability Discovery
        console.print("\n[bold yellow]🎯 Phase 2: Vulnerability Discovery[/bold yellow]")
        
        # Phase 3: Exploitation (if enabled)
        if self.config.enable_auto_exploitation:
            console.print("\n[bold red]💥 Phase 3: Exploitation[/bold red]")
        
        # Phase 4: Post-Exploitation
        console.print("\n[bold magenta]🔑 Phase 4: Post-Exploitation & Lateral Movement[/bold magenta]")
        
        # Main execution loop
        system_prompt = self._build_enhanced_system_prompt()
        history = self._initialize_history()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Executing attack chain...", total=self.config.max_steps)
            
            for step_num in range(1, self.config.max_steps + 1):
                # Check termination conditions
                if self._should_terminate():
                    break
                
                # Dynamic timeout adjustment based on step
                timeout = self._calculate_timeout(step_num)
                
                try:
                    # MANDATORY RAG query before each decision
                    rag_context = self._mandatory_rag_query(history)
                    self.rag_queries += 1
                    
                    # Build context with RAG insights
                    context = self._build_enhanced_context(history, rag_context)
                    
                    # Get LLM decision
                    raw_response = self.llm.complete(
                        system_prompt=system_prompt,
                        user_prompt=context,
                        max_tokens=600,
                        temperature=0.05,
                        json_mode=True
                    )
                    
                    # Parse and validate response
                    parsed = self._parse_with_validation(raw_response)
                    
                    if not parsed:
                        self._handle_parse_failure(raw_response, history)
                        continue
                    
                    # Extract action
                    thought = parsed.get("thought", "Continuing pentest")
                    tool_name = parsed.get("tool", "")
                    args = parsed.get("args", {})
                    
                    # Validate tool choice
                    if not self._validate_tool_choice(tool_name, args, history):
                        continue
                    
                    # Display step info
                    self._display_step_info(step_num, thought, tool_name, args)
                    
                    # Execute tool
                    execution_start = time.time()
                    
                    if tool_name == "done":
                        self.status = CampaignStatus.COMPLETED
                        break
                    
                    # Check if dynamic tool generation needed
                    if tool_name == "generate_tool":
                        dynamic_tool = self._handle_dynamic_tool_generation(args)
                        if dynamic_tool:
                            observation = execute_tool("run_command", {
                                "command": dynamic_tool['command'],
                                "timeout": dynamic_tool['timeout']
                            })
                        else:
                            observation = "Dynamic tool generation failed"
                    else:
                        # Standard tool execution
                        observation = execute_tool(tool_name, args)
                    
                    execution_time = time.time() - execution_start
                    
                    # Process findings
                    if tool_name == "report_finding":
                        self._process_finding(observation, step_num)
                    
                    # Update tracking
                    self.tool_usage[tool_name] += 1
                    
                    # Record step
                    step = AttackStep(
                        step_number=step_num,
                        thought=thought,
                        tool=tool_name,
                        args=args,
                        observation=observation[:OBSERVATION_MAX_LENGTH],
                        success=self._determine_success(observation),
                        execution_time=execution_time,
                        rag_context=rag_context[:200]
                    )
                    self.steps.append(step)
                    
                    # Update history
                    history = self._update_history(history, raw_response, observation, tool_name)
                    
                    # Dynamic adaptation
                    self._adapt_strategy(step)
                    
                    progress.update(task, advance=1)
                    
                except Exception as e:
                    logger.error(f"Step {step_num} failed: {e}")
                    self.error_count += 1
                    self._handle_error(e, step_num)
        
        # Finalize
        self.total_execution_time = time.time() - self.start_time
        return self._generate_comprehensive_report()
    
    def _generate_objective(self, target: str) -> str:
        """Generate intelligent objective based on target"""
        rag_results = self.kb.query(f"Common penetration testing objectives for: {target}", "planning")
        
        prompt = f"""Generate a comprehensive penetration testing objective for target: {target}
Based on knowledge base insights, create a specific, measurable objective.
Respond with a single concise objective statement."""
        
        try:
            objective = self.llm.complete(
                system_prompt="You are an expert penetration tester creating test objectives.",
                user_prompt=prompt,
                max_tokens=200,
                temperature=0.3
            )
            return objective.strip()
        except:
            return f"Identify and exploit vulnerabilities in {target} to demonstrate impact"
    
    def _gather_initial_intelligence(self) -> Dict:
        """Gather pre-engagement intelligence using RAG"""
        console.print("[dim]Gathering initial intelligence from knowledge base...[/dim]")
        
        intel = {
            "target_profile": self.kb.query(f"Profile of target: {self.config.target}", "recon"),
            "common_vulnerabilities": self.kb.query(f"Common vulnerabilities for: {self.config.target}", "vulnerability"),
            "attack_vectors": self.kb.query(f"Attack vectors for: {self.config.target}", "attack"),
            "defense_mechanisms": self.kb.query(f"Defense mechanisms for: {self.config.target}", "defense")
        }
        
        # Display intel summary
        for category, data in intel.items():
            results_count = len(data.get("results", []))
            console.print(f"  [green]✓[/green] {category.replace('_', ' ').title()}: {results_count} insights found")
        
        return intel
    
    def _mandatory_rag_query(self, history: List[Dict]) -> str:
        """Mandatory RAG query before each decision - cannot be skipped"""
        
        # Build query from recent history
        recent_actions = []
        for msg in history[-5:]:
            if msg["role"] == "user":
                recent_actions.append(msg["content"][:200])
        
        context = " ".join(recent_actions)
        
        # Multiple targeted queries
        queries = [
            f"Next best action based on: {context}",
            f"Common tools for current phase: {context}",
            f"Safety considerations for: {context}"
        ]
        
        all_insights = []
        for query in queries:
            results = self.kb.query(query, "decision_support")
            if results.get("results"):
                all_insights.extend([r.get("text", "")[:200] for r in results["results"]])
        
        return " | ".join(all_insights[:3])  # Top 3 most relevant insights
    
    def _build_enhanced_system_prompt(self) -> str:
        """Build comprehensive system prompt with all capabilities"""
        
        return f"""You are an elite autonomous red team AI agent conducting authorized penetration testing.

CAMPAIGN: {self.campaign_id}
TARGET: {self.config.target}
OBJECTIVE: {self.config.objective}
STEALTH LEVEL: {self.config.stealth_level}
SCAN INTENSITY: {self.config.scan_intensity}

AVAILABLE TOOLS:
{get_tool_descriptions()}

DYNAMIC TOOL GENERATION: Available (use 'generate_tool' when existing tools are insufficient)
RAG KNOWLEDGE BASE: Fully integrated (results automatically included in context)

RESPONSE FORMAT - STRICT JSON ONLY:
{{{{
    "thought": "Detailed reasoning based on RAG insights and current state",
    "tool": "exact_tool_name_or_generate_tool",
    "args": {{{{"param1": "value1", "param2": "value2"}}}},
    "expected_outcome": "What you expect to achieve",
    "fallback_plan": "Alternative if this fails"
}}}}

DECISION FRAMEWORK:
1. ALWAYS consider RAG knowledge base insights first
2. Choose the most appropriate tool for current phase
3. If no existing tool fits, use 'generate_tool' with detailed requirements
4. Prioritize stealth based on stealth level: {self.config.stealth_level}
5. Record all findings immediately with 'report_finding'

ATTACK PHASES:
- Reconnaissance: nmap_port_scan, http_probe, dns_enum, etc.
- Vulnerability Analysis: search_exploits, vuln_scanner, etc.
- Exploitation: run_command with exploits, custom tools
- Post-Exploitation: persistence, lateral_movement, data_exfil
- Reporting: report_finding for all discoveries

Use 'done' ONLY when objective is fully achieved or all possibilities exhausted."""
    
    def _build_enhanced_context(self, history: List[Dict], rag_insights: str) -> str:
        """Build context with mandatory RAG integration"""
        
        context_parts = []
        
        # Add RAG insights prominently
        context_parts.append(f"🔍 KNOWLEDGE BASE INSIGHTS (Must Consider):\n{rag_insights}\n")
        
        # Add campaign progress
        context_parts.append(f"📊 CAMPAIGN PROGRESS:")
        context_parts.append(f"Steps executed: {len(self.steps)}/{self.config.max_steps}")
        context_parts.append(f"Findings discovered: {len(self.findings)}")
        
        if self.findings:
            context_parts.append("Recent findings:")
            for finding in self.findings[-3:]:
                context_parts.append(f"  - {finding.title} ({finding.severity})")
        
        # Add recent history
        context_parts.append(f"\n📜 RECENT ACTIONS:")
        for msg in history[-6:]:
            role = "Agent" if msg["role"] == "assistant" else "Result"
            content = msg["content"][:400]
            context_parts.append(f"{role}: {content}")
        
        # Add current instruction
        context_parts.append(f"\n🎯 YOUR TASK:")
        context_parts.append(f"Based on the knowledge base insights above and current progress,")
        context_parts.append(f"determine the next optimal action. Consider:")
        context_parts.append(f"1. What phase are we in?")
        context_parts.append(f"2. What information is missing?")
        context_parts.append(f"3. What's the highest value target?")
        context_parts.append(f"4. How to maintain stealth level: {self.config.stealth_level}?")
        
        return "\n".join(context_parts)
    
    def _parse_with_validation(self, raw: str) -> Optional[Dict]:
        """Enhanced JSON parsing with multiple fallback strategies"""
        
        if not raw or not raw.strip():
            return None
            
        clean = re.sub(r"```(?:json)?", "", raw).strip().strip("`").strip()
        
        # Strategy 1: Direct parse
        try:
            parsed = json.loads(clean)
            if self._is_valid_action(parsed):
                return parsed
        except:
            pass
        
        # Strategy 2: Extract JSON with tool key
        match = re.search(r'\{[^{}]*"tool"\s*:\s*"[^"]+"[^{}]*\}', clean, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group())
                if self._is_valid_action(parsed):
                    return parsed
            except:
                pass
        
        # Strategy 3: Fix common JSON errors
        try:
            # Fix unquoted keys
            fixed = re.sub(r'([{,])\s*(\w+):', r'\1"\2":', clean)
            # Fix single quotes
            fixed = fixed.replace("'", '"')
            parsed = json.loads(fixed)
            if self._is_valid_action(parsed):
                return parsed
        except:
            pass
        
        # Strategy 4: Extract tool and thought with regex
        tool_match = re.search(r'"tool"\s*:\s*"([a-zA-Z_]+)"', raw)
        thought_match = re.search(r'"thought"\s*:\s*"([^"]{10,})"', raw)
        
        if tool_match:
            return {
                "thought": thought_match.group(1) if thought_match else "Continuing based on analysis",
                "tool": tool_match.group(1),
                "args": self._extract_args(raw)
            }
        
        return None
    
    def _is_valid_action(self, parsed: Dict) -> bool:
        """Validate parsed action"""
        if not isinstance(parsed, dict):
            return False
        if "tool" not in parsed:
            return False
        if parsed["tool"] == "thought" and "thought" not in parsed:
            return False
        return True
    
    def _extract_args(self, raw: str) -> Dict:
        """Extract arguments from malformed JSON"""
        args = {}
        # Find key-value pairs
        pairs = re.findall(r'"(\w+)"\s*:\s*("[^"]*"|\{[^}]*\}|\[[^\]]*\]|\d+|true|false|null)', raw)
        for key, value in pairs:
            try:
                args[key] = json.loads(value)
            except:
                args[key] = value.strip('"')
        return args
    
    def _validate_tool_choice(self, tool_name: str, args: Dict, history: List[Dict]) -> bool:
        """Validate tool choice for safety and logic"""
        
        # Check for placeholder tools
        if self._is_placeholder(tool_name):
            logger.warning(f"Placeholder tool detected: {tool_name}")
            return False
        
        # Check for infinite loops
        tool_key = f"{tool_name}:{json.dumps(args, sort_keys=True)[:100]}"
        if self.tool_usage.get(tool_key, 0) >= MAX_LOOP_DETECTION:
            logger.warning(f"Loop detected for tool: {tool_name}")
            history.append({
                "role": "user",
                "content": f"You've used {tool_name} with same arguments multiple times. MUST try different approach."
            })
            return False
        
        # Validate dangerous commands
        if tool_name == "run_command" and "command" in args:
            if self._is_dangerous_command(args["command"]):
                logger.warning(f"Dangerous command blocked: {args['command']}")
                return False
        
        return True
    
    def _is_dangerous_command(self, command: str) -> bool:
        """Check for dangerous commands"""
        dangerous = [
            "rm -rf /", "dd if=/dev/zero", "mkfs.", "> /dev/sda",
            "chmod 777 /", "wget -O - | sh", "curl | bash"
        ]
        return any(d in command.lower() for d in dangerous)
    
    def _handle_dynamic_tool_generation(self, args: Dict) -> Optional[Dict]:
        """Handle dynamic tool generation request"""
        logger.info("Generating dynamic tool...")
        
        context = {
            "target": self.config.target,
            "findings": [f.to_dict() for f in self.findings],
            "current_step": len(self.steps),
            "stealth": self.config.stealth_level
        }
        
        return self.tool_generator.generate_tool(
            requirement=args.get("requirement", "custom pentest tool"),
            context=context
        )
    
    def _process_finding(self, observation: str, step_num: int):
        """Process and record finding"""
        try:
            result = json.loads(observation) if isinstance(observation, str) else observation
            
            if result.get("recorded"):
                finding_data = result["finding"]
                
                # Enrich with RAG
                enriched = self.kb.get_relevant_techniques(finding_data.get("title", ""))
                if enriched:
                    finding_data["technique_id"] = enriched[0].get("technique_id", "")
                
                # Get exploit suggestions
                exploits = self.kb.get_exploit_suggestions(finding_data.get("title", ""))
                if exploits:
                    finding_data["exploit_suggestions"] = [e.get("text", "") for e in exploits[:3]]
                
                finding = Finding(
                    title=finding_data.get("title", "Untitled"),
                    severity=finding_data.get("severity", "medium"),
                    host=finding_data.get("host", self.config.target),
                    description=finding_data.get("description", ""),
                    technique_id=finding_data.get("technique_id", ""),
                    mitigation=finding_data.get("mitigation", ""),
                    cvss_score=finding_data.get("cvss_score", 0.0),
                    evidence=finding_data.get("evidence", ""),
                    related_steps=[step_num],
                    cve_ids=finding_data.get("cve_ids", [])
                )
                
                self.findings.append(finding)
                
                # Display finding
                self._display_finding(finding)
        except Exception as e:
            logger.error(f"Failed to process finding: {e}")
    
    def _display_finding(self, finding: Finding):
        """Display finding in formatted way"""
        severity_colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "dim",
            "info": "blue"
        }
        
        color = severity_colors.get(finding.severity, "white")
        
        console.print(Panel(
            f"[{color}]🔴 {finding.title}[/{color}]\n"
            f"Severity: [{color}]{finding.severity.upper()}[/{color}]\n"
            f"Host: {finding.host}\n"
            f"Technique: {finding.technique_id}\n"
            f"Description: {finding.description[:200]}\n"
            f"CVSS: {finding.cvss_score}",
            title="[bold red]NEW FINDING[/bold red]",
            border_style=color.split()[-1]
        ))
    
    def _adapt_strategy(self, step: AttackStep):
        """Dynamically adapt strategy based on results"""
        
        # Check if we're stuck
        if len(self.steps) > 5:
            recent_success = sum(1 for s in self.steps[-5:] if s.success)
            if recent_success < 2:
                logger.info("Low success rate detected, adapting strategy...")
                # Could modify stealth level, change attack vectors, etc.
    
    def _should_terminate(self) -> bool:
        """Check termination conditions"""
        if self.status == CampaignStatus.COMPLETED:
            return True
        if self.error_count > 10:
            self.status = CampaignStatus.FAILED
            return True
        if self.parse_failures > MAX_PARSE_FAILURES:
            self.status = CampaignStatus.FAILED
            return True
        return False
    
    def _generate_comprehensive_report(self) -> dict:
        """Generate detailed campaign report"""
        
        # Calculate statistics
        success_rate = sum(1 for s in self.steps if s.success) / max(len(self.steps), 1) * 100
        
        report = {
            "campaign_id": self.campaign_id,
            "status": self.status.value,
            "target": self.config.target,
            "objective": self.config.objective,
            "duration_seconds": self.total_execution_time,
            "statistics": {
                "total_steps": len(self.steps),
                "successful_steps": sum(1 for s in self.steps if s.success),
                "success_rate": f"{success_rate:.1f}%",
                "findings_count": len(self.findings),
                "critical_findings": sum(1 for f in self.findings if f.severity == "critical"),
                "high_findings": sum(1 for f in self.findings if f.severity == "high"),
                "rag_queries": self.rag_queries,
                "tools_used": dict(self.tool_usage),
                "errors": self.error_count
            },
            "findings": [f.to_dict() for f in self.findings],
            "attack_timeline": [
                {
                    "step": s.step_number,
                    "tool": s.tool,
                    "thought": s.thought,
                    "success": s.success,
                    "execution_time": s.execution_time,
                    "timestamp": s.timestamp
                }
                for s in self.steps
            ],
            "recommendations": self._generate_recommendations(),
            "execution_log": "logs/agent_execution.log"
        }
        
        # Save report
        os.makedirs("reports", exist_ok=True)
        report_path = f"reports/{self.campaign_id}_comprehensive_report.json"
        
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        # Display summary
        self._display_final_summary(report)
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []
        
        # Based on findings
        for finding in self.findings:
            if finding.severity in ["critical", "high"]:
                recommendations.append(f"Critical: Address {finding.title} - {finding.mitigation}")
        
        # Based on attack path
        recommendations.append("Review and harden all exposed services")
        recommendations.append("Implement proper input validation")
        recommendations.append("Enable comprehensive logging and monitoring")
        
        return recommendations
    
    def _display_banner(self):
        """Display enhanced banner"""
        console.print(Panel(
            f"[bold red]⚡ AUTONOMOUS RED TEAM AGENT v2.0 ⚡[/bold red]\n\n"
            f"[cyan]Target:[/cyan] {self.config.target}\n"
            f"[yellow]Objective:[/yellow] {self.config.objective[:100]}\n"
            f"[green]Stealth:[/green] {self.config.stealth_level.upper()}\n"
            f"[blue]Campaign ID:[/blue] {self.campaign_id}\n"
            f"[magenta]RAG Integration:[/magenta] MANDATORY\n"
            f"[magenta]Dynamic Tools:[/magenta] {'ENABLED' if self.config.enable_dynamic_tools else 'DISABLED'}\n"
            f"[magenta]Auto Exploitation:[/magenta] {'ENABLED' if self.config.enable_auto_exploitation else 'DISABLED'}\n"
            f"[dim]Max Steps: {self.config.max_steps} | Scan Intensity: {self.config.scan_intensity}[/dim]",
            title="[bold red]🔴 OPERATION INITIATED 🔴[/bold red]",
            border_style="red"
        ))
    
    def _display_step_info(self, step_num: int, thought: str, tool: str, args: Dict):
        """Display step information"""
        console.print(f"\n[dim]━━━ Step {step_num}/{self.config.max_steps} ━━━[/dim]")
        console.print(f"[bold cyan]💭 Thought:[/bold cyan] {thought[:200]}")
        console.print(f"[bold yellow]🔧 Action:[/bold yellow] {tool}")
        if args:
            console.print(f"[dim]Parameters: {json.dumps(args)[:150]}[/dim]")
    
    def _display_final_summary(self, report: dict):
        """Display final summary table"""
        table = Table(
            title=f"🎯 Campaign Summary - {self.campaign_id}",
            box=box.HEAVY,
            show_lines=True
        )
        
        table.add_column("Metric", style="cyan", width=30)
        table.add_column("Value", style="bold", width=50)
        
        stats = report["statistics"]
        
        table.add_row("Status", f"[{self._status_color(self.status)}]{self.status.value.upper()}[/{self._status_color(self.status)}]")
        table.add_row("Duration", f"{report['duration_seconds']:.2f} seconds")
        table.add_row("Total Steps", str(stats["total_steps"]))
        table.add_row("Success Rate", stats["success_rate"])
        table.add_row("Findings", str(stats["findings_count"]))
        table.add_row("Critical Findings", f"[bold red]{stats['critical_findings']}[/bold red]")
        table.add_row("High Findings", f"[red]{stats['high_findings']}[/red]")
        table.add_row("RAG Queries", str(stats["rag_queries"]))
        table.add_row("Report Location", f"reports/{self.campaign_id}_comprehensive_report.json")
        
        console.print("\n")
        console.print(table)
        
        # Display findings tree
        if self.findings:
            tree = Tree("[bold red]🔍 Findings Hierarchy[/bold red]")
            for finding in self.findings:
                severity_icon = {
                    "critical": "🔴", "high": "🟠", 
                    "medium": "🟡", "low": "🟢", "info": "🔵"
                }
                branch = tree.add(f"{severity_icon.get(finding.severity, '⚪')} [{finding.severity.upper()}] {finding.title}")
                branch.add(f"Host: {finding.host}")
                branch.add(f"Technique: {finding.technique_id}")
            console.print(tree)
    
    def _status_color(self, status: CampaignStatus) -> str:
        """Get color for status"""
        colors = {
            CampaignStatus.COMPLETED: "green",
            CampaignStatus.FAILED: "red",
            CampaignStatus.RUNNING: "yellow",
            CampaignStatus.ABORTED: "dim"
        }
        return colors.get(status, "white")
    
    def _initialize_history(self) -> List[Dict]:
        """Initialize conversation history"""
        return [{
            "role": "user",
            "content": f"Begin comprehensive penetration test against {self.config.target}. "
                      f"Objective: {self.config.objective}. "
                      f"Start with thorough reconnaissance based on knowledge base intelligence."
        }]
    
    def _update_history(self, history: List[Dict], response: str, observation: str, tool: str) -> List[Dict]:
        """Update conversation history with smart truncation"""
        history.append({"role": "assistant", "content": response[:500]})
        history.append({
            "role": "user",
            "content": f"Result from {tool}:\n{observation[:OBSERVATION_MAX_LENGTH]}\n\n"
                      f"What is your next action based on this result and knowledge base insights? "
                      f"Respond with JSON only."
        })
        
        # Smart truncation - keep most recent and most important
        if len(history) > 20:
            # Keep first message (context) and last 15 messages
            history = [history[0]] + history[-15:]
        
        return history
    
    def _handle_parse_failure(self, raw: str, history: List[Dict]):
        """Handle JSON parse failures"""
        self.parse_failures += 1
        logger.warning(f"Parse failure {self.parse_failures}/{MAX_PARSE_FAILURES}")
        
        if self.parse_failures >= MAX_PARSE_FAILURES:
            # Reset with explicit instructions
            history.clear()
            history.append({
                "role": "user",
                "content": (
                    f'You MUST respond with valid JSON only. Example:\n'
                    f'{{"thought": "I will scan the target for open ports", '
                    f'"tool": "nmap_port_scan", '
                    f'"args": {{"host": "{self.config.target}", "ports": "1-1000"}}}}\n\n'
                    f'Follow this exact format. Begin reconnaissance.'
                )
            })
            self.parse_failures = 0
    
    def _handle_error(self, error: Exception, step_num: int):
        """Handle execution errors"""
        logger.error(f"Error in step {step_num}: {str(error)}")
        logger.error(traceback.format_exc())
        
        # Could implement recovery strategies here
    
    def _calculate_timeout(self, step_num: int) -> int:
        """Calculate appropriate timeout based on step number"""
        # Longer timeouts for later, more complex steps
        base_timeout = 30
        complexity_factor = min(step_num / 10, 3)  # Max 3x
        return int(base_timeout * complexity_factor)
    
    def _determine_success(self, observation: str) -> bool:
        """Determine if tool execution was successful"""
        if not observation:
            return False
        failure_indicators = ["error", "failed", "timeout", "connection refused", "permission denied"]
        observation_lower = observation.lower()
        return not any(indicator in observation_lower for indicator in failure_indicators)

# ============================================================
# MAIN EXECUTION
# ============================================================

if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    
    # Resolve Qdrant path from environment or check fallback paths
    qdrant_path = os.getenv("QDRANT_PATH")
    if not qdrant_path:
        possible_paths = [
            "./qdrant",
            "../qdrant",
            "/dataset/qdrant",
            "/app/data/qdrant",
            "/app/qdrant_data",
        ]
        for p in possible_paths:
            if os.path.exists(p):
                qdrant_path = p
                break
        else:
            qdrant_path = "./qdrant"

    # Initialize agent with knowledge base path
    agent = AutonomousAgent(qdrant_path=qdrant_path)
    
    # Run campaign
    report = agent.run(
        target="example.com",
        objective="Perform comprehensive penetration test to identify and exploit vulnerabilities",
        stealth="high"
    )
    
    print(f"\nCampaign completed: {report['campaign_id']}")
    print(f"Findings: {report['statistics']['findings_count']}")
    print(f"Report saved: reports/{report['campaign_id']}_comprehensive_report.json")