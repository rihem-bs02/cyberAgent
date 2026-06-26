"""
Campaign State
Single source of truth shared across all agents throughout the kill chain.
Passed by reference — every agent reads and writes to this object.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from enum import Enum


class CampaignPhase(str, Enum):
    INIT        = "init"
    RECON       = "recon"
    SCANNING    = "scanning"
    EXPLOITATION= "exploitation"
    PRIVESC     = "privesc"
    PERSISTENCE = "persistence"
    LATERAL     = "lateral_movement"
    EXFIL       = "exfiltration"
    REPORTING   = "reporting"
    COMPLETE    = "complete"
    FAILED      = "failed"


class PhaseStatus(str, Enum):
    PENDING  = "pending"
    RUNNING  = "running"
    SUCCESS  = "success"
    FAILED   = "failed"
    PIVOTING = "pivoting"   # blocked, trying alternative


@dataclass
class TargetInfo:
    raw_input:    str                    # original user input
    hosts:        list[str] = field(default_factory=list)
    open_ports:   dict      = field(default_factory=dict)  # host → [ports]
    services:     dict      = field(default_factory=dict)  # host → {port: service}
    os_info:      dict      = field(default_factory=dict)  # host → os
    domain:       str       = ""
    dc_host:      str       = ""        # domain controller if found
    web_endpoints:list[str] = field(default_factory=list)
    ics_devices:  list[str] = field(default_factory=list)  # medical/OT devices


@dataclass
class Finding:
    phase:       str
    title:       str
    description: str
    severity:    str    # critical / high / medium / low
    host:        str
    technique_id:str    # ATT&CK ID
    evidence:    str    = ""
    remediation: str    = ""


@dataclass
class Credential:
    host:     str
    username: str
    password: str = ""
    hash:     str = ""
    source:   str = ""   # mimikatz / spray / etc


@dataclass
class CampaignState:
    # ── Identity ───────────────────────────────────────
    campaign_id:   str      = ""
    target_input:  str      = ""
    objective:     str      = "Full compromise and data exfiltration"
    stealth_level: str      = "high"   # low / medium / high
    started_at:    str      = ""

    # ── Current state ──────────────────────────────────
    current_phase: CampaignPhase   = CampaignPhase.INIT
    phase_status:  PhaseStatus     = PhaseStatus.PENDING

    # ── Target knowledge ───────────────────────────────
    target:        TargetInfo      = field(default_factory=lambda: TargetInfo(""))

    # ── Findings accumulator ───────────────────────────
    findings:      list[Finding]   = field(default_factory=list)
    credentials:   list[Credential]= field(default_factory=list)
    compromised_hosts: list[str]   = field(default_factory=list)

    # ── Agent memory ───────────────────────────────────
    failed_techniques: list[str]   = field(default_factory=list)
    tried_exploits:    list[str]   = field(default_factory=list)
    attack_path:       list[str]   = field(default_factory=list)  # narrative log
    pivot_attempts:    int         = 0
    max_pivots:        int         = 5

    # ── RAG context cache ──────────────────────────────
    rag_context:   dict            = field(default_factory=dict)  # phase → context str

    # ── Output ─────────────────────────────────────────
    report_path:   str             = ""
    attck_mapping: list[str]       = field(default_factory=list)  # [T1059, T1078, ...]

    # ── ReAct trace (phase → list of step narratives) ──
    react_traces:  dict            = field(default_factory=dict)

    def add_finding(self, **kwargs):
        f = Finding(**kwargs)
        self.findings.append(f)
        if f.technique_id and f.technique_id not in self.attck_mapping:
            self.attck_mapping.append(f.technique_id)
        return f

    def add_credential(self, **kwargs):
        c = Credential(**kwargs)
        self.credentials.append(c)
        return c

    def log_step(self, message: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.attack_path.append(f"[{ts}] [{self.current_phase.value}] {message}")

    def advance_phase(self, next_phase: CampaignPhase):
        self.log_step(f"Phase complete → advancing to {next_phase.value}")
        self.current_phase = next_phase
        self.phase_status  = PhaseStatus.PENDING

    def mark_blocked(self, reason: str):
        self.log_step(f"BLOCKED: {reason} — entering pivot mode")
        self.phase_status = PhaseStatus.PIVOTING
        self.pivot_attempts += 1

    def summary(self) -> str:
        return (
            f"Campaign: {self.campaign_id}\n"
            f"Target: {self.target_input}\n"
            f"Phase: {self.current_phase.value} ({self.phase_status.value})\n"
            f"Hosts discovered: {len(self.target.hosts)}\n"
            f"Findings: {len(self.findings)}\n"
            f"Credentials: {len(self.credentials)}\n"
            f"Compromised: {self.compromised_hosts}\n"
            f"ATT&CK techniques: {', '.join(self.attck_mapping)}\n"
        )
