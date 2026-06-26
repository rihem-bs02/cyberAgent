"""
Letta Cross-Campaign Memory Client
Stores and recalls pentesting knowledge across campaigns using the Letta API.
Falls back to local JSON file if Letta is not running — no crash.

Letta setup (optional):
  pip install letta
  letta server   (starts local server on http://localhost:8283)
  or set LETTA_BASE_URL / LETTA_AGENT_ID in .env

What is stored:
  - Techniques that succeeded on specific target types
  - Credentials that proved reusable across targets
  - Hosts and their vulnerability fingerprints
  - Campaign summaries for cross-engagement pattern analysis
"""
import os
import sys
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional
from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# ── Config ─────────────────────────────────────────────────────────────────────
LETTA_BASE_URL = os.getenv("LETTA_BASE_URL", "http://localhost:8283")
LETTA_AGENT_ID = os.getenv("LETTA_AGENT_ID", "")
LETTA_TOKEN    = os.getenv("LETTA_TOKEN", "")

# Local fallback memory file
MEMORY_DIR  = os.path.join(os.path.dirname(os.path.dirname(__file__)), "memory", "store")
MEMORY_FILE = os.path.join(MEMORY_DIR, "campaign_memory.json")

# ── Letta client availability ──────────────────────────────────────────────────
try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False


class LettaMemory:
    """
    Cross-campaign intelligence store.

    Primary: Letta agent API (if running)
    Fallback: Local JSON file at memory/store/campaign_memory.json

    Stores:
      - succeeded techniques per target type / subnet
      - harvested credentials and whether they reuse across targets
      - vulnerability fingerprints per host
      - full campaign summaries for pattern analysis
    """

    def __init__(self):
        self._letta_ok = False
        self._local: dict = self._load_local()
        self._try_connect_letta()

    def _try_connect_letta(self):
        """Test Letta connectivity."""
        if not _REQUESTS_AVAILABLE:
            logger.info("LettaMemory: requests not available — using local JSON memory")
            return
        try:
            resp = _requests.get(
                f"{LETTA_BASE_URL}/v1/agents",
                headers=self._headers(),
                timeout=3,
            )
            if resp.status_code < 400:
                self._letta_ok = True
                logger.success(f"LettaMemory: connected to Letta at {LETTA_BASE_URL}")
            else:
                logger.info(f"LettaMemory: Letta responded {resp.status_code} — using local fallback")
        except Exception as e:
            logger.info(f"LettaMemory: Letta not available ({type(e).__name__}) — using local fallback")

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if LETTA_TOKEN:
            h["Authorization"] = f"Bearer {LETTA_TOKEN}"
        return h

    @property
    def using_letta(self) -> bool:
        return self._letta_ok

    # ── Local persistence ──────────────────────────────────────────────────────

    def _load_local(self) -> dict:
        """Load local memory store."""
        os.makedirs(MEMORY_DIR, exist_ok=True)
        if os.path.exists(MEMORY_FILE):
            try:
                with open(MEMORY_FILE) as f:
                    data = json.load(f)
                logger.info(f"LettaMemory: loaded {len(data.get('campaigns', []))} campaigns from local store")
                return data
            except Exception as e:
                logger.warning(f"LettaMemory: corrupt local store ({e}) — starting fresh")
        return {
            "campaigns":    [],
            "techniques":   {},   # technique_id → {target_pattern, success_count, fail_count}
            "credentials":  [],   # [{username, password_hash, worked_on: [host_patterns]}]
            "host_profiles":{},   # ip_hash → {os, ports, vulns, last_seen}
        }

    def _save_local(self):
        """Persist local memory to disk."""
        try:
            os.makedirs(MEMORY_DIR, exist_ok=True)
            with open(MEMORY_FILE, "w") as f:
                json.dump(self._local, f, indent=2, default=str)
        except Exception as e:
            logger.warning(f"LettaMemory: failed to save local store: {e}")

    @staticmethod
    def _subnet_key(target: str) -> str:
        """Normalize target to subnet key (e.g. 192.168.1.5/24 → 192.168.1.x)."""
        parts = target.replace("/24", "").split(".")
        if len(parts) >= 3:
            return f"{'.'.join(parts[:3])}.x"
        return target

    # ── Letta API helpers ──────────────────────────────────────────────────────

    def _letta_send_message(self, message: str) -> Optional[str]:
        """Send a message to the Letta agent and return its response."""
        if not self._letta_ok or not LETTA_AGENT_ID:
            return None
        try:
            resp = _requests.post(
                f"{LETTA_BASE_URL}/v1/agents/{LETTA_AGENT_ID}/messages",
                headers=self._headers(),
                json={"messages": [{"role": "user", "content": message}]},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                messages = data.get("messages", [])
                for msg in reversed(messages):
                    if msg.get("role") == "assistant":
                        return msg.get("content", "")
        except Exception as e:
            logger.warning(f"LettaMemory: Letta API error: {e}")
        return None

    def _letta_store(self, key: str, value: dict):
        """Store a key-value pair in Letta agent memory."""
        if not self._letta_ok:
            return
        msg = (
            f"STORE MEMORY — key: {key}\n"
            f"data: {json.dumps(value, default=str)[:1000]}\n"
            "Acknowledge with: stored"
        )
        self._letta_send_message(msg)

    # ── Store campaign results ─────────────────────────────────────────────────

    def store_campaign(self, state) -> bool:
        """
        Persist a completed campaign's intelligence for future recall.
        Called automatically from the orchestrator after reporting.
        """
        campaign_id = state.campaign_id
        target      = state.target_input
        subnet_key  = self._subnet_key(target)

        # Build summary record
        record = {
            "campaign_id":  campaign_id,
            "target":       target,
            "subnet_key":   subnet_key,
            "stored_at":    datetime.now().isoformat(),
            "findings_count":    len(state.findings),
            "credentials_count": len(state.credentials),
            "compromised":       state.compromised_hosts,
            "attck_mapping":     state.attck_mapping,
            "successful_techniques": [
                f.technique_id for f in state.findings
                if f.technique_id
            ],
            "failed_techniques": state.failed_techniques,
        }

        # Update technique success stats
        for tid in record["successful_techniques"]:
            if tid not in self._local["techniques"]:
                self._local["techniques"][tid] = {
                    "success_count":   0,
                    "fail_count":      0,
                    "target_patterns": [],
                }
            self._local["techniques"][tid]["success_count"] += 1
            if subnet_key not in self._local["techniques"][tid]["target_patterns"]:
                self._local["techniques"][tid]["target_patterns"].append(subnet_key)

        for tid in record["failed_techniques"]:
            if tid not in self._local["techniques"]:
                self._local["techniques"][tid] = {
                    "success_count":   0,
                    "fail_count":      0,
                    "target_patterns": [],
                }
            self._local["techniques"][tid]["fail_count"] += 1

        # Store credentials (hashed for safety)
        for cred in state.credentials:
            pw_hash = hashlib.sha256(cred.password.encode()).hexdigest()[:12] if cred.password else ""
            cred_rec = {
                "username":    cred.username,
                "pw_hash":     pw_hash,
                "host_pattern": self._subnet_key(cred.host),
                "source":      cred.source,
                "found_at":    datetime.now().isoformat(),
            }
            # Avoid duplicates
            already_stored = any(
                c["username"] == cred.username and c["pw_hash"] == pw_hash
                for c in self._local["credentials"]
            )
            if not already_stored:
                self._local["credentials"].append(cred_rec)

        # Add campaign summary
        self._local["campaigns"].append(record)
        self._save_local()

        # Also store in Letta if available
        if self.using_letta:
            self._letta_store(f"campaign:{campaign_id}", record)

        logger.success(
            f"LettaMemory: campaign {campaign_id} stored "
            f"({len(record['successful_techniques'])} techniques, "
            f"{len(state.credentials)} creds)"
        )
        return True

    # ── Recall for pre-campaign enrichment ────────────────────────────────────

    def recall_techniques(self, target: str, top_k: int = 5) -> list[dict]:
        """
        Return the most successful techniques for this target subnet.
        Called before a campaign starts to bias the LLM toward known-good approaches.
        """
        subnet_key = self._subnet_key(target)

        if self.using_letta and LETTA_AGENT_ID:
            letta_response = self._letta_send_message(
                f"What pentesting techniques have worked on targets matching {subnet_key}? "
                "List technique IDs and success rates."
            )
            if letta_response:
                logger.info(f"LettaMemory: Letta recall for {subnet_key}: {letta_response[:200]}")

        # Local recall — sort by success_count, filtered by subnet pattern
        relevant = [
            {
                "technique_id":  tid,
                "success_count": data["success_count"],
                "fail_count":    data["fail_count"],
                "success_rate":  data["success_count"] / max(1, data["success_count"] + data["fail_count"]),
                "target_patterns": data["target_patterns"],
            }
            for tid, data in self._local["techniques"].items()
            if data["success_count"] > 0
            and (not data["target_patterns"] or subnet_key in data["target_patterns"])
        ]

        relevant.sort(key=lambda x: x["success_rate"], reverse=True)
        top = relevant[:top_k]

        if top:
            logger.info(f"LettaMemory: recalled {len(top)} techniques for {subnet_key}: {[t['technique_id'] for t in top]}")
        return top

    def recall_credentials(self, target: str) -> list[dict]:
        """
        Recall credentials that worked on similar subnets — useful for password spraying.
        """
        subnet_key = self._subnet_key(target)
        matching = [
            c for c in self._local["credentials"]
            if c.get("host_pattern") == subnet_key or not c.get("host_pattern")
        ]

        if self.using_letta and LETTA_AGENT_ID:
            letta_response = self._letta_send_message(
                f"What credentials have been captured from targets in subnet {subnet_key}? "
                "List usernames and sources."
            )
            if letta_response:
                logger.info(f"LettaMemory: Letta creds for {subnet_key}: {letta_response[:200]}")

        logger.info(f"LettaMemory: {len(matching)} credential records recalled for {subnet_key}")
        return matching

    def get_context_for_phase(self, phase: str, target: str) -> str:
        """
        Build a context string injected into agent prompts.
        Enriches the agent with cross-campaign institutional knowledge.
        """
        techniques = self.recall_techniques(target, top_k=5)
        creds      = self.recall_credentials(target)

        if not techniques and not creds:
            return ""

        lines = [f"[CROSS-CAMPAIGN MEMORY — {phase.upper()} on {target}]"]

        if techniques:
            lines.append("Previously successful techniques:")
            for t in techniques:
                rate = f"{t['success_rate']*100:.0f}%"
                lines.append(f"  - {t['technique_id']} (success rate: {rate}, used {t['success_count']}x)")

        if creds and phase in ("exploitation", "lateral_movement", "privesc"):
            lines.append("Credentials from similar subnets:")
            for c in creds[:5]:
                lines.append(f"  - {c['username']} via {c['source']} on {c['host_pattern']}")

        context = "\n".join(lines)
        logger.info(f"LettaMemory: injecting {len(lines)} memory lines for {phase}")
        return context

    def get_past_campaigns(self, target_pattern: str = "") -> list[dict]:
        """Return list of past campaigns matching an optional target pattern."""
        if not target_pattern:
            return self._local["campaigns"]
        return [
            c for c in self._local["campaigns"]
            if target_pattern in c.get("target", "") or
               target_pattern in c.get("subnet_key", "")
        ]

    def campaign_count(self) -> int:
        return len(self._local["campaigns"])

    def total_techniques(self) -> int:
        return len(self._local["techniques"])

    def status_report(self) -> dict:
        """Quick summary of what's in memory."""
        return {
            "backend":           "letta" if self.using_letta else "local_json",
            "campaigns_stored":  self.campaign_count(),
            "techniques_known":  self.total_techniques(),
            "credentials_stored":len(self._local["credentials"]),
            "memory_file":       MEMORY_FILE if not self.using_letta else "letta",
        }
