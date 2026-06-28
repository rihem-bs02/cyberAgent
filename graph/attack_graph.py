"""
Attack Graph — Neo4j-backed campaign topology.
Stores hosts, vulnerabilities, findings and lateral movement paths as a graph.
Falls back to in-memory dict if Neo4j is not running — no crash.

Neo4j setup (optional):
  docker run -d -p 7474:7474 -p 7687:7687 --env NEO4J_AUTH=none neo4j:latest
  or set NEO4J_URI / NEO4J_USER / NEO4J_PASS in .env
"""
import os
import sys
import json
from datetime import datetime
from typing import Optional
from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# ── Neo4j connection ───────────────────────────────────────────────────────────
NEO4J_URI  = os.getenv("NEO4J_URI",  "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASSWORD") or os.getenv("NEO4J_PASS") or "password"

try:
    from neo4j import GraphDatabase
    _NEO4J_AVAILABLE = True
except ImportError:
    _NEO4J_AVAILABLE = False
    logger.warning("neo4j driver not installed — using in-memory graph fallback. "
                   "Install with: pip install neo4j")


class AttackGraph:
    """
    Attack graph — stores the full campaign topology.

    When Neo4j is available, data persists across sessions.
    When not available, uses in-memory dicts (data lives for this run only).

    Node types:
        (:Host)        — network host
        (:Service)     — service on a port
        (:Vulnerability) — CVE / finding
        (:Credential)  — harvested credential
        (:Campaign)    — campaign metadata

    Edge types:
        HAS_SERVICE, HAS_VULNERABILITY, EXPLOITED_VIA,
        LATERAL_TO, PROVIDES_CRED, FOUND_IN
    """

    def __init__(self):
        self._driver = None
        self._mem: dict = {
            "campaigns":      {},
            "hosts":          {},
            "services":       {},
            "vulnerabilities":[],
            "credentials":    [],
            "edges":          [],
        }
        self._connect()

    def _connect(self):
        """Try to connect to Neo4j. Silently fall back on failure."""
        if not _NEO4J_AVAILABLE:
            logger.info("AttackGraph: running in-memory (no neo4j driver)")
            return
        try:
            self._driver = GraphDatabase.driver(
                NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS)
            )
            # Test connection
            with self._driver.session() as s:
                s.run("RETURN 1")
            logger.success(f"AttackGraph: connected to Neo4j at {NEO4J_URI}")
            self._ensure_constraints()
        except Exception as e:
            logger.warning(f"AttackGraph: Neo4j unavailable ({e}) — using in-memory fallback")
            self._driver = None

    @property
    def using_neo4j(self) -> bool:
        return self._driver is not None

    def _run(self, cypher: str, **params) -> list:
        """Execute Cypher query, return list of records."""
        if not self.using_neo4j:
            return []
        try:
            with self._driver.session() as s:
                result = s.run(cypher, **params)
                return [dict(r) for r in result]
        except Exception as e:
            logger.warning(f"AttackGraph Cypher error: {e}")
            return []

    def _ensure_constraints(self):
        """Create uniqueness constraints."""
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (c:Campaign) REQUIRE c.campaign_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.uid IS UNIQUE",
        ]
        for cypher in constraints:
            try:
                self._run(cypher)
            except Exception:
                pass

    # ── Campaign ───────────────────────────────────────────────────────────────

    def init_campaign(self, campaign_id: str, target: str, objective: str):
        """Create campaign node."""
        self._mem["campaigns"][campaign_id] = {
            "campaign_id": campaign_id,
            "target":      target,
            "objective":   objective,
            "started_at":  datetime.now().isoformat(),
        }
        self._run(
            """MERGE (c:Campaign {campaign_id: $cid})
               SET c.target=$target, c.objective=$objective, c.started_at=$ts""",
            cid=campaign_id, target=target, objective=objective,
            ts=datetime.now().isoformat(),
        )
        logger.info(f"AttackGraph: campaign {campaign_id} initialized")

    # ── Hosts ─────────────────────────────────────────────────────────────────

    def add_host(
        self,
        campaign_id: str,
        ip:          str,
        hostname:    str   = "",
        os_name:     str   = "",
        ports:       list  = None,
        status:      str   = "discovered",
    ):
        """Add or update a host node."""
        ports = ports or []
        self._mem["hosts"][ip] = {
            "ip": ip, "hostname": hostname,
            "os": os_name, "ports": ports, "status": status,
        }
        self._run(
            """MERGE (h:Host {ip: $ip})
               SET h.hostname=$hostname, h.os=$os, h.ports=$ports, h.status=$status
               WITH h
               MATCH (c:Campaign {campaign_id: $cid})
               MERGE (c)-[:INCLUDES]->(h)""",
            ip=ip, hostname=hostname, os=os_name,
            ports=json.dumps(ports), status=status, cid=campaign_id,
        )
        logger.debug(f"AttackGraph: host {ip} added/updated")

    def mark_compromised(self, ip: str, method: str = ""):
        """Mark a host as compromised."""
        if ip in self._mem["hosts"]:
            self._mem["hosts"][ip]["status"] = "compromised"
        self._run(
            "MATCH (h:Host {ip:$ip}) SET h.status='compromised', h.compromise_method=$method",
            ip=ip, method=method,
        )

    # ── Services ──────────────────────────────────────────────────────────────

    def add_service(
        self,
        host_ip: str,
        port:    int,
        service: str,
        version: str = "",
        product: str = "",
    ):
        """Add a service found on a host."""
        uid = f"{host_ip}:{port}"
        self._mem["services"][uid] = {
            "host": host_ip, "port": port,
            "service": service, "version": version, "product": product,
        }
        self._run(
            """MERGE (s:Service {uid: $uid})
               SET s.port=$port, s.service=$service, s.version=$version, s.product=$product
               WITH s
               MATCH (h:Host {ip: $ip})
               MERGE (h)-[:HAS_SERVICE]->(s)""",
            uid=uid, port=port, service=service,
            version=version, product=product, ip=host_ip,
        )

    # ── Vulnerabilities / Findings ────────────────────────────────────────────

    def add_vulnerability(
        self,
        campaign_id:  str,
        host_ip:      str,
        title:        str,
        technique_id: str,
        severity:     str,
        cve_id:       str   = "",
        evidence:     str   = "",
        phase:        str   = "",
    ):
        """Add a vulnerability / finding node."""
        uid = f"{host_ip}-{technique_id}-{title[:30]}"
        vuln = {
            "uid": uid, "campaign_id": campaign_id, "host": host_ip,
            "title": title, "technique_id": technique_id, "severity": severity,
            "cve_id": cve_id, "evidence": evidence[:500], "phase": phase,
        }
        self._mem["vulnerabilities"].append(vuln)
        self._run(
            """MERGE (v:Vulnerability {uid: $uid})
               SET v.title=$title, v.technique_id=$tid, v.severity=$sev,
                   v.cve_id=$cve, v.evidence=$evidence, v.phase=$phase
               WITH v
               MATCH (h:Host {ip: $ip})
               MERGE (h)-[:HAS_VULNERABILITY]->(v)
               WITH v
               MATCH (c:Campaign {campaign_id: $cid})
               MERGE (c)-[:FOUND_IN]->(v)""",
            uid=uid, title=title, tid=technique_id, sev=severity,
            cve=cve_id, evidence=evidence[:500], phase=phase,
            ip=host_ip, cid=campaign_id,
        )
        logger.debug(f"AttackGraph: vulnerability '{title}' on {host_ip}")

    # ── Credentials ───────────────────────────────────────────────────────────

    def add_credential(
        self,
        host_ip:  str,
        username: str,
        password: str = "",
        hash_val: str = "",
        source:   str = "",
    ):
        """Add harvested credential node."""
        cred = {
            "host": host_ip, "username": username,
            "password": password, "hash": hash_val, "source": source,
        }
        self._mem["credentials"].append(cred)
        uid = f"{username}@{host_ip}"
        self._run(
            """MERGE (cr:Credential {uid: $uid})
               SET cr.username=$user, cr.password=$pw, cr.hash=$hash, cr.source=$src
               WITH cr
               MATCH (h:Host {ip: $ip})
               MERGE (h)-[:PROVIDES_CRED]->(cr)""",
            uid=uid, user=username, pw=password,
            hash=hash_val, src=source, ip=host_ip,
        )

    # ── Lateral movement edges ─────────────────────────────────────────────────

    def add_lateral_edge(
        self,
        src_ip:     str,
        dst_ip:     str,
        technique:  str = "",
        credential: str = "",
    ):
        """Record lateral movement from src_ip to dst_ip."""
        self._mem["edges"].append({
            "type": "lateral", "src": src_ip, "dst": dst_ip,
            "technique": technique, "credential": credential,
        })
        self._run(
            """MATCH (a:Host {ip:$src}), (b:Host {ip:$dst})
               MERGE (a)-[r:LATERAL_TO {technique:$tech}]->(b)
               SET r.credential=$cred""",
            src=src_ip, dst=dst_ip, tech=technique, cred=credential,
        )

    # ── Query ─────────────────────────────────────────────────────────────────

    def get_attack_path(self, campaign_id: str) -> list[dict]:
        """Return full attack path as ordered list of nodes."""
        if self.using_neo4j:
            return self._run(
                """MATCH (c:Campaign {campaign_id:$cid})-[:INCLUDES]->(h:Host)
                   OPTIONAL MATCH (h)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                   OPTIONAL MATCH (h)-[:LATERAL_TO]->(next:Host)
                   RETURN h.ip AS host, h.status AS status,
                          collect(DISTINCT v.technique_id) AS techniques,
                          collect(DISTINCT next.ip) AS lateral_to
                   ORDER BY h.status DESC""",
                cid=campaign_id,
            )
        # In-memory fallback
        return [
            {
                "host":       ip,
                "status":     info.get("status", ""),
                "techniques": [
                    v["technique_id"] for v in self._mem["vulnerabilities"]
                    if v["host"] == ip
                ],
                "ports": info.get("ports", []),
            }
            for ip, info in self._mem["hosts"].items()
        ]

    def get_summary(self, campaign_id: str) -> dict:
        """High-level graph summary for the final report."""
        if self.using_neo4j:
            rows = self._run(
                """MATCH (c:Campaign {campaign_id:$cid})
                   OPTIONAL MATCH (c)-[:INCLUDES]->(h:Host)
                   OPTIONAL MATCH (c)-[:FOUND_IN]->(v:Vulnerability)
                   RETURN
                     count(DISTINCT h) AS total_hosts,
                     count(DISTINCT CASE WHEN h.status='compromised' THEN h END) AS compromised,
                     count(DISTINCT v) AS total_vulns,
                     count(DISTINCT CASE WHEN v.severity='critical' THEN v END) AS critical_vulns""",
                cid=campaign_id,
            )
            return rows[0] if rows else {}

        return {
            "total_hosts":     len(self._mem["hosts"]),
            "compromised":     sum(1 for h in self._mem["hosts"].values() if h.get("status") == "compromised"),
            "total_vulns":     len(self._mem["vulnerabilities"]),
            "critical_vulns":  sum(1 for v in self._mem["vulnerabilities"] if v.get("severity") == "critical"),
            "credentials":     len(self._mem["credentials"]),
        }

    def export_graphml(self, output_path: str, campaign_id: str):
        """Export attack graph as GraphML for visualization in Gephi / yEd."""
        hosts = self._mem["hosts"]
        edges = self._mem["edges"]
        vulns = self._mem["vulnerabilities"]

        lines = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<graphml xmlns="http://graphml.graphdrawing.org/graphml">',
                 '<graph id="G" edgedefault="directed">']

        # Nodes
        for ip, info in hosts.items():
            color = "#ff4444" if info.get("status") == "compromised" else "#44aaff"
            lines.append(
                f'<node id="{ip}"><data key="label">{ip}</data>'
                f'<data key="color">{color}</data></node>'
            )

        # Edges
        for i, edge in enumerate(edges):
            lines.append(
                f'<edge id="e{i}" source="{edge["src"]}" target="{edge["dst"]}">'
                f'<data key="label">{edge.get("technique","")}</data></edge>'
            )

        lines += ["</graph>", "</graphml>"]

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            f.write("\n".join(lines))
        logger.success(f"AttackGraph: exported GraphML to {output_path}")

    def sync_from_state(self, campaign_id: str, state):
        """
        Populate the attack graph from a completed CampaignState.
        Call this after each phase completes.
        """
        # Sync hosts
        for host_ip in state.target.hosts:
            ports = state.target.open_ports.get(host_ip, [])
            os_info = state.target.os_info.get(host_ip, {})
            status = "compromised" if host_ip in state.compromised_hosts else "discovered"
            self.add_host(
                campaign_id=campaign_id,
                ip=host_ip,
                os_name=os_info.get("os", ""),
                ports=ports,
                status=status,
            )
            # Sync services
            svcs = state.target.services.get(host_ip, {})
            for port, svc in svcs.items():
                svc_name = svc if isinstance(svc, str) else svc.get("service", "")
                self.add_service(host_ip, int(port), svc_name)

        # Sync findings
        for finding in state.findings:
            self.add_vulnerability(
                campaign_id  = campaign_id,
                host_ip      = finding.host or state.target_input,
                title        = finding.title,
                technique_id = finding.technique_id,
                severity     = finding.severity,
                evidence     = finding.evidence,
                phase        = finding.phase,
            )

        # Sync credentials
        for cred in state.credentials:
            self.add_credential(
                host_ip  = cred.host,
                username = cred.username,
                password = cred.password,
                hash_val = cred.hash,
                source   = cred.source,
            )

    def close(self):
        if self._driver:
            try:
                self._driver.close()
            except Exception:
                pass
