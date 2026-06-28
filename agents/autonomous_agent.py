import json
import os
import sys
import re
import time
import hashlib
import traceback
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict

from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.tree import Tree
from rich.syntax import Syntax
from rich import box

# Neo4j imports
try:
    from neo4j import GraphDatabase, basic_auth
    from neo4j.exceptions import ServiceUnavailable, AuthError
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    logger.warning("Neo4j driver not installed. Install with: pip install neo4j")

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
RAG_QUERY_LIMIT = 3  # Reduced to prevent overhead

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

class NodeType(Enum):
    HOST = "Host"
    PORT = "Port"
    SERVICE = "Service"
    VULNERABILITY = "Vulnerability"
    FINDING = "Finding"
    EXPLOIT = "Exploit"
    CREDENTIAL = "Credential"
    ATTACK_PATH = "AttackPath"
    TOOL = "Tool"

class RelationshipType(Enum):
    HAS_PORT = "HAS_PORT"
    RUNS_SERVICE = "RUNS_SERVICE"
    HAS_VULNERABILITY = "HAS_VULNERABILITY"
    EXPLOITS = "EXPLOITS"
    COMPROMISES = "COMPROMISES"
    LEADS_TO = "LEADS_TO"
    USES_TOOL = "USES_TOOL"
    DISCOVERED = "DISCOVERED"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"

@dataclass
class Finding:
    id: str = field(default_factory=lambda: f"FIND-{datetime.now().strftime('%Y%m%d%H%M%S')}")
    title: str = ""
    severity: str = "medium"
    host: str = ""
    port: int = 0
    service: str = ""
    description: str = ""
    technique_id: str = ""
    mitigation: str = ""
    cvss_score: float = 0.0
    evidence: str = ""
    cve_ids: List[str] = field(default_factory=list)
    affected_hosts: List[str] = field(default_factory=list)
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
    target_host: str = ""
    target_port: int = 0
    execution_time: float = 0.0
    rag_context: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    relationships_created: List[Tuple[str, str, str]] = field(default_factory=list)

@dataclass
class HostNode:
    ip: str
    hostname: str = ""
    os: str = ""
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    is_compromised: bool = False
    compromise_method: str = ""
    credentials_found: List[str] = field(default_factory=list)
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())

# ============================================================
# NEO4J GRAPH DATABASE INTEGRATION
# ============================================================

class AttackGraphDB:
    """Neo4j graph database for attack path visualization and relationship mapping"""
    
    def __init__(self, uri: str = None, user: str = None, password: str = None):
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = user or os.getenv("NEO4J_USER", "neo4j")
        self.password = password or os.getenv("NEO4J_PASS", "password")
        self.driver = None
        self.connected = False
        self.nodes_created = 0
        self.relationships_created = 0
        
        if NEO4J_AVAILABLE:
            self._connect()
        else:
            logger.warning("Neo4j not available. Graph features disabled.")
    
    def _connect(self):
        """Establish Neo4j connection"""
        try:
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
                max_connection_lifetime=3600,
                max_connection_pool_size=10,
                connection_acquisition_timeout=30
            )
            self.driver.verify_connectivity()
            self.connected = True
            logger.success(f"✅ Connected to Neo4j graph database at {self.uri}")
            self._create_constraints()
            self._create_indexes()
        except ServiceUnavailable:
            logger.warning(f"⚠️ Neo4j server not available at {self.uri}. Running without graph.")
            self.connected = False
        except AuthError:
            logger.warning(f"⚠️ Neo4j authentication failed. Check credentials.")
            self.connected = False
        except Exception as e:
            logger.warning(f"⚠️ Neo4j connection failed: {e}")
            self.connected = False
    
    def _create_constraints(self):
        """Create uniqueness constraints"""
        if not self.connected:
            return
        
        constraints = [
            "CREATE CONSTRAINT host_ip_unique IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE",
            "CREATE CONSTRAINT port_unique IF NOT EXISTS FOR (p:Port) REQUIRE (p.number, p.protocol) IS NODE KEY",
            "CREATE CONSTRAINT vulnerability_unique IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
            "CREATE CONSTRAINT finding_unique IF NOT EXISTS FOR (f:Finding) REQUIRE f.id IS UNIQUE",
            "CREATE CONSTRAINT tool_unique IF NOT EXISTS FOR (t:Tool) REQUIRE t.name IS UNIQUE",
            "CREATE CONSTRAINT exploit_unique IF NOT EXISTS FOR (e:Exploit) REQUIRE e.id IS UNIQUE",
        ]
        
        with self.driver.session() as session:
            for constraint in constraints:
                try:
                    session.run(constraint)
                except Exception as e:
                    logger.debug(f"Constraint creation note: {e}")
    
    def _create_indexes(self):
        """Create performance indexes"""
        if not self.connected:
            return
        
        indexes = [
            "CREATE INDEX host_os IF NOT EXISTS FOR (h:Host) ON (h.os)",
            "CREATE INDEX vulnerability_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)",
            "CREATE INDEX finding_severity IF NOT EXISTS FOR (f:Finding) ON (f.severity)",
            "CREATE INDEX service_name IF NOT EXISTS FOR (s:Service) ON (s.name)",
        ]
        
        with self.driver.session() as session:
            for index in indexes:
                try:
                    session.run(index)
                except Exception as e:
                    logger.debug(f"Index creation note: {e}")
    
    def add_host(self, ip: str, hostname: str = "", os_type: str = "", is_target: bool = False) -> bool:
        """Add or update host node"""
        if not self.connected:
            return False
        
        try:
            with self.driver.session() as session:
                session.run("""
                    MERGE (h:Host {ip: $ip})
                    SET h.hostname = $hostname,
                        h.os = $os_type,
                        h.is_target = $is_target,
                        h.last_seen = datetime(),
                        h.updated_at = datetime()
                    RETURN h
                """, ip=ip, hostname=hostname, os_type=os_type, is_target=is_target)
                self.nodes_created += 1
                return True
        except Exception as e:
            logger.error(f"Failed to add host {ip}: {e}")
            return False
    
    def add_port(self, host_ip: str, port: int, protocol: str = "tcp", service: str = "", 
                 version: str = "", state: str = "open") -> bool:
        """Add port to host"""
        if not self.connected:
            return False
        
        try:
            with self.driver.session() as session:
                session.run("""
                    MATCH (h:Host {ip: $host_ip})
                    MERGE (p:Port {number: $port, protocol: $protocol})
                    SET p.service = $service,
                        p.version = $version,
                        p.state = $state,
                        p.discovered_at = datetime()
                    MERGE (h)-[r:HAS_PORT]->(p)
                    SET r.discovered_at = datetime()
                    RETURN h, p
                """, host_ip=host_ip, port=port, protocol=protocol, 
                     service=service, version=version, state=state)
                self.relationships_created += 1
                return True
        except Exception as e:
            logger.error(f"Failed to add port {port} to {host_ip}: {e}")
            return False
    
    def add_service(self, host_ip: str, port: int, service_name: str, version: str = "",
                    banner: str = "") -> bool:
        """Add service node and connect to host"""
        if not self.connected:
            return False
        
        try:
            with self.driver.session() as session:
                session.run("""
                    MATCH (h:Host {ip: $host_ip})
                    MATCH (p:Port {number: $port})
                    MERGE (s:Service {name: $service_name, host: $host_ip, port: $port})
                    SET s.version = $version,
                        s.banner = $banner,
                        s.discovered_at = datetime()
                    MERGE (h)-[r1:RUNS_SERVICE]->(s)
                    MERGE (p)-[r2:EXPOSES_SERVICE]->(s)
                    SET r1.discovered_at = datetime(),
                        r2.discovered_at = datetime()
                """, host_ip=host_ip, port=port, service_name=service_name,
                     version=version, banner=banner)
                self.relationships_created += 2
                return True
        except Exception as e:
            logger.error(f"Failed to add service {service_name}: {e}")
            return False
    
    def add_vulnerability(self, host_ip: str, vuln_id: str, name: str, severity: str,
                          description: str = "", cve_id: str = "", cvss_score: float = 0.0,
                          port: int = 0, service: str = "") -> bool:
        """Add vulnerability and connect to host/service"""
        if not self.connected:
            return False
        
        try:
            with self.driver.session() as session:
                # Create vulnerability node
                session.run("""
                    MATCH (h:Host {ip: $host_ip})
                    MERGE (v:Vulnerability {id: $vuln_id})
                    SET v.name = $name,
                        v.severity = $severity,
                        v.description = $description,
                        v.cve_id = $cve_id,
                        v.cvss_score = $cvss_score,
                        v.discovered_at = datetime()
                    MERGE (h)-[r:HAS_VULNERABILITY]->(v)
                    SET r.discovered_at = datetime()
                """, host_ip=host_ip, vuln_id=vuln_id, name=name,
                     severity=severity, description=description,
                     cve_id=cve_id, cvss_score=cvss_score)
                
                # Connect to service if applicable
                if service:
                    session.run("""
                        MATCH (v:Vulnerability {id: $vuln_id})
                        MATCH (s:Service {name: $service, host: $host_ip})
                        MERGE (v)-[r:AFFECTS_SERVICE]->(s)
                        SET r.discovered_at = datetime()
                    """, vuln_id=vuln_id, service=service, host_ip=host_ip)
                
                self.nodes_created += 1
                self.relationships_created += 1
                return True
        except Exception as e:
            logger.error(f"Failed to add vulnerability {vuln_id}: {e}")
            return False
    
    def add_finding(self, finding: Finding) -> bool:
        """Add finding and create relationships"""
        if not self.connected:
            return False
        
        try:
            with self.driver.session() as session:
                session.run("""
                    CREATE (f:Finding {
                        id: $id,
                        title: $title,
                        severity: $severity,
                        description: $description,
                        technique_id: $technique_id,
                        cvss_score: $cvss_score,
                        timestamp: datetime($timestamp),
                        evidence: $evidence
                    })
                    WITH f
                    MATCH (h:Host {ip: $host})
                    MERGE (f)-[r1:DISCOVERED_ON]->(h)
                    SET r1.timestamp = datetime()
                """, id=finding.id, title=finding.title, severity=finding.severity,
                     description=finding.description, technique_id=finding.technique_id,
                     cvss_score=finding.cvss_score, timestamp=finding.timestamp,
                     evidence=finding.evidence[:1000], host=finding.host)
                
                # Connect to vulnerabilities
                if finding.cve_ids:
                    for cve in finding.cve_ids:
                        session.run("""
                            MATCH (f:Finding {id: $finding_id})
                            MATCH (v:Vulnerability {cve_id: $cve})
                            MERGE (f)-[r:REFERENCES]->(v)
                        """, finding_id=finding.id, cve=cve)
                
                self.nodes_created += 1
                return True
        except Exception as e:
            logger.error(f"Failed to add finding {finding.id}: {e}")
            return False
    
    def add_attack_path(self, from_host: str, to_host: str, technique: str, 
                        tool: str, success: bool = False) -> bool:
        """Create attack path/compromise relationship"""
        if not self.connected:
            return False
        
        try:
            with self.driver.session() as session:
                session.run("""
                    MATCH (h1:Host {ip: $from_host})
                    MATCH (h2:Host {ip: $to_host})
                    MERGE (h1)-[r:COMPROMISES]->(h2)
                    SET r.technique = $technique,
                        r.tool = $tool,
                        r.success = $success,
                        r.timestamp = datetime()
                    RETURN h1, h2, r
                """, from_host=from_host, to_host=to_host,
                     technique=technique, tool=tool, success=success)
                
                # Update target host as compromised
                if success:
                    session.run("""
                        MATCH (h:Host {ip: $to_host})
                        SET h.is_compromised = true,
                            h.compromised_at = datetime()
                    """, to_host=to_host)
                
                self.relationships_created += 1
                return True
        except Exception as e:
            logger.error(f"Failed to add attack path: {e}")
            return False
    
    def add_credential(self, host_ip: str, username: str, password_hash: str = "",
                       credential_type: str = "discovered") -> bool:
        """Add discovered credentials"""
        if not self.connected:
            return False
        
        try:
            with self.driver.session() as session:
                session.run("""
                    MATCH (h:Host {ip: $host_ip})
                    MERGE (c:Credential {username: $username, host: $host_ip})
                    SET c.password_hash = $password_hash,
                        c.type = $credential_type,
                        c.discovered_at = datetime()
                    MERGE (h)-[r:HAS_CREDENTIAL]->(c)
                    SET r.discovered_at = datetime()
                """, host_ip=host_ip, username=username,
                     password_hash=password_hash, credential_type=credential_type)
                
                self.nodes_created += 1
                self.relationships_created += 1
                return True
        except Exception as e:
            logger.error(f"Failed to add credential: {e}")
            return False
    
    def add_tool_execution(self, tool_name: str, target: str, args: Dict, 
                          success: bool, execution_time: float) -> bool:
        """Record tool execution"""
        if not self.connected:
            return False
        
        try:
            with self.driver.session() as session:
                session.run("""
                    MERGE (t:Tool {name: $tool_name})
                    CREATE (e:Execution {
                        id: randomUUID(),
                        target: $target,
                        args: $args,
                        success: $success,
                        execution_time: $execution_time,
                        timestamp: datetime()
                    })
                    MERGE (t)-[r:EXECUTED]->(e)
                    SET r.timestamp = datetime()
                """, tool_name=tool_name, target=target,
                     args=json.dumps(args)[:500], success=success,
                     execution_time=execution_time)
                return True
        except Exception as e:
            logger.error(f"Failed to record tool execution: {e}")
            return False
    
    def get_attack_paths(self, target_ip: str, max_depth: int = 5) -> List[Dict]:
        """Get all attack paths to target"""
        if not self.connected:
            return []
        
        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH path = (start:Host)-[:COMPROMISES*1..%d]->(target:Host {ip: $ip})
                    WHERE start.is_target = false OR start.ip <> $ip
                    RETURN path, length(path) as depth
                    ORDER BY depth
                    LIMIT 20
                """ % max_depth, ip=target_ip)
                
                paths = []
                for record in result:
                    path_data = {
                        "depth": record["depth"],
                        "nodes": [],
                        "relationships": []
                    }
                    
                    for node in record["path"].nodes:
                        path_data["nodes"].append(dict(node))
                    
                    for rel in record["path"].relationships:
                        path_data["relationships"].append({
                            "type": rel.type,
                            "properties": dict(rel)
                        })
                    
                    paths.append(path_data)
                
                return paths
        except Exception as e:
            logger.error(f"Failed to get attack paths: {e}")
            return []
    
    def get_all_vulnerabilities(self, min_severity: str = "medium") -> List[Dict]:
        """Get all vulnerabilities with minimum severity"""
        if not self.connected:
            return []
        
        severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        min_level = severity_order.get(min_severity, 0)
        
        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (v:Vulnerability)
                    WHERE v.severity IN ['critical', 'high', 'medium', 'low']
                    RETURN v, 
                           CASE v.severity
                               WHEN 'critical' THEN 4
                               WHEN 'high' THEN 3
                               WHEN 'medium' THEN 2
                               WHEN 'low' THEN 1
                               ELSE 0
                           END as severity_level
                    ORDER BY severity_level DESC
                """)
                
                return [dict(record["v"]) for record in result 
                       if record["severity_level"] >= min_level]
        except Exception as e:
            logger.error(f"Failed to get vulnerabilities: {e}")
            return []
    
    def get_host_summary(self, host_ip: str) -> Dict:
        """Get comprehensive host information from graph"""
        if not self.connected:
            return {}
        
        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (h:Host {ip: $ip})
                    OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
                    OPTIONAL MATCH (h)-[:RUNS_SERVICE]->(s:Service)
                    OPTIONAL MATCH (h)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                    OPTIONAL MATCH (h)-[:HAS_CREDENTIAL]->(c:Credential)
                    OPTIONAL MATCH (attacker)-[:COMPROMISES]->(h)
                    RETURN h,
                           collect(DISTINCT p) as ports,
                           collect(DISTINCT s) as services,
                           collect(DISTINCT v) as vulnerabilities,
                           collect(DISTINCT c) as credentials,
                           collect(DISTINCT attacker.ip) as attackers
                """, ip=host_ip)
                
                record = result.single()
                if record:
                    return {
                        "host": dict(record["h"]),
                        "ports": [dict(p) for p in record["ports"]],
                        "services": [dict(s) for s in record["services"]],
                        "vulnerabilities": [dict(v) for v in record["vulnerabilities"]],
                        "credentials": [dict(c) for c in record["credentials"]],
                        "attackers": record["attackers"]
                    }
                return {}
        except Exception as e:
            logger.error(f"Failed to get host summary: {e}")
            return {}
    
    def export_graph_for_visualization(self) -> Dict:
        """Export entire graph for D3.js or Neo4j Browser visualization"""
        if not self.connected:
            return {"nodes": [], "links": [], "error": "Not connected"}
        
        try:
            with self.driver.session() as session:
                # Get all nodes with their labels and properties
                nodes_result = session.run("""
                    MATCH (n)
                    OPTIONAL MATCH (n)-[r]-()
                    RETURN DISTINCT n, labels(n) as labels, 
                           collect(DISTINCT type(r)) as relationship_types
                """)
                
                nodes = []
                node_ids = set()
                
                for record in nodes_result:
                    node = dict(record["n"])
                    node_id = node.get("ip") or node.get("id") or node.get("name") or str(hash(str(node)))
                    
                    if node_id not in node_ids:
                        node_ids.add(node_id)
                        nodes.append({
                            "id": node_id,
                            "labels": record["labels"],
                            "properties": node,
                            "relationship_types": record["relationship_types"]
                        })
                
                # Get all relationships
                links_result = session.run("""
                    MATCH (n)-[r]->(m)
                    RETURN n, r, m, type(r) as rel_type,
                           labels(n) as from_labels,
                           labels(m) as to_labels
                """)
                
                links = []
                for record in links_result:
                    from_node = dict(record["n"])
                    to_node = dict(record["m"])
                    from_id = from_node.get("ip") or from_node.get("id") or from_node.get("name")
                    to_id = to_node.get("ip") or to_node.get("id") or to_node.get("name")
                    
                    if from_id and to_id:
                        links.append({
                            "source": from_id,
                            "target": to_id,
                            "type": record["rel_type"],
                            "properties": dict(record["r"]),
                            "from_labels": record["from_labels"],
                            "to_labels": record["to_labels"]
                        })
                
                return {
                    "nodes": nodes,
                    "links": links,
                    "statistics": {
                        "total_nodes": len(nodes),
                        "total_relationships": len(links),
                        "node_types": self._count_node_types(nodes),
                        "relationship_types": self._count_relationship_types(links)
                    }
                }
        except Exception as e:
            logger.error(f"Failed to export graph: {e}")
            return {"nodes": [], "links": [], "error": str(e)}
    
    def _count_node_types(self, nodes: List[Dict]) -> Dict[str, int]:
        """Count nodes by label"""
        counts = defaultdict(int)
        for node in nodes:
            for label in node.get("labels", []):
                counts[label] += 1
        return dict(counts)
    
    def _count_relationship_types(self, links: List[Dict]) -> Dict[str, int]:
        """Count relationships by type"""
        counts = defaultdict(int)
        for link in links:
            counts[link["type"]] += 1
        return dict(counts)
    
    def generate_attack_graph_summary(self, target_ip: str) -> str:
        """Generate human-readable attack graph summary"""
        if not self.connected:
            return "Graph database not connected"
        
        host_summary = self.get_host_summary(target_ip)
        attack_paths = self.get_attack_paths(target_ip)
        vulnerabilities = self.get_all_vulnerabilities()
        
        summary = f"""
=== ATTACK GRAPH SUMMARY ===
Target: {target_ip}
Generated: {datetime.now().isoformat()}

HOST INFORMATION:
{json.dumps(host_summary, indent=2)[:500]}

ATTACK PATHS DISCOVERED: {len(attack_paths)}
"""
        
        for i, path in enumerate(attack_paths[:5], 1):
            path_nodes = [n.get("ip", n.get("name", "?")) for n in path["nodes"]]
            summary += f"\nPath {i}: {' → '.join(path_nodes)}"
        
        summary += f"\n\nVULNERABILITIES FOUND: {len(vulnerabilities)}"
        
        for vuln in vulnerabilities[:10]:
            summary += f"\n  - [{vuln.get('severity', '?').upper()}] {vuln.get('name', 'Unknown')}"
        
        return summary
    
    def clear_database(self):
        """Clear all data from Neo4j (use with caution!)"""
        if not self.connected:
            return
        
        try:
            with self.driver.session() as session:
                session.run("MATCH (n) DETACH DELETE n")
                logger.warning("Neo4j database cleared")
        except Exception as e:
            logger.error(f"Failed to clear database: {e}")
    
    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")

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
# ENHANCED AUTONOMOUS AGENT WITH GRAPH SUPPORT
# ============================================================

class AutonomousAgent:
    """Fully autonomous red team agent with RAG and Neo4j graph integration"""
    
    def __init__(self, qdrant_path: str, use_graph: bool = True):
        # Core components
        self.kb = KnowledgeBase(qdrant_path)
        self.llm = LLMClient()
        
        # Graph database
        self.use_graph = use_graph and NEO4J_AVAILABLE
        self.graph = AttackGraphDB() if self.use_graph else None
        
        # Campaign state
        self.target = ""
        self.objective = ""
        self.stealth = "high"
        self.campaign_id = ""
        self.status = CampaignStatus.RUNNING
        self.steps: List[AttackStep] = []
        self.findings: List[Finding] = []
        
        # Host tracking
        self.hosts: Dict[str, HostNode] = {}
        self.discovered_hosts: Set[str] = set()
        
        # Tracking
        self.tool_usage = defaultdict(int)
        self.error_count = 0
        self.parse_failures = 0
        self.rag_queries = 0
        self.start_time = 0
        
        # Add main target host
        self.discovered_hosts.add(target if hasattr(self, 'target') else "")
        
    def run(self, target: str, objective: str = "", stealth: str = "high") -> dict:
        """Main execution method"""
        
        self.start_time = time.time()
        self.target = target
        self.objective = objective or f"Complete security assessment of {target}"
        self.stealth = stealth
        self.campaign_id = f"RT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Add target to graph
        if self.graph and self.graph.connected:
            self.graph.add_host(target, is_target=True)
            self.hosts[target] = HostNode(ip=target)
        
        # Display banner
        self._display_banner()
        
        # Build system prompt
        system_prompt = self._build_system_prompt()
        
        # Initialize history
        history = [{
            "role": "user",
            "content": f"Begin penetration test against {target}. Start with reconnaissance using nmap_port_scan on {target}."
        }]
        
        # Phase tracking
        phases = {
            1: ("🔍 PHASE 1: RECONNAISSANCE", "cyan"),
            10: ("🎯 PHASE 2: VULNERABILITY DISCOVERY", "yellow"),
            20: ("💥 PHASE 3: EXPLOITATION", "red"),
            30: ("🔑 PHASE 4: POST-EXPLOITATION", "magenta")
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Executing attack chain with graph mapping...", total=MAX_STEPS)
            
            for step_num in range(1, MAX_STEPS + 1):
                # Check phase transitions
                for phase_num, (phase_name, phase_color) in phases.items():
                    if step_num == phase_num:
                        console.print(f"\n[bold {phase_color}]{phase_name}[/bold {phase_color}]")
                
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
                    
                    # Extract target host from args
                    target_host = args.get("host", args.get("url", self.target))
                    if target_host.startswith("http"):
                        target_host = target_host.split("//")[-1].split(":")[0].split("/")[0]
                    target_port = args.get("port", args.get("ports", 0))
                    
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
                    
                    success = self._determine_success(observation)
                    
                    # Update graph based on tool execution
                    if self.graph and self.graph.connected:
                        self._update_graph_from_tool(tool_name, args, observation, success)
                    
                    # Process findings
                    if tool_name == "report_finding":
                        self._process_finding(observation, step_num)
                    
                    # Track usage
                    tool_key = f"{tool_name}:{json.dumps(args, sort_keys=True)[:60]}"
                    self.tool_usage[tool_key] += 1
                    self.rag_queries += 1
                    
                    # Discover new hosts
                    new_hosts = self._extract_hosts_from_observation(observation)
                    for host in new_hosts:
                        if host not in self.discovered_hosts:
                            self.discovered_hosts.add(host)
                            if self.graph and self.graph.connected:
                                self.graph.add_host(host)
                    
                    # Record step
                    step = AttackStep(
                        step_number=step_num,
                        thought=thought,
                        tool=tool_name,
                        args=args,
                        observation=observation[:OBSERVATION_MAX_LENGTH],
                        success=success,
                        target_host=target_host,
                        target_port=int(target_port) if str(target_port).isdigit() else 0,
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
        
        # Generate report with graph data
        return self._generate_report()
    
    def _build_system_prompt(self) -> str:
        """Build system prompt"""
        return f"""You are an autonomous penetration testing AI agent with graph database integration.

TARGET: {self.target}
OBJECTIVE: {self.objective}
STEALTH LEVEL: {self.stealth}

AVAILABLE TOOLS:
{get_tool_descriptions()}

RESPOND WITH ONLY THIS JSON FORMAT:
{{"thought": "your reasoning here", "tool": "tool_name", "args": {{"param": "value"}}}}

ATTACK PHASES:
1. RECONNAISSANCE: nmap_port_scan, http_probe, dns_enum
2. VULNERABILITY DISCOVERY: search_exploits, vuln_scanner
3. EXPLOITATION: run_command with exploits, custom tools
4. POST-EXPLOITATION: lateral_movement, persistence

RULES:
1. Start with port scanning the target
2. Record all findings with report_finding
3. Map relationships between hosts, services, and vulnerabilities
4. Use 'done' when complete
5. NEVER use placeholder text - always real tool names and values"""
    
    def _get_rag_context(self, history: List[Dict]) -> str:
        """Get RAG context for current state"""
        try:
            recent = []
            for msg in history[-3:]:
                if msg["role"] == "user":
                    recent.append(msg["content"][:150])
            
            context = " ".join(recent) if recent else f"Pentest against {self.target}"
            
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
        parts.append(f"Discovered hosts: {len(self.discovered_hosts)}")
        
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
            "analyze observation", "next tool action", "select tool", "decide",
            "consider next", "pick tool", "use appropriate", "select appropriate"
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
    
    def _update_graph_from_tool(self, tool_name: str, args: Dict, observation: str, success: bool):
        """Update Neo4j graph based on tool execution"""
        if not self.graph or not self.graph.connected:
            return
        
        target_host = args.get("host", args.get("url", self.target))
        if isinstance(target_host, str) and target_host.startswith("http"):
            target_host = target_host.split("//")[-1].split(":")[0].split("/")[0]
        
        # Record tool execution
        self.graph.add_tool_execution(tool_name, target_host, args, success, 0)
        
        # Update graph based on tool type
        if tool_name == "nmap_port_scan":
            self._parse_nmap_to_graph(observation, target_host)
        
        elif tool_name == "http_probe":
            port = args.get("url", "").split(":")[-1].split("/")[0] if ":" in args.get("url", "") else 80
            service = "http" if "https" not in args.get("url", "") else "https"
            self.graph.add_port(target_host, int(port) if str(port).isdigit() else 80, service=service)
        
        elif tool_name == "search_exploits":
            self._parse_exploits_to_graph(observation, target_host)
        
        elif tool_name == "report_finding":
            try:
                result = json.loads(observation) if isinstance(observation, str) else observation
                if result.get("recorded"):
                    finding_data = result.get("finding", {})
                    self.graph.add_vulnerability(
                        host_ip=target_host,
                        vuln_id=f"VULN-{len(self.findings)+1}",
                        name=finding_data.get("title", "Unknown"),
                        severity=finding_data.get("severity", "medium"),
                        description=finding_data.get("description", ""),
                        cve_id=finding_data.get("technique_id", "")
                    )
            except:
                pass
    
    def _parse_nmap_to_graph(self, observation: str, host: str):
        """Parse nmap output and update graph"""
        if not self.graph or not self.graph.connected:
            return
        
        # Parse open ports from nmap output
        port_pattern = r'(\d+)/tcp\s+open\s+(\S+)'
        matches = re.findall(port_pattern, observation)
        
        for port, service in matches:
            port_num = int(port)
            self.graph.add_port(host, port_num, service=service)
            self.graph.add_service(host, port_num, service)
    
    def _parse_exploits_to_graph(self, observation: str, host: str):
        """Parse exploit search results and update graph"""
        if not self.graph or not self.graph.connected:
            return
        
        # Parse CVE IDs
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        cve_matches = re.findall(cve_pattern, observation)
        
        for cve in cve_matches:
            self.graph.add_vulnerability(
                host_ip=host,
                vuln_id=f"CVE-{cve}",
                name=f"Vulnerability {cve}",
                severity="medium",
                cve_id=cve
            )
    
    def _extract_hosts_from_observation(self, observation: str) -> Set[str]:
        """Extract IP addresses and hostnames from observation"""
        hosts = set()
        
        # IPv4 pattern
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        hosts.update(re.findall(ip_pattern, observation))
        
        # Hostname pattern (simplified)
        hostname_pattern = r'\b([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        hosts.update(re.findall(hostname_pattern, observation))
        
        return hosts
    
    def _process_finding(self, observation: str, step_num: int):
        """Process and record finding"""
        try:
            result = json.loads(observation) if isinstance(observation, str) else observation
            
            if result.get("recorded"):
                finding_data = result.get("finding", {})
                
                finding = Finding(
                    id=f"FIND-{self.campaign_id}-{len(self.findings)+1:03d}",
                    title=finding_data.get("title", "Untitled Finding"),
                    severity=finding_data.get("severity", "medium"),
                    host=finding_data.get("host", self.target),
                    port=finding_data.get("port", 0),
                    service=finding_data.get("service", ""),
                    description=finding_data.get("description", ""),
                    technique_id=finding_data.get("technique_id", ""),
                    mitigation=finding_data.get("mitigation", ""),
                    cvss_score=finding_data.get("cvss_score", 0.0),
                    evidence=finding_data.get("evidence", ""),
                    cve_ids=finding_data.get("cve_ids", []),
                    affected_hosts=finding_data.get("affected_hosts", [self.target]),
                    related_steps=[step_num]
                )
                
                self.findings.append(finding)
                
                # Add to graph
                if self.graph and self.graph.connected:
                    self.graph.add_finding(finding)
                    self.graph.add_vulnerability(
                        host_ip=finding.host,
                        vuln_id=finding.id,
                        name=finding.title,
                        severity=finding.severity,
                        description=finding.description,
                        cve_id=finding.technique_id,
                        cvss_score=finding.cvss_score
                    )
                
                # Display finding
                self._display_finding(finding)
        except Exception as e:
            logger.error(f"Failed to process finding: {e}")
    
    def _display_finding(self, finding: Finding):
        """Display finding with formatting"""
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
            f"ID: {finding.id}\n"
            f"Severity: [{color}]{finding.severity.upper()}[/{color}]\n"
            f"Host: {finding.host}\n"
            f"Technique: {finding.technique_id}\n"
            f"CVSS: {finding.cvss_score}",
            title="[bold red]NEW FINDING RECORDED[/bold red]",
            border_style=color.split()[-1] if " " in color else color
        ))
    
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
        graph_status = "✅ Connected" if (self.graph and self.graph.connected) else "❌ Disabled"
        
        console.print(Panel(
            f"[bold red]⚡ AUTONOMOUS RED TEAM AGENT v3.0 ⚡[/bold red]\n\n"
            f"[cyan]Target:[/cyan] {self.target}\n"
            f"[yellow]Objective:[/yellow] {self.objective[:100]}\n"
            f"[green]Stealth:[/green] {self.stealth.upper()}\n"
            f"[blue]Campaign:[/blue] {self.campaign_id}\n"
            f"[magenta]Neo4j Graph:[/magenta] {graph_status}\n"
            f"[magenta]RAG Knowledge:[/magenta] Integrated\n"
            f"[dim]Max Steps: {MAX_STEPS}[/dim]",
            title="[bold red]🔴 OPERATION INITIATED 🔴[/bold red]",
            border_style="red"
        ))
    
    def _display_step(self, step_num: int, thought: str, tool: str, args: Dict):
        """Display step information"""
        console.print(f"\n[dim]━━━ Step {step_num}/{MAX_STEPS} ━━━[/dim]")
        console.print(f"[bold cyan]💭 {thought[:150]}[/bold cyan]")
        console.print(f"[bold yellow]🔧 {tool}[/bold yellow] {json.dumps(args)[:80]}")
    
    def _update_history(self, history: List[Dict], response: str, observation: str, tool: str) -> List[Dict]:
        """Update conversation history"""
        history.append({"role": "assistant", "content": response[:500]})
        history.append({
            "role": "user",
            "content": f"Result from {tool}:\n{observation[:500]}\n\nWhat is your next action? Respond with JSON only."
        })
        
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
        failure_keywords = ["error", "failed", "timeout", "refused", "permission denied", "connection refused"]
        return not any(kw in observation.lower() for kw in failure_keywords)
    
    def _generate_report(self) -> dict:
        """Generate comprehensive report with graph data"""
        duration = time.time() - self.start_time
        
        # Get graph data if available
        graph_data = {}
        if self.graph and self.graph.connected:
            graph_data = {
                "attack_paths": self.graph.get_attack_paths(self.target),
                "vulnerabilities": self.graph.get_all_vulnerabilities(),
                "host_summary": self.graph.get_host_summary(self.target),
                "visualization": self.graph.export_graph_for_visualization()
            }
        
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
                "errors": self.error_count,
                "hosts_discovered": len(self.discovered_hosts),
                "graph_nodes": self.graph.nodes_created if self.graph else 0,
                "graph_relationships": self.graph.relationships_created if self.graph else 0
            },
            "findings": [asdict(f) for f in self.findings],
            "attack_timeline": [
                {
                    "step": s.step_number,
                    "tool": s.tool,
                    "thought": s.thought[:100],
                    "target_host": s.target_host,
                    "target_port": s.target_port,
                    "success": s.success,
                    "execution_time": s.execution_time
                }
                for s in self.steps
            ],
            "graph_data": graph_data,
            "discovered_hosts": list(self.discovered_hosts),
            "recommendations": self._generate_recommendations()
        }
        
        # Save report
        os.makedirs("reports", exist_ok=True)
        report_path = f"reports/{self.campaign_id}_report.json"
        
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        # Save graph visualization data separately
        if graph_data.get("visualization"):
            graph_viz_path = f"reports/{self.campaign_id}_graph.json"
            with open(graph_viz_path, "w") as f:
                json.dump(graph_data["visualization"], f, indent=2)
        
        # Display summary
        self._display_summary(report)
        
        # Display graph summary if available
        if self.graph and self.graph.connected:
            console.print("\n[bold cyan]📊 Attack Graph Summary:[/bold cyan]")
            console.print(self.graph.generate_attack_graph_summary(self.target))
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations"""
        recommendations = [
            "Implement regular security patching and updates",
            "Enable comprehensive logging and monitoring",
            "Conduct regular security assessments",
            "Implement network segmentation",
            "Use multi-factor authentication where possible"
        ]
        
        for finding in self.findings:
            if finding.severity in ["critical", "high"]:
                recommendations.append(f"Address {finding.title} - {finding.mitigation}")
        
        return list(set(recommendations))
    
    def _display_summary(self, report: dict):
        """Display final summary"""
        table = Table(title=f"🎯 Campaign Summary - {self.campaign_id}", box=box.HEAVY)
        table.add_column("Metric", style="cyan", width=30)
        table.add_column("Value", style="bold", width=50)
        
        stats = report["statistics"]
        
        table.add_row("Status", f"[green]{self.status.value.upper()}[/green]")
        table.add_row("Duration", f"{report['duration_seconds']:.2f}s")
        table.add_row("Total Steps", str(stats["total_steps"]))
        table.add_row("Successful Steps", str(stats["successful_steps"]))
        table.add_row("Findings", str(stats["findings_count"]))
        table.add_row("Critical Findings", f"[bold red]{stats['critical_findings']}[/bold red]")
        table.add_row("High Findings", f"[red]{stats['high_findings']}[/red]")
        table.add_row("Hosts Discovered", str(stats["hosts_discovered"]))
        table.add_row("Graph Nodes", str(stats["graph_nodes"]))
        table.add_row("Graph Relationships", str(stats["graph_relationships"]))
        table.add_row("RAG Queries", str(stats["rag_queries"]))
        table.add_row("Report", f"reports/{self.campaign_id}_report.json")
        table.add_row("Graph Data", f"reports/{self.campaign_id}_graph.json")
        
        console.print("\n")
        console.print(table)
        
        # Display findings tree
        if self.findings:
            tree = Tree("[bold red]🔍 Findings Hierarchy[/bold red]")
            for f in self.findings:
                icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(f.severity, "⚪")
                branch = tree.add(f"{icon} [{f.severity.upper()}] {f.title}")
                branch.add(f"Host: {f.host} | Technique: {f.technique_id}")
            console.print(tree)
    
    def cleanup(self):
        """Cleanup resources"""
        if self.graph:
            self.graph.close()


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
    
    print(f"📁 Qdrant path: {qdrant_path}")
    print(f"🔷 Neo4j available: {NEO4J_AVAILABLE}")
    
    # Initialize agent with graph support
    agent = AutonomousAgent(
        qdrant_path=qdrant_path,
        use_graph=True  # Set to False to disable graph
    )
    
    # Run campaign
    try:
        report = agent.run(
            target="192.168.171.129",
            objective="Complete security assessment with attack path mapping",
            stealth="high"
        )
        
        print(f"\n✅ Campaign completed: {report['campaign_id']}")
        print(f"📊 Total findings: {report['statistics']['findings_count']}")
        print(f"🕸️ Graph nodes created: {report['statistics']['graph_nodes']}")
        print(f"🔗 Graph relationships: {report['statistics']['graph_relationships']}")
        print(f"📁 Report: reports/{report['campaign_id']}_report.json")
        print(f"📁 Graph data: reports/{report['campaign_id']}_graph.json")
        
    finally:
        agent.cleanup()