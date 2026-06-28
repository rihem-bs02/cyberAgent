import socket, subprocess, requests, json, os, sys
from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

ALLOWED_COMMANDS = [
    "nmap", "curl", "wget", "whatweb", "nikto", "sqlmap",
    "hydra", "gobuster", "dirb", "wfuzz", "ffuf",
    "ping", "traceroute", "whois", "dig", "host",
    "nc", "netcat", "python3", "python",
    "searchsploit", "john", "hashcat", "medusa",
    "smbclient", "enum4linux", "nbtscan",
    "wpscan", "openssl", "ssh", "ftp",
]

def tool_tcp_scan(args):
    host    = args.get("host", "")
    ports   = args.get("ports", [80,443,22,3000,8080,8443,8888,21,25,445,3306,5432])
    timeout = float(args.get("timeout", 1.5))
    if not host:
        return "ERROR: host required"
    if isinstance(ports, str):
        try:
            if "-" in ports:
                start, end = ports.split("-")
                ports = list(range(int(start), min(int(end)+1, int(start)+200)))
            else:
                ports = [int(p) for p in ports.split(",") if p.strip()]
        except Exception:
            ports = [80,443,22,3000,8080]
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((host, int(port))) == 0:
                banner = ""
                try:
                    if port in [80,8080,3000,8000,8888]:
                        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(256).decode("utf-8", errors="ignore").strip()[:80]
                except Exception:
                    pass
                open_ports.append({"port": port, "banner": banner})
            s.close()
        except Exception:
            pass
    if not open_ports:
        return f"No open ports found on {host}"
    return json.dumps({"host": host, "open_ports": open_ports})

def tool_nmap_port_scan(args):
    host  = args.get("host", "")
    ports = args.get("ports", "1-1000")
    flags = args.get("flags", f"-sT -T4 -p {ports} --open -sV")
    if not host:
        return "ERROR: host required"
    try:
        result = subprocess.run(
            ["nmap"] + flags.split() + [host],
            capture_output=True, text=True, timeout=120
        )
        output = (result.stdout + result.stderr).strip()
        return output[:3000] if output else "No nmap output"
    except FileNotFoundError:
        return tool_tcp_scan(args)
    except subprocess.TimeoutExpired:
        return "nmap timed out — try tcp_scan instead"
    except Exception as e:
        return f"nmap error: {e}"

def tool_nmap_ping_sweep(args):
    target = args.get("target", args.get("host", ""))
    if not target:
        return "ERROR: target required"
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-T4", target],
            capture_output=True, text=True, timeout=60
        )
        return (result.stdout + result.stderr)[:2000]
    except Exception as e:
        return f"ping sweep error: {e}"

def tool_nmap_vuln_scan(args):
    host  = args.get("host", "")
    ports = args.get("ports", "")
    port_arg = f"-p {ports}" if ports else ""
    if not host:
        return "ERROR: host required"
    try:
        cmd = ["nmap", "-sV", "--script=vuln,http-headers,banner", "-T3"] + \
              (port_arg.split() if port_arg else []) + [host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        return (result.stdout + result.stderr)[:3000]
    except Exception as e:
        return f"vuln scan error: {e}"

def tool_http_probe(args):
    url     = args.get("url", "")
    method  = args.get("method", "GET").upper()
    headers = args.get("headers", {})
    data    = args.get("data", None)
    if not url:
        return "ERROR: url required"
    try:
        import urllib3
        urllib3.disable_warnings()
        resp = requests.request(
            method, url,
            headers={**{"User-Agent": "Mozilla/5.0"}, **headers},
            data=data, timeout=10, verify=False, allow_redirects=True,
        )
        return json.dumps({
            "url":         url,
            "status_code": resp.status_code,
            "headers":     dict(resp.headers),
            "body":        resp.text[:1500],
        })
    except Exception as e:
        return f"HTTP probe error: {e}"

def tool_dns_resolve(args):
    hostname = args.get("hostname", args.get("host", ""))
    if not hostname:
        return "ERROR: hostname required"
    try:
        results = socket.getaddrinfo(hostname, None)
        ips = list({r[4][0] for r in results})
        return json.dumps({"hostname": hostname, "ips": ips})
    except Exception as e:
        return f"DNS resolution failed: {e}"

def tool_run_command(args):
    command = args.get("command", "")
    timeout = int(args.get("timeout", 30))
    if not command:
        return "ERROR: command required"
    first = command.strip().split()[0].split("/")[-1]
    if not any(command.strip().startswith(p) for p in ALLOWED_COMMANDS):
        return f"Command not permitted: {first}"
    try:
        result = subprocess.run(
            command, shell=True,
            capture_output=True, text=True, timeout=timeout,
        )
        output = (result.stdout + result.stderr).strip()
        return output[:3000] if output else "(no output)"
    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout}s"
    except Exception as e:
        return f"Command error: {e}"

def tool_shell(args):
    return tool_run_command(args)

def tool_search_exploits(args):
    query = args.get("query", "")
    if not query:
        return "ERROR: query required"
    try:
        result = subprocess.run(
            ["searchsploit", "--json", query],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            data     = json.loads(result.stdout)
            exploits = data.get("RESULTS_EXPLOIT", [])[:10]
            if not exploits:
                return f"No exploits found for: {query}"
            lines = [f"Found {len(exploits)} exploits for '{query}':"]
            for e in exploits:
                lines.append(f"  [{e.get('EDB-ID','')}] {e.get('Title','')} | {e.get('Type','')} | {e.get('Platform','')}")
            return "\n".join(lines)
        return result.stderr or "searchsploit returned no results"
    except FileNotFoundError:
        return "searchsploit not found — try: apt install exploitdb"
    except Exception as e:
        return f"searchsploit error: {e}"

def tool_rag_query(args):
    from knowledge.qdrant.rag_retriever import RAGRetriever
    qdrant_path = args.get("qdrant_path", os.getenv("QDRANT_PATH", "/dataset/qdrant"))
    query       = args.get("query", "")
    phase       = args.get("phase", "all")
    top_k       = int(args.get("top_k", 5))
    if not query:
        return "ERROR: query required"
    try:
        rag = RAGRetriever(qdrant_path=qdrant_path)
        return rag.query_phase(phase=phase, context=query, top_k=top_k)
    except Exception as e:
        return f"RAG query error: {e}"

def tool_cve_lookup(args):
    product = args.get("product", "")
    version = args.get("version", "")
    if not product:
        return "ERROR: product required"
    try:
        params  = {"keywordSearch": f"{product} {version}".strip(), "resultsPerPage": 5}
        api_key = os.getenv("NVD_API_KEY", "")
        headers = {"apiKey": api_key} if api_key else {}
        resp    = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params, headers=headers, timeout=15,
        )
        if resp.status_code != 200:
            return f"NVD API error: {resp.status_code}"
        vulns = resp.json().get("vulnerabilities", [])
        if not vulns:
            return f"No CVEs found for {product} {version}"
        lines = [f"CVEs for '{product} {version}':"]
        for item in vulns[:5]:
            cve   = item.get("cve", {})
            cid   = cve.get("id", "")
            descs = cve.get("descriptions", [])
            desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")[:200]
            lines.append(f"  {cid}: {desc}")
        return "\n".join(lines)
    except Exception as e:
        return f"CVE lookup error: {e}"

def tool_report_finding(args):
    return json.dumps({
        "recorded": True,
        "finding": {
            "title":       args.get("title", ""),
            "severity":    args.get("severity", "medium"),
            "host":        args.get("host", ""),
            "description": args.get("description", ""),
            "evidence":    args.get("evidence", ""),
            "technique_id":args.get("technique_id", ""),
            "remediation": args.get("remediation", ""),
        }
    })

# ── Registry ──────────────────────────────────────────────────────────────────

# ── Registry ─────────────────────────────────────────────
TOOLS = {
    "tcp_scan":        {"fn": tool_tcp_scan,        "description": "TCP port scan. Args: host (str), ports (list)"},
    "nmap_port_scan":  {"fn": tool_nmap_port_scan,  "description": "Nmap scan. Args: host (str), ports (str like 21,22,80,443), flags (str optional)"},
    "nmap_ping_sweep": {"fn": tool_nmap_ping_sweep, "description": "Find live hosts. Args: target (str)"},
    "nmap_vuln_scan":  {"fn": tool_nmap_vuln_scan,  "description": "Nmap vuln scripts. Args: host (str), ports (str)"},
    "http_probe":      {"fn": tool_http_probe,      "description": "Probe HTTP. Args: url (str), method (str)"},
    "http":            {"fn": tool_http_probe,      "description": "Alias http_probe. Args: url (str)"},
    "dns_resolve":     {"fn": tool_dns_resolve,     "description": "Resolve hostname. Args: hostname (str)"},
    "run_command":     {"fn": tool_run_command,     "description": "Run tool command. Args: command (str), timeout (int). Allowed: nmap curl nikto sqlmap gobuster whatweb hydra searchsploit msfconsole"},
    "shell":           {"fn": tool_shell,           "description": "Alias run_command. Args: command (str), timeout (int)"},
    "search_exploits": {"fn": tool_search_exploits, "description": "Search ExploitDB. Args: query (str)"},
    "rag_query":       {"fn": tool_rag_query,       "description": "Query knowledge base. Args: query (str), phase (recon|exploitation|privesc|all), top_k (int)"},
    "cve_lookup":      {"fn": tool_cve_lookup,      "description": "Look up CVEs. Args: product (str), version (str)"},
    "report_finding":  {"fn": tool_report_finding,  "description": "Record finding. Args: title, severity (critical|high|medium|low), host, description, technique_id, remediation"},
}


def _normalize(name: str) -> str:
    return name.strip().replace(" ", "_").replace("-", "_").lower()


def execute_tool(name: str, args: dict) -> str:
    clean = _normalize(name)
    if clean in TOOLS:
        try:
            return str(TOOLS[clean]["fn"](args))
        except Exception as e:
            return f"Tool {clean} error: {e}"
    matches = [k for k in TOOLS if k.startswith(clean[:8])]
    if len(matches) == 1:
        try:
            return str(TOOLS[matches[0]]["fn"](args))
        except Exception as e:
            return f"Tool {matches[0]} error: {e}"
    return f"Unknown tool: {name}. Available: {list(TOOLS.keys())}"


def get_tool_descriptions() -> str:
    return "\n".join(f"- {n}: {i['description']}" for n, i in TOOLS.items())
