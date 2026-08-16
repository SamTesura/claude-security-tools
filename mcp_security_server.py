#!/usr/bin/env python3
"""
MCP Security Testing Server
Educational pentesting tools wrapped in MCP interface.

Runs the underlying binaries as root inside the Kali container. Hardened:
- fail-closed scope enforcement (no allow-all unless explicitly opted in)
- strict argv construction (no attacker-controlled flags)
- bounded, lenient-decoded subprocess output with process-group cleanup
- secret redaction + restrictive file permissions on all artifacts
- blocking work offloaded off the asyncio event loop with a concurrency cap
"""

import subprocess
import re
import json
import sqlite3
import os
import sys
import signal
import uuid
import functools
import ipaddress
from datetime import datetime
from typing import Optional, Dict, List
from pathlib import Path
from urllib.parse import urlparse

import anyio
from mcp.server.fastmcp import FastMCP

# Restrictive default file mode for everything this process creates.
os.umask(0o077)

# Initialize FastMCP server
__version__ = "1.1.0"
mcp = FastMCP("security-testing")

# Configuration
DB_PATH = os.getenv("SCAN_DB_PATH", "/data/scans.db")
RESULTS_PATH = os.getenv("RESULTS_PATH", "/data/results")
SCOPE_FILE = os.getenv("MCP_SCOPE_FILE")
# Hard ceiling on captured output (per stream) returned to the client and
# written to disk. Prevents a chatty tool from blowing the client context or
# filling the bind mount. Override with MAX_OUTPUT_BYTES.
MAX_OUTPUT_BYTES = int(os.getenv("MAX_OUTPUT_BYTES", str(2 * 1024 * 1024)))

# Cap concurrent external processes so N offloaded scans do not each buffer
# full output into memory at once.
_PROC_LIMITER = anyio.CapacityLimiter(4)

# Scope enforcement. If MCP_SCOPE_FILE is set, the server fails closed for any
# target outside the listed CIDRs / hosts / URL patterns. If unset, the server
# REFUSES TO START unless the operator explicitly opts into allow-all with
# MCP_SCOPE_MODE=audit (fail-closed by default on a root offensive-tool box).
_SCOPE: Dict = {"mode": "audit"}

def _load_scope():
    global _SCOPE
    if not SCOPE_FILE:
        if os.getenv("MCP_SCOPE_MODE") == "audit":
            _SCOPE = {"mode": "audit"}
            print(
                "[security-mcp] WARNING: MCP_SCOPE_MODE=audit — all targets allowed "
                "(explicit opt-in). No scope enforcement.",
                file=sys.stderr,
            )
            return
        raise RuntimeError(
            "MCP_SCOPE_FILE is unset. Refusing to start fail-open on a root "
            "offensive-tooling server. Set MCP_SCOPE_FILE=/path/to/scope.json to "
            "enforce scope, or MCP_SCOPE_MODE=audit to explicitly allow all targets."
        )
    if not os.path.exists(SCOPE_FILE):
        raise RuntimeError(f"MCP_SCOPE_FILE set but file not found: {SCOPE_FILE}")
    with open(SCOPE_FILE) as f:
        data = json.load(f)
    _SCOPE = {
        "mode": "enforce",
        "cidrs": [ipaddress.ip_network(c, strict=False) for c in data.get("cidrs", [])],
        "hosts": set(data.get("hosts", [])),
        "url_patterns": [re.compile(p) for p in data.get("url_patterns", [])],
    }
    print(
        f"[security-mcp] scope ENFORCED from {SCOPE_FILE}: "
        f"{len(_SCOPE['cidrs'])} CIDRs, {len(_SCOPE['hosts'])} hosts, "
        f"{len(_SCOPE['url_patterns'])} URL patterns",
        file=sys.stderr,
    )

_load_scope()

def _ip_in_scope(ip: "ipaddress._BaseAddress") -> bool:
    return any(ip in net for net in _SCOPE["cidrs"])

def _network_in_scope(net: "ipaddress._BaseNetwork") -> bool:
    return any(
        net.version == allowed.version and net.subnet_of(allowed)
        for allowed in _SCOPE["cidrs"]
    )

def enforce_scope_target(target: str) -> None:
    """Reject IP / CIDR / range / hostname targets outside scope."""
    if _SCOPE["mode"] == "audit":
        return
    if target in _SCOPE["hosts"]:
        return
    # Single IP literal.
    try:
        if _ip_in_scope(ipaddress.ip_address(target)):
            return
    except ValueError:
        pass
    else:
        raise PermissionError(f"Target {target!r} not in scope. Add it to MCP_SCOPE_FILE.")
    # CIDR / network target (e.g. 192.168.1.0/24) — require full containment,
    # never overlap (overlap would let 0.0.0.0/0 pass any allowed CIDR).
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        net = None
    if net is not None:
        if _network_in_scope(net):
            return
        raise PermissionError(f"Target {target!r} not in scope. Add it to MCP_SCOPE_FILE.")
    # Hyphen range (e.g. 192.168.1.1-254) — check both endpoints are in scope.
    m = re.fullmatch(r'(\d+\.\d+\.\d+\.\d+)-(\d+)', target)
    if m:
        base, last = m.group(1), m.group(2)
        try:
            start = ipaddress.ip_address(base)
            end = ipaddress.ip_address('.'.join(base.split('.')[:3] + [last]))
            if _ip_in_scope(start) and _ip_in_scope(end):
                return
        except ValueError:
            pass
    raise PermissionError(f"Target {target!r} not in scope. Add it to MCP_SCOPE_FILE.")

def enforce_scope_url(url: str) -> None:
    """Reject URLs whose host or pattern is outside scope."""
    if _SCOPE["mode"] == "audit":
        return
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host in _SCOPE["hosts"]:
        return
    try:
        if _ip_in_scope(ipaddress.ip_address(host)):
            return
    except ValueError:
        pass
    # Fully anchored match only — pat.match is start-anchored and allows
    # prefix/userinfo bypass (e.g. http://allowed.com.attacker.com/).
    for pat in _SCOPE["url_patterns"]:
        if pat.fullmatch(url):
            return
    raise PermissionError(
        f"URL {url!r} not in scope. Add its host or a URL pattern to MCP_SCOPE_FILE."
    )

# Initialize database and results directory
def init_storage():
    Path(RESULTS_PATH).mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(RESULTS_PATH, 0o700)
    except OSError:
        pass
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                tool TEXT NOT NULL,
                target TEXT NOT NULL,
                command TEXT NOT NULL,
                status TEXT NOT NULL,
                result_file TEXT
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_tool_ts ON scan_history(tool, timestamp)"
        )
        conn.commit()
    finally:
        conn.close()
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass

init_storage()

# Utility functions
def sanitize_target(target: str) -> str:
    """Sanitize target input to prevent command / argument injection."""
    if not target or len(target) > 255:
        raise ValueError("target empty or too long")
    if target.startswith('-'):
        raise ValueError("target cannot start with dash")
    if '..' in target.split('/'):
        raise ValueError("path traversal blocked")
    # First char must be alphanumeric so the token can never be read as a flag.
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.\-:/]*', target):
        raise ValueError(f"Invalid target format: {target}")
    return target

def sanitize_input(value: str) -> str:
    """General input sanitization."""
    dangerous = ['&', '|', ';', '$', '`', '\n', '(', ')', '<', '>', '"', "'", '\\']
    for char in dangerous:
        if char in value:
            raise ValueError(f"Invalid character in input: {char}")
    if value.startswith('-'):
        raise ValueError("value cannot start with dash")
    return value

def sanitize_url(url: str) -> str:
    """URL validation — http(s) scheme, no shell/control chars, no leading dash."""
    if len(url) > 2048:
        raise ValueError("URL too long")
    if not re.match(r'^https?://[^\s]+$', url):
        raise ValueError("URL must be http(s):// scheme without whitespace")
    if re.search(r'[\x00-\x1f\x7f`$\\]', url):
        raise ValueError("URL contains forbidden control or shell characters")
    if url.startswith('-'):
        raise ValueError("URL cannot start with dash")
    return url

def sanitize_path(p: str) -> str:
    """Filesystem path validation — block traversal + shell chars."""
    if len(p) > 4096:
        raise ValueError("Path too long")
    if re.search(r'[\x00-\x1f`$\\]', p):
        raise ValueError("Path contains forbidden characters")
    if '..' in p.split('/'):
        raise ValueError("Path traversal blocked")
    if p.startswith('-'):
        raise ValueError("Path cannot start with dash")
    return p

# Flags whose following argv token is a secret and must never be persisted/logged.
_SECRET_FLAGS = {"--api-token", "--password", "--pass", "-p"}

def redact_cmd(cmd: List[str]) -> str:
    """Render an argv list for logging with secrets and URL userinfo redacted."""
    out: List[str] = []
    redact_next = False
    for tok in cmd:
        if redact_next:
            out.append("***REDACTED***")
            redact_next = False
            continue
        if tok in _SECRET_FLAGS:
            out.append(tok)
            redact_next = True
            continue
        if re.match(r'^https?://[^/]*@', tok):
            tok = re.sub(r'^(https?://)[^/@]*@', r'\1***@', tok)
        out.append(tok)
    return " ".join(out)

def _decode_cap(b: Optional[bytes]) -> str:
    """Decode bytes leniently and cap length so a tool can't flood the response."""
    if not b:
        return ""
    truncated = len(b) > MAX_OUTPUT_BYTES
    s = b[:MAX_OUTPUT_BYTES].decode("utf-8", "replace")
    if truncated:
        s += f"\n...[output truncated at {MAX_OUTPUT_BYTES} bytes]"
    return s

def _kill_tree(proc: subprocess.Popen) -> None:
    """SIGKILL the whole process group so grandchildren don't survive a timeout."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

def run_command(cmd: List[str], timeout: int = 300) -> Dict:
    """Execute a command safely: own process group, bounded lenient output.

    Blocking — callers offload it via _run() so the event loop stays responsive.
    """
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,  # own process group for full-tree kill
        )
    except FileNotFoundError:
        return {"success": False, "stdout": "", "stderr": f"binary not found: {cmd[0]}", "returncode": -1}
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e), "returncode": -1}

    try:
        out_b, err_b = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            out_b, err_b = proc.communicate(timeout=10)
        except Exception:
            out_b, err_b = b"", b""
        stderr = "Command timeout exceeded"
        extra = _decode_cap(err_b)
        if extra:
            stderr += "\n" + extra
        return {"success": False, "stdout": _decode_cap(out_b), "stderr": stderr, "returncode": -1}
    except Exception as e:
        _kill_tree(proc)
        return {"success": False, "stdout": "", "stderr": str(e), "returncode": -1}

    return {
        "success": proc.returncode == 0,
        "stdout": _decode_cap(out_b),
        "stderr": _decode_cap(err_b),
        "returncode": proc.returncode,
    }

async def _run(cmd: List[str], timeout: int = 300) -> Dict:
    """Offload the blocking subprocess to a worker thread (bounded concurrency)."""
    return await anyio.to_thread.run_sync(
        functools.partial(run_command, cmd, timeout=timeout), limiter=_PROC_LIMITER
    )

def log_scan(tool: str, target: str, command: str, status: str, result_file: Optional[str] = None):
    """Log scan to database. Never let a storage failure discard a completed scan."""
    try:
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute(
                "INSERT INTO scan_history (timestamp, tool, target, command, status, result_file) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (datetime.now().isoformat(), tool, target, command, status, result_file),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"[security-mcp] log_scan failed: {e}", file=sys.stderr)

def _unique_name(tool: str, target: str, ext: str = "txt") -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', target)[:60] or "target"
    return f"{tool}_{safe}_{ts}_{os.getpid()}_{uuid.uuid4().hex[:8]}.{ext}"

def _write_private(path: str, content: str) -> None:
    """Create a file 0600 (fail if it already exists) and write content."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)

def save_result(tool: str, target: str, content: str) -> str:
    """Save scan result to a uniquely-named 0600 file. Never fatal."""
    filepath = os.path.join(RESULTS_PATH, _unique_name(tool, target))
    try:
        _write_private(filepath, content)
    except Exception as e:
        print(f"[security-mcp] save_result failed: {e}", file=sys.stderr)
    return filepath

def parse_nmap_output(output: str) -> Dict:
    """Parse Nmap output for structured data (anchored to real port lines)."""
    ports = []
    line_re = re.compile(r'^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$')
    for line in output.split('\n'):
        m = line_re.match(line.strip())
        if not m:
            continue
        ports.append({
            "port": f"{m.group(1)}/{m.group(2)}",
            "state": m.group(3),
            "service": m.group(4),
            "version": (m.group(5) or "").strip(),
        })
    return {"open_ports": ports}

# Allowed nmap scan techniques (mutually-exclusive -sX flags).
_NMAP_SCAN_TYPES = {"sS", "sT", "sU", "sN", "sF", "sX", "sA", "sW", "sM", "sY", "sZ"}

# NMAP Tools
@mcp.tool()
async def nmap_basic(target: str, ports: str = "1-1000") -> str:
    """
    Basic Nmap scan with stealth SYN scan

    Args:
        target: IP address or hostname to scan
        ports: Port range to scan (default: 1-1000)

    Returns:
        Formatted scan results with raw output and parsed data
    """
    target = sanitize_target(target)
    enforce_scope_target(target)
    ports = sanitize_input(ports)

    cmd = ["nmap", "-sS", "-T2", "-p", ports, target]
    result = await _run(cmd, timeout=600)

    if result["success"]:
        parsed = parse_nmap_output(result["stdout"])
        result_file = save_result("nmap_basic", target, result["stdout"])
        log_scan("nmap_basic", target, redact_cmd(cmd), "success", result_file)

        return f"""✅ Nmap Basic Scan Complete
Target: {target}
Ports: {ports}

📊 Parsed Results:
{json.dumps(parsed, indent=2)}

📝 Raw Output:
{result["stdout"]}

💾 Saved to: {result_file}
"""
    else:
        log_scan("nmap_basic", target, redact_cmd(cmd), "failed")
        return f"❌ Scan failed: {result['stderr']}"

@mcp.tool()
async def nmap_advanced(
    target: str,
    scan_type: str = "sS",
    ports: str = "1-65535",
    timing: str = "2",
    service_detection: bool = True,
    os_detection: bool = False,
    script_scan: bool = False
) -> str:
    """
    Advanced Nmap scan with full customization

    Args:
        target: IP address or hostname
        scan_type: Scan type (sS=SYN, sT=TCP, sU=UDP, sN=NULL)
        ports: Port range
        timing: Timing template (0-5, 2=stealthy)
        service_detection: Enable service/version detection
        os_detection: Enable OS detection (requires root)
        script_scan: Enable default NSE scripts

    Returns:
        Comprehensive scan results
    """
    target = sanitize_target(target)
    enforce_scope_target(target)
    ports = sanitize_input(ports)
    if scan_type not in _NMAP_SCAN_TYPES:
        raise ValueError(f"scan_type must be one of {sorted(_NMAP_SCAN_TYPES)}")
    if not re.fullmatch(r'[0-5]', str(timing)):
        raise ValueError("timing must be 0-5")

    cmd = ["nmap", f"-{scan_type}", f"-T{timing}", "-p", ports]

    if service_detection:
        cmd.append("-sV")
    if os_detection:
        cmd.append("-O")
    if script_scan:
        cmd.append("-sC")

    cmd.append(target)

    result = await _run(cmd, timeout=1800)

    if result["success"]:
        parsed = parse_nmap_output(result["stdout"])
        result_file = save_result("nmap_advanced", target, result["stdout"])
        log_scan("nmap_advanced", target, redact_cmd(cmd), "success", result_file)

        return f"""✅ Nmap Advanced Scan Complete
Target: {target}
Configuration: {scan_type} scan, T{timing} timing

📊 Parsed Results:
{json.dumps(parsed, indent=2)}

📝 Full Output:
{result["stdout"]}

💾 Saved to: {result_file}
"""
    else:
        log_scan("nmap_advanced", target, redact_cmd(cmd), "failed")
        return f"❌ Scan failed: {result['stderr']}"

@mcp.tool()
def get_scan_history(limit: int = 20, tool: Optional[str] = None) -> str:
    """
    Retrieve scan history from database

    Args:
        limit: Number of records to retrieve (default: 20, max: 500)
        tool: Filter by specific tool (optional)

    Returns:
        Formatted scan history
    """
    limit = max(1, min(int(limit), 500))
    conn = sqlite3.connect(DB_PATH)

    if tool:
        tool = sanitize_input(tool)
        cursor = conn.execute(
            "SELECT * FROM scan_history WHERE tool=? ORDER BY timestamp DESC LIMIT ?",
            (tool, limit)
        )
    else:
        cursor = conn.execute(
            "SELECT * FROM scan_history ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )

    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return "No scan history found."

    output = "📊 Scan History\n" + "="*50 + "\n\n"
    for row in rows:
        output += f"""Timestamp: {row[1]}
Tool: {row[2]}
Target: {row[3]}
Status: {row[4]}
Result File: {row[6] or 'N/A'}
{'-'*50}
"""

    return output

# NIKTO
@mcp.tool()
async def nikto_scan(target: str, port: int = 80, ssl: bool = False, tuning: Optional[str] = None) -> str:
    """
    Nikto web server vulnerability scan.

    Args:
        target: Hostname or IP (no scheme)
        port: TCP port (default 80)
        ssl: Use HTTPS
        tuning: Nikto -Tuning string (e.g. "x6" = all minus dos)
    """
    target = sanitize_target(target)
    enforce_scope_target(target)
    if not (1 <= port <= 65535):
        raise ValueError("port must be 1-65535")
    cmd = ["nikto", "-h", target, "-p", str(port), "-ask", "no"]
    if ssl:
        cmd.append("-ssl")
    if tuning:
        if not re.fullmatch(r'[0-9a-cex]+', tuning):
            raise ValueError("tuning string invalid")
        cmd += ["-Tuning", tuning]
    result = await _run(cmd, timeout=1200)
    rf = save_result("nikto", target, result["stdout"])
    log_scan("nikto", target, redact_cmd(cmd), "success" if result["success"] else "failed", rf)
    status = "✅" if result["success"] else "⚠️"
    return f"{status} Nikto Scan Complete\nTarget: {target}:{port}\n\n{result['stdout']}\n\n💾 Saved to: {rf}"

# SQLMAP
@mcp.tool()
async def sqlmap_scan(
    url: str,
    level: int = 1,
    risk: int = 1,
    technique: str = "BEUSTQ",
    crawl: int = 0,
    forms: bool = False,
    dbs: bool = False,
    tables: Optional[str] = None,
) -> str:
    """
    SQLmap SQL-injection scan.

    Args:
        url: Full target URL (include query string for GET injection points)
        level: Test depth 1-5
        risk: Payload risk 1-3
        technique: Subset of BEUSTQ (B=boolean, E=error, U=union, S=stacked, T=time, Q=inline)
        crawl: Crawl depth 0-10 (0=off)
        forms: Auto-test HTML forms
        dbs: Enumerate databases
        tables: Database name to enumerate tables for
    """
    url = sanitize_url(url)
    enforce_scope_url(url)
    if not (1 <= level <= 5):
        raise ValueError("level must be 1-5")
    if not (1 <= risk <= 3):
        raise ValueError("risk must be 1-3")
    if not re.fullmatch(r'[BEUSTQ]+', technique):
        raise ValueError("technique must be subset of BEUSTQ")
    if not (0 <= crawl <= 10):
        raise ValueError("crawl must be 0-10")
    cmd = ["sqlmap", "-u", url, "--batch", "--level", str(level),
           "--risk", str(risk), "--technique", technique, "--random-agent"]
    if crawl > 0:
        cmd += ["--crawl", str(crawl)]
    if forms:
        cmd.append("--forms")
    if dbs:
        cmd.append("--dbs")
    if tables:
        sanitize_input(tables)
        cmd += ["-D", tables, "--tables"]
    result = await _run(cmd, timeout=1800)
    short = re.sub(r'[^a-zA-Z0-9]+', '_', url)[:60]
    rf = save_result("sqlmap", short, result["stdout"])
    log_scan("sqlmap", url, redact_cmd(cmd), "success" if result["success"] else "failed", rf)
    s = "✅" if result["success"] else "⚠️"
    return f"{s} SQLmap Complete\nURL: {url}\nLevel: {level}  Risk: {risk}  Technique: {technique}\n\n{result['stdout'][-8000:]}\n\n💾 Saved to: {rf}"

# WPSCAN
@mcp.tool()
async def wpscan_scan(url: str, enumerate: str = "vp,vt,u1-10", api_token: Optional[str] = None) -> str:
    """
    WPScan WordPress vulnerability + enumeration.

    Args:
        url: WordPress site URL
        enumerate: csv WPScan enumerate flags (vp=vuln plugins, vt=vuln themes, u=users)
        api_token: WPVulnDB token (else WPSCAN_API_TOKEN env)
    """
    url = sanitize_url(url)
    enforce_scope_url(url)
    if not re.fullmatch(r'[a-zA-Z0-9,\-]+', enumerate) or enumerate.startswith('-'):
        raise ValueError("enumerate must be alnum+comma+dash and not start with dash")
    cmd = ["wpscan", "--url", url, "--enumerate", enumerate,
           "--random-user-agent", "--no-banner", "--disable-tls-checks"]
    token = api_token or os.getenv("WPSCAN_API_TOKEN")
    if token:
        if not re.fullmatch(r'[A-Za-z0-9]+', token):
            raise ValueError("api_token must be alphanumeric")
        cmd += ["--api-token", token]
    result = await _run(cmd, timeout=1200)
    short = re.sub(r'[^a-zA-Z0-9]+', '_', url)[:60]
    rf = save_result("wpscan", short, result["stdout"])
    # redact_cmd() blanks the --api-token value so it is never persisted to scans.db.
    log_scan("wpscan", url, redact_cmd(cmd), "success" if result["success"] else "failed", rf)
    s = "✅" if result["success"] else "⚠️"
    return f"{s} WPScan Complete\nURL: {url}\n\n{result['stdout'][-8000:]}\n\n💾 Saved to: {rf}"

# DIRB
@mcp.tool()
async def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", extensions: str = "") -> str:
    """
    Dirb directory/file brute force.

    Args:
        url: Target base URL (must end with /)
        wordlist: Path to wordlist (default common.txt)
        extensions: csv extensions to append (e.g. "php,html,bak")
    """
    url = sanitize_url(url)
    enforce_scope_url(url)
    wordlist = sanitize_path(wordlist)
    cmd = ["dirb", url, wordlist, "-S", "-r"]
    if extensions:
        if not re.fullmatch(r'[a-zA-Z0-9,]+', extensions):
            raise ValueError("extensions alnum csv only")
        cmd += ["-X", "." + ",.".join(extensions.split(","))]
    result = await _run(cmd, timeout=1800)
    short = re.sub(r'[^a-zA-Z0-9]+', '_', url)[:60]
    rf = save_result("dirb", short, result["stdout"])
    log_scan("dirb", url, redact_cmd(cmd), "success" if result["success"] else "failed", rf)
    s = "✅" if result["success"] else "⚠️"
    return f"{s} Dirb Complete\nURL: {url}\n\n{result['stdout'][-8000:]}\n\n💾 Saved to: {rf}"

# SEARCHSPLOIT
@mcp.tool()
async def searchsploit_lookup(query: str, json_output: bool = True, exact: bool = False) -> str:
    """
    Searchsploit Exploit-DB query (offline local DB).

    Args:
        query: Keywords (e.g. 'apache 2.4 rce')
        json_output: Parse output as JSON
        exact: Exact match only
    """
    if not re.fullmatch(r'[a-zA-Z0-9 \.\-_]+', query):
        raise ValueError("query must be alnum + space + .-_")
    terms = query.split()
    # Any term starting with '-' would be parsed as a searchsploit flag
    # (e.g. -u triggers a network update, -m mirrors a file). Reject them.
    if any(t.startswith('-') for t in terms):
        raise ValueError("query terms cannot start with dash")
    cmd = ["searchsploit"]
    if json_output:
        cmd.append("-j")
    if exact:
        cmd.append("-e")
    cmd += terms
    result = await _run(cmd, timeout=120)
    log_scan("searchsploit", query, redact_cmd(cmd), "success" if result["success"] else "failed")
    s = "✅" if result["success"] else "⚠️"
    return f"{s} Searchsploit\nQuery: {query}\n\n{result['stdout']}"

# HYDRA
@mcp.tool()
async def hydra_bruteforce(
    target: str,
    service: str,
    userlist: str,
    passlist: str,
    port: Optional[int] = None,
    tasks: int = 4,
    stop_on_success: bool = True,
) -> str:
    """
    Hydra credential brute force. AUTHORIZED TARGETS ONLY.

    Args:
        target: IP or hostname
        service: ssh, ftp, http-post-form, smb, rdp, etc.
        userlist: Path to user list file
        passlist: Path to password list file
        port: Override default port
        tasks: Parallel tasks 1-16
        stop_on_success: Exit on first valid credential
    """
    target = sanitize_target(target)
    enforce_scope_target(target)
    if not re.fullmatch(r'[a-z0-9\-]+', service):
        raise ValueError("service must be lowercase alnum+dash")
    userlist = sanitize_path(userlist)
    passlist = sanitize_path(passlist)
    if not (1 <= tasks <= 16):
        raise ValueError("tasks must be 1-16")
    cmd = ["hydra", "-L", userlist, "-P", passlist, "-t", str(tasks), "-I"]
    if stop_on_success:
        cmd.append("-f")
    if port:
        if not (1 <= port <= 65535):
            raise ValueError("port must be 1-65535")
        cmd += ["-s", str(port)]
    cmd += [target, service]
    result = await _run(cmd, timeout=1800)
    rf = save_result("hydra", target, result["stdout"])
    log_scan("hydra", target, redact_cmd(cmd), "success" if result["success"] else "failed", rf)
    s = "✅" if result["success"] else "⚠️"
    return f"{s} Hydra Complete\nTarget: {target}/{service}\n\n{result['stdout']}\n\n💾 Saved to: {rf}"

# JOHN THE RIPPER
@mcp.tool()
async def john_crack(
    hash_content: str,
    hash_format: Optional[str] = None,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    show: bool = False,
    max_runtime: int = 1800,
) -> str:
    """
    John the Ripper offline password cracker.

    Args:
        hash_content: Raw hash text (one per line). Written to a temp file.
        hash_format: --format= name (e.g. nt, sha512crypt, NT, raw-md5)
        wordlist: Path to wordlist (default rockyou.txt)
        show: Run --show to display already-cracked passwords
        max_runtime: Wall-clock limit seconds (max 1800)
    """
    if len(hash_content) > 1_000_000:
        raise ValueError("hash_content too large (>1MB)")
    if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', hash_content):
        raise ValueError("hash_content contains control characters")
    if not (60 <= max_runtime <= 1800):
        raise ValueError("max_runtime must be 60-1800")
    hash_path = os.path.join(RESULTS_PATH, _unique_name("john_hashes", "input"))
    _write_private(hash_path, hash_content)
    wordlist = sanitize_path(wordlist)
    cmd = ["john"]
    if hash_format:
        if not re.fullmatch(r'[a-zA-Z0-9\-]+', hash_format):
            raise ValueError("hash_format must be alnum+dash")
        cmd.append(f"--format={hash_format}")
    if show:
        cmd.append("--show")
    else:
        cmd.append(f"--wordlist={wordlist}")
    cmd.append(hash_path)
    result = await _run(cmd, timeout=max_runtime)
    log_scan("john", hash_path, redact_cmd(cmd), "success" if result["success"] else "failed", hash_path)
    s = "✅" if result["success"] else "⚠️"
    return f"{s} John Complete\nHashes: {hash_path}\n\n{result['stdout']}\n{result['stderr']}"

# METASPLOIT
@mcp.tool()
async def msfconsole_run(module: str, options: Dict[str, str], action: str = "run") -> str:
    """
    Run a Metasploit module non-interactively via RC file.

    Args:
        module: Module path (e.g. 'auxiliary/scanner/ssh/ssh_version')
        options: Dict of option name → value
        action: 'run', 'check', or 'exploit'
    """
    # Hard restriction: only auxiliary/* and post/* modules are reachable via MCP.
    # exploit/* launches must stay in human-driven msfconsole.
    if not re.fullmatch(r'(auxiliary|post)/[a-zA-Z0-9_/\-]+', module):
        raise ValueError(
            "Only auxiliary/* and post/* modules are allowed via MCP. "
            "exploit/* requires a human in the loop."
        )
    if action not in ("run", "check"):
        raise ValueError("action must be run|check (exploit is blocked by module restriction)")
    rc_lines = [f"use {module}"]
    for k, v in options.items():
        if not re.fullmatch(r'[A-Za-z0-9_]+', k):
            raise ValueError(f"option name invalid: {k}")
        sval = str(v)
        if '\n' in sval or '\r' in sval:
            raise ValueError("option values cannot contain newlines")
        if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', sval):
            raise ValueError(f"option value contains control chars: {k}")
        # If the option is a host target, enforce scope on it.
        if k.upper() in ("RHOSTS", "RHOST"):
            for tok in re.split(r'[,\s]+', sval):
                tok = tok.strip()
                if not tok:
                    continue
                if tok.startswith("file:") or "*" in tok:
                    raise ValueError("file:/wildcard RHOSTS not allowed via MCP")
                enforce_scope_target(tok)
        rc_lines.append(f"set {k} {sval}")
    rc_lines += [action, "exit"]
    rc_path = os.path.join(RESULTS_PATH, _unique_name("msf", module.replace("/", "_"), ext="rc"))
    _write_private(rc_path, "\n".join(rc_lines) + "\n")
    cmd = ["msfconsole", "-q", "-r", rc_path]
    result = await _run(cmd, timeout=1800)
    log_scan("msfconsole", module, redact_cmd(cmd), "success" if result["success"] else "failed", rc_path)
    s = "✅" if result["success"] else "⚠️"
    return f"{s} Metasploit\nModule: {module}\nAction: {action}\n\n{result['stdout'][-8000:]}\n\n💾 RC: {rc_path}"

if __name__ == "__main__":
    mcp.run()
