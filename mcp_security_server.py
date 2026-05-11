#!/usr/bin/env python3
"""
MCP Security Testing Server
Educational pentesting tools wrapped in MCP interface
Running as ROOT for full privileges
"""

import subprocess
import re
import json
import sqlite3
import os
import sys
import ipaddress
from datetime import datetime
from typing import Optional, Dict, List
from pathlib import Path
from urllib.parse import urlparse
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("security-testing")

# Configuration
DB_PATH = os.getenv("SCAN_DB_PATH", "/data/scans.db")
RESULTS_PATH = os.getenv("RESULTS_PATH", "/data/results")
SCOPE_FILE = os.getenv("MCP_SCOPE_FILE")

# Scope enforcement. If MCP_SCOPE_FILE is set, the server fails closed for any
# target outside the listed CIDRs / hosts / URL patterns. If unset, the server
# runs in audit mode (allow-all + startup warning) for backwards compatibility.
_SCOPE: Dict = {"mode": "audit"}

def _load_scope():
    global _SCOPE
    if not SCOPE_FILE:
        print(
            "[security-mcp] WARNING: MCP_SCOPE_FILE unset — running in AUDIT mode "
            "(all targets allowed). Set MCP_SCOPE_FILE=/path/to/scope.json to enforce.",
            file=sys.stderr,
        )
        return
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

def enforce_scope_target(target: str) -> None:
    """Reject IP/hostname targets outside scope."""
    if _SCOPE["mode"] == "audit":
        return
    if target in _SCOPE["hosts"]:
        return
    try:
        ip = ipaddress.ip_address(target)
        for net in _SCOPE["cidrs"]:
            if ip in net:
                return
    except ValueError:
        pass  # target is a hostname, not a literal IP
    raise PermissionError(
        f"Target {target!r} not in scope. Add it to MCP_SCOPE_FILE."
    )

def enforce_scope_url(url: str) -> None:
    """Reject URLs whose host or pattern is outside scope."""
    if _SCOPE["mode"] == "audit":
        return
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host in _SCOPE["hosts"]:
        return
    try:
        ip = ipaddress.ip_address(host)
        for net in _SCOPE["cidrs"]:
            if ip in net:
                return
    except ValueError:
        pass
    for pat in _SCOPE["url_patterns"]:
        if pat.match(url):
            return
    raise PermissionError(
        f"URL {url!r} not in scope. Add its host or a URL pattern to MCP_SCOPE_FILE."
    )

# Initialize database and results directory
def init_storage():
    Path(RESULTS_PATH).mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
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
    conn.commit()
    conn.close()

init_storage()

# Utility functions
def sanitize_target(target: str) -> str:
    """Sanitize target input to prevent command injection"""
    pattern = re.compile(r'^[a-zA-Z0-9\.\-\:\/]+$')
    if not pattern.match(target):
        raise ValueError(f"Invalid target format: {target}")
    return target

def sanitize_input(value: str) -> str:
    """General input sanitization"""
    dangerous = ['&', '|', ';', '$', '`', '\n', '(', ')', '<', '>', '"', "'", '\\']
    for char in dangerous:
        if char in value:
            raise ValueError(f"Invalid character in input: {char}")
    return value

def sanitize_url(url: str) -> str:
    """URL validation — http(s) scheme, no shell/control chars, no leading dash"""
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
    """Filesystem path validation — block traversal + shell chars"""
    if len(p) > 4096:
        raise ValueError("Path too long")
    if re.search(r'[\x00-\x1f`$\\]', p):
        raise ValueError("Path contains forbidden characters")
    if '..' in p.split('/'):
        raise ValueError("Path traversal blocked")
    if p.startswith('-'):
        raise ValueError("Path cannot start with dash")
    return p

def run_command(cmd: List[str], timeout: int = 300) -> Dict:
    """Execute command safely and return results - running as ROOT"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": "Command timeout exceeded",
            "returncode": -1
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "returncode": -1
        }

def log_scan(tool: str, target: str, command: str, status: str, result_file: Optional[str] = None):
    """Log scan to database"""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO scan_history (timestamp, tool, target, command, status, result_file) VALUES (?, ?, ?, ?, ?, ?)",
        (datetime.now().isoformat(), tool, target, command, status, result_file)
    )
    conn.commit()
    conn.close()

def save_result(tool: str, target: str, content: str) -> str:
    """Save scan result to file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{tool}_{target.replace('/', '_')}_{timestamp}.txt"
    filepath = os.path.join(RESULTS_PATH, filename)
    with open(filepath, 'w') as f:
        f.write(content)
    return filepath

def parse_nmap_output(output: str) -> Dict:
    """Parse Nmap output for structured data"""
    ports = []
    lines = output.split('\n')
    for line in lines:
        if '/tcp' in line or '/udp' in line:
            parts = line.split()
            if len(parts) >= 3:
                ports.append({
                    "port": parts[0],
                    "state": parts[1],
                    "service": parts[2] if len(parts) > 2 else "unknown"
                })
    return {"open_ports": ports}

# NMAP Tools
@mcp.tool()
def nmap_basic(target: str, ports: str = "1-1000") -> str:
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
    result = run_command(cmd, timeout=600)
    
    if result["success"]:
        parsed = parse_nmap_output(result["stdout"])
        result_file = save_result("nmap_basic", target, result["stdout"])
        log_scan("nmap_basic", target, " ".join(cmd), "success", result_file)
        
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
        log_scan("nmap_basic", target, " ".join(cmd), "failed")
        return f"❌ Scan failed: {result['stderr']}"

@mcp.tool()
def nmap_advanced(
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

    cmd = ["nmap", f"-{scan_type}", f"-T{timing}", "-p", ports]
    
    if service_detection:
        cmd.append("-sV")
    if os_detection:
        cmd.append("-O")
    if script_scan:
        cmd.append("-sC")
    
    cmd.append(target)
    
    result = run_command(cmd, timeout=1800)
    
    if result["success"]:
        parsed = parse_nmap_output(result["stdout"])
        result_file = save_result("nmap_advanced", target, result["stdout"])
        log_scan("nmap_advanced", target, " ".join(cmd), "success", result_file)
        
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
        log_scan("nmap_advanced", target, " ".join(cmd), "failed")
        return f"❌ Scan failed: {result['stderr']}"

@mcp.tool()
def get_scan_history(limit: int = 20, tool: Optional[str] = None) -> str:
    """
    Retrieve scan history from database
    
    Args:
        limit: Number of records to retrieve (default: 20)
        tool: Filter by specific tool (optional)
    
    Returns:
        Formatted scan history
    """
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
def nikto_scan(target: str, port: int = 80, ssl: bool = False, tuning: Optional[str] = None) -> str:
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
    result = run_command(cmd, timeout=1200)
    rf = save_result("nikto", target, result["stdout"])
    log_scan("nikto", target, " ".join(cmd), "success" if result["success"] else "failed", rf)
    status = "✅" if result["success"] else "⚠️"
    return f"{status} Nikto Scan Complete\nTarget: {target}:{port}\n\n{result['stdout']}\n\n💾 Saved to: {rf}"

# SQLMAP
@mcp.tool()
def sqlmap_scan(
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
    result = run_command(cmd, timeout=1800)
    short = re.sub(r'[^a-zA-Z0-9]+', '_', url)[:60]
    rf = save_result("sqlmap", short, result["stdout"])
    log_scan("sqlmap", url, " ".join(cmd), "success" if result["success"] else "failed", rf)
    s = "✅" if result["success"] else "⚠️"
    return f"{s} SQLmap Complete\nURL: {url}\nLevel: {level}  Risk: {risk}  Technique: {technique}\n\n{result['stdout'][-8000:]}\n\n💾 Saved to: {rf}"

# WPSCAN
@mcp.tool()
def wpscan_scan(url: str, enumerate: str = "vp,vt,u1-10", api_token: Optional[str] = None) -> str:
    """
    WPScan WordPress vulnerability + enumeration.

    Args:
        url: WordPress site URL
        enumerate: csv WPScan enumerate flags (vp=vuln plugins, vt=vuln themes, u=users)
        api_token: WPVulnDB token (else WPSCAN_API_TOKEN env)
    """
    url = sanitize_url(url)
    enforce_scope_url(url)
    if not re.fullmatch(r'[a-zA-Z0-9,\-]+', enumerate):
        raise ValueError("enumerate must be alnum+comma+dash")
    cmd = ["wpscan", "--url", url, "--enumerate", enumerate,
           "--random-user-agent", "--no-banner", "--disable-tls-checks"]
    token = api_token or os.getenv("WPSCAN_API_TOKEN")
    if token:
        if not re.fullmatch(r'[A-Za-z0-9]+', token):
            raise ValueError("api_token must be alphanumeric")
        cmd += ["--api-token", token]
    result = run_command(cmd, timeout=1200)
    short = re.sub(r'[^a-zA-Z0-9]+', '_', url)[:60]
    rf = save_result("wpscan", short, result["stdout"])
    log_scan("wpscan", url, " ".join(cmd), "success" if result["success"] else "failed", rf)
    s = "✅" if result["success"] else "⚠️"
    return f"{s} WPScan Complete\nURL: {url}\n\n{result['stdout'][-8000:]}\n\n💾 Saved to: {rf}"

# DIRB
@mcp.tool()
def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", extensions: str = "") -> str:
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
    result = run_command(cmd, timeout=1800)
    short = re.sub(r'[^a-zA-Z0-9]+', '_', url)[:60]
    rf = save_result("dirb", short, result["stdout"])
    log_scan("dirb", url, " ".join(cmd), "success" if result["success"] else "failed", rf)
    s = "✅" if result["success"] else "⚠️"
    return f"{s} Dirb Complete\nURL: {url}\n\n{result['stdout'][-8000:]}\n\n💾 Saved to: {rf}"

# SEARCHSPLOIT
@mcp.tool()
def searchsploit_lookup(query: str, json_output: bool = True, exact: bool = False) -> str:
    """
    Searchsploit Exploit-DB query (offline local DB).

    Args:
        query: Keywords (e.g. 'apache 2.4 rce')
        json_output: Parse output as JSON
        exact: Exact match only
    """
    if not re.fullmatch(r'[a-zA-Z0-9 \.\-_]+', query):
        raise ValueError("query must be alnum + space + .-_")
    cmd = ["searchsploit"]
    if json_output:
        cmd.append("-j")
    if exact:
        cmd.append("-e")
    cmd += query.split()
    result = run_command(cmd, timeout=120)
    log_scan("searchsploit", query, " ".join(cmd), "success" if result["success"] else "failed")
    s = "✅" if result["success"] else "⚠️"
    return f"{s} Searchsploit\nQuery: {query}\n\n{result['stdout']}"

# HYDRA
@mcp.tool()
def hydra_bruteforce(
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
    result = run_command(cmd, timeout=1800)
    rf = save_result("hydra", target, result["stdout"])
    log_scan("hydra", target, " ".join(cmd), "success" if result["success"] else "failed", rf)
    s = "✅" if result["success"] else "⚠️"
    return f"{s} Hydra Complete\nTarget: {target}/{service}\n\n{result['stdout']}\n\n💾 Saved to: {rf}"

# JOHN THE RIPPER
@mcp.tool()
def john_crack(
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
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    hash_path = os.path.join(RESULTS_PATH, f"john_hashes_{ts}.txt")
    with open(hash_path, "w") as f:
        f.write(hash_content)
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
    result = run_command(cmd, timeout=max_runtime)
    log_scan("john", hash_path, " ".join(cmd), "success" if result["success"] else "failed", hash_path)
    s = "✅" if result["success"] else "⚠️"
    return f"{s} John Complete\nHashes: {hash_path}\n\n{result['stdout']}\n{result['stderr']}"

# METASPLOIT
@mcp.tool()
def msfconsole_run(module: str, options: Dict[str, str], action: str = "run") -> str:
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
                if tok:
                    enforce_scope_target(tok)
        rc_lines.append(f"set {k} {sval}")
    rc_lines += [action, "exit"]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    rc_path = os.path.join(RESULTS_PATH, f"msf_{ts}.rc")
    with open(rc_path, "w") as f:
        f.write("\n".join(rc_lines) + "\n")
    cmd = ["msfconsole", "-q", "-r", rc_path]
    result = run_command(cmd, timeout=1800)
    log_scan("msfconsole", module, " ".join(cmd), "success" if result["success"] else "failed", rc_path)
    s = "✅" if result["success"] else "⚠️"
    return f"{s} Metasploit\nModule: {module}\nAction: {action}\n\n{result['stdout'][-8000:]}\n\n💾 RC: {rc_path}"

if __name__ == "__main__":
    mcp.run()
