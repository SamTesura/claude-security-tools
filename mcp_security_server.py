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
from datetime import datetime
from typing import Optional, Dict, List
from pathlib import Path
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("security-testing")

# Configuration
DB_PATH = os.getenv("SCAN_DB_PATH", "/data/scans.db")
RESULTS_PATH = os.getenv("RESULTS_PATH", "/data/results")

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

if __name__ == "__main__":
    mcp.run()
