# Claude Security Tools

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-WSL%202-blue.svg)](https://docs.microsoft.com/en-us/windows/wsl/)
[![Kali Linux](https://img.shields.io/badge/OS-Kali%20Linux-557C94.svg)](https://www.kali.org/)

> Run professional security testing tools (Nmap, Nikto, SQLmap, WPScan, and more) directly through Claude AI using MCP (Model Context Protocol) on Windows 11 + WSL 2 + Kali Linux.

⚠️ **FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING ONLY**

---

## 🎯 Overview

This project provides a fully-configured MCP server that integrates professional penetration testing tools with Claude AI. Chat with Claude to run security scans, enumerate systems, search for exploits, and more - all through natural language.

### What is MCP?

Model Context Protocol (MCP) allows Claude to interact with external tools and systems. This server wraps security testing tools in an MCP interface, giving Claude the ability to run real pentesting commands on your behalf.

---

## ✨ Features

### 🛠️ Security Tools Included

- **Nmap** - Network scanning and port discovery
- **Nikto** - Web server vulnerability scanning  
- **SQLmap** - SQL injection detection and exploitation
- **WPScan** - WordPress vulnerability scanner
- **Dirb** - Web directory brute-forcing
- **Searchsploit** - Exploit-DB search
- **Metasploit** - Penetration testing framework
- **Hydra** - Network password cracker
- **John the Ripper** - Password hash cracker

### 🔑 Key Capabilities

✅ **Basic & Advanced Modes** - Simple defaults for quick scans, full control for experts  
✅ **Stealth Scanning** - Low-noise, IDS-evasion techniques  
✅ **Result Persistence** - SQLite database + file storage  
✅ **Safety Confirmations** - Destructive tools require explicit confirmation  
✅ **Input Sanitization** - Protection against command injection  
✅ **Full Privileges** - Root access for all scan types  
✅ **Formatted Output** - Raw output + parsed structured data

---

## 📋 Prerequisites

### Required Software

- **Windows 11** (with virtualization enabled)
- **WSL 2** (Windows Subsystem for Linux 2)
- **Kali Linux** (via Microsoft Store)
- **Docker Desktop for Windows** (with WSL 2 backend)
- **Claude Desktop** (with MCP support)

### System Requirements

- 8GB RAM minimum (16GB recommended)
- 20GB free disk space
- Admin privileges on Windows

---

## 🚀 Quick Start

### 1. Install WSL 2 + Kali Linux

**From Windows PowerShell (Administrator):**

```powershell
# Enable WSL
wsl --install

# Restart computer when prompted

# Install Kali Linux
wsl --install -d kali-linux

# Verify installation
wsl -l -v
```

### 2. Install Docker Desktop

1. Download [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/)
2. Install and enable WSL 2 backend
3. Go to **Settings → Resources → WSL Integration**
4. Enable integration with **kali-linux**
5. Click **Apply & Restart**

### 3. Clone This Repository

**From Kali Linux WSL:**

```bash
# Open Kali WSL
wsl -d kali-linux

# Navigate to home directory
cd ~

# Clone the repository
git clone https://github.com/samtesura/claude-security-tools.git
cd claude-security-tools

# Make setup script executable
chmod +x setup.sh
```

### 4. Run Setup

```bash
# Run the automated setup script
./setup.sh
```

The setup script will:
- ✅ Check Docker Desktop integration
- ✅ Create necessary directories
- ✅ Build the Kali Linux container (~10-15 minutes)
- ✅ Configure environment variables
- ✅ Start the MCP server
- ✅ Verify installation

### 5. Configure Claude Desktop

**Edit Claude Desktop config:**

Windows path: `%APPDATA%\Claude\claude_desktop_config.json`

Add this to your MCP servers:

```json
{
  "mcpServers": {
    "security-testing": {
      "command": "wsl",
      "args": [
        "-d",
        "kali-linux",
        "--exec",
        "docker",
        "exec",
        "-i",
        "mcp-security-server",
        "python3",
        "/root/mcp_security_server.py"
      ],
      "env": {
        "SCAN_DB_PATH": "/data/scans.db",
        "RESULTS_PATH": "/data/results"
      }
    }
  }
}
```

### 6. Restart Claude Desktop

1. Completely close Claude Desktop
2. Reopen Claude Desktop
3. Check the 🔌 icon - you should see "security-testing" connected

### 7. Start Scanning!

Ask Claude:
- "Run an nmap scan on 192.168.1.1"
- "Scan my network 192.168.1.0/24 for web servers"
- "Check if example.com has any web vulnerabilities with Nikto"
- "Search for WordPress exploits"

---

## 📖 Documentation

- [**Installation Guide**](docs/INSTALLATION.md) - Detailed setup instructions
- [**Usage Guide**](docs/USAGE.md) - Tool examples and best practices
- [**Troubleshooting**](docs/TROUBLESHOOTING.md) - Common issues and solutions
- [**Contributing**](CONTRIBUTING.md) - How to contribute

---

## 🎓 Usage Examples

### Network Scanning

```
You: "Run a fast nmap scan on 192.168.1.0/24"
Claude: [Executes nmap -F -T2 192.168.1.0/24 and shows results]
```

### Web Vulnerability Scanning

```
You: "Scan https://testsite.local for vulnerabilities"
Claude: [Runs Nikto scan and provides detailed findings]
```

### WordPress Security Audit

```
You: "Check if wordpress-site.com has vulnerable plugins"
Claude: [Executes WPScan with enumeration and shows results]
```

### Exploit Research

```
You: "Search for Apache 2.4.49 exploits"
Claude: [Queries Exploit-DB and shows available exploits]
```

---

## 🔒 Security & Legal

### ⚠️ Legal Disclaimer

**THIS TOOL IS FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY.**

You must:
- ✅ Only test systems you own or have explicit written permission to test
- ✅ Comply with all applicable laws and regulations
- ✅ Never use these tools for malicious purposes
- ✅ Understand that unauthorized access to computer systems is illegal

**The authors are not responsible for any misuse or damage caused by this software.**

### 🛡️ Security Features

- **Input Sanitization** - All inputs validated to prevent command injection
- **Confirmation Required** - Destructive tools (SQLmap, Hydra) require explicit confirmation
- **Isolated Container** - Tools run in Docker container with controlled privileges
- **Audit Trail** - All scans logged to SQLite database

---

## 🗂️ Project Structure

```
claude-security-tools/
├── mcp_security_server.py    # Main MCP server (Python + FastMCP)
├── Dockerfile                 # Kali Linux container definition
├── docker-compose.yml         # Container orchestration
├── setup.sh                   # Automated setup script
├── .env.template             # Environment variables template
├── LICENSE                    # MIT License
├── README.md                  # This file
├── data/                     # Persistent data (created by setup)
│   ├── scans.db             # SQLite database
│   └── results/             # Scan output files
└── docs/                    # Documentation
    └── INSTALLATION.md      # Detailed installation guide
```

---

## 💾 Data Management

### Viewing Results

**From WSL:**
```bash
cd ~/claude-security-tools
ls -lh data/results/
cat data/results/nmap_*.txt
```

**From Windows:**
Press `Win+R`, type: `\\wsl$\kali-linux\home\<username>\claude-security-tools\data\results`

### Backup to Windows Desktop

```bash
cp -r data "/mnt/c/Users/<your-username>/Desktop/security-backup-$(date +%Y%m%d)"
```

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Anthropic](https://www.anthropic.com/) - For Claude and MCP
- [Kali Linux Team](https://www.kali.org/) - For the pentesting distribution
- [Offensive Security](https://www.offensive-security.com/) - For security tools and training

---

**Made with ❤️ for ethical hackers and security professionals**

*Remember: With great power comes great responsibility. Use these tools ethically and legally.*