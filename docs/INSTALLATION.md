# Installation Guide

Complete step-by-step guide to installing Claude Security Tools on Windows 11 + WSL 2 + Kali Linux.

---

## Prerequisites Check

### Windows Requirements

- **Windows 11** (Build 22000 or higher)
- **Admin privileges**
- **Virtualization enabled** in BIOS

### Hardware Requirements

- **CPU**: 64-bit processor with virtualization support
- **RAM**: 8GB minimum, 16GB recommended
- **Disk**: 20GB free space
- **Network**: Internet connection

---

## Install WSL 2

### Step 1: Enable WSL

**Open PowerShell as Administrator:**

```powershell
# Enable WSL and Virtual Machine Platform
wsl --install

# If already installed, update to WSL 2
wsl --set-default-version 2
```

### Step 2: Restart Computer

Restart when prompted.

### Step 3: Verify Installation

```powershell
# Check WSL version
wsl --version
```

---

## Install Kali Linux

### Option 1: Microsoft Store (Recommended)

1. Open **Microsoft Store**
2. Search for "**Kali Linux**"
3. Click **Get** or **Install**

### Option 2: Command Line

```powershell
# Install Kali Linux directly
wsl --install -d kali-linux
```

### Initial Setup

1. Launch **Kali Linux** from Start Menu
2. Create username and password
3. Wait for setup to complete

### Update Kali (Optional)

```bash
sudo apt update && sudo apt upgrade -y
```

---

## Install Docker Desktop

### Step 1: Download

1. Go to [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/)
2. Download and run installer

### Step 2: Enable WSL Integration

1. Open **Docker Desktop**
2. Go to **Settings → Resources → WSL Integration**
3. Enable: **kali-linux**
4. Click **Apply & Restart**

### Step 3: Verify

```bash
# From Kali WSL
docker --version
docker-compose --version
docker run hello-world
```

---

## Install Claude Desktop

1. Go to [claude.ai](https://claude.ai)
2. Download for Windows
3. Install and sign in

---

## Setup Claude Security Tools

### Step 1: Clone Repository

```bash
# From Kali WSL
cd ~
git clone https://github.com/samtesura/claude-security-tools.git
cd claude-security-tools
chmod +x setup.sh
```

### Step 2: Run Setup

```bash
./setup.sh
```

### Step 3: Verify

```bash
docker-compose ps
```

---

## Configure Claude Desktop

### Edit Config File

**Path:** `%APPDATA%\Claude\claude_desktop_config.json`

Add:

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

### Restart Claude

1. Close Claude Desktop completely
2. Reopen
3. Check 🔌 icon shows "security-testing" connected

---

## Verification

Ask Claude:
```
Can you run a ping scan on 127.0.0.1 using nmap?
```

You should see scan results!

---

## Troubleshooting

### Docker Not Found

```powershell
# From PowerShell
wsl --shutdown
# Restart Docker Desktop
# Reopen Kali WSL
```

### Container Build Fails

```bash
mkdir -p ~/.docker
echo '{"credsStore": ""}' > ~/.docker/config.json
docker-compose build --no-cache
```

### Claude Can't Connect

1. Verify container: `docker-compose ps`
2. Check config path
3. Restart Claude Desktop
4. Check logs: `docker-compose logs -f`

---

For more issues, see [GitHub Issues](https://github.com/samtesura/claude-security-tools/issues).