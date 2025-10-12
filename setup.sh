#!/bin/bash

# MCP Security Server Setup Script for WSL
# Automated deployment for educational pentesting environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${PURPLE}[STEP]${NC} $1"
}

# Banner
echo -e "${GREEN}"
cat << "EOF"
╔═══════════════════════════════════════════════════╗
║   MCP Security Testing Server Setup               ║
║   WSL + Kali Linux Edition                        ║
╚═══════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Detect WSL
if grep -qEi "(Microsoft|WSL)" /proc/version &> /dev/null ; then
    print_success "Running in WSL environment"
    IS_WSL=true
else
    print_warning "Not detected as WSL, but continuing anyway..."
    IS_WSL=false
fi

# Show current location
print_info "Current directory: $(pwd)"
print_info "Windows path: \\\\wsl\$\\kali-linux$(pwd)"

# Legal disclaimer
echo -e "${RED}"
cat << "EOF"

⚠️  LEGAL DISCLAIMER ⚠️
════════════════════════════════════════════════════
This tool is for AUTHORIZED SECURITY TESTING ONLY.

✓ Only test systems you own or have written permission to test
✓ Unauthorized access to computer systems is ILLEGAL
✓ Users are responsible for complying with ALL applicable laws
✓ The authors are NOT liable for misuse or damage

By continuing, you agree to use this tool ETHICALLY and LEGALLY.
════════════════════════════════════════════════════

EOF
echo -e "${NC}"

read -p "Do you agree to use this tool ethically and legally? (yes/no): " agree
if [[ ! "$agree" =~ ^[Yy]es$ ]]; then
    print_error "Setup aborted. You must agree to the terms."
    exit 1
fi

echo ""
print_step "Checking prerequisites..."

# Check if we're in the right directory
if [ ! -f "Dockerfile" ] || [ ! -f "mcp_security_server.py" ]; then
    print_error "Required files not found in current directory!"
    echo ""
    echo "Expected files:"
    echo "  ✗ Dockerfile"
    echo "  ✗ mcp_security_server.py"
    echo "  ✗ docker-compose.yml"
    echo "  ✗ .env.template"
    echo ""
    echo "Please ensure all files are in: $(pwd)"
    echo "Windows path: \\\\wsl\$\\kali-linux$(pwd)"
    exit 1
fi

# Check for Docker
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed or not accessible."
    echo ""
    echo "For WSL, you need Docker Desktop for Windows with WSL integration:"
    echo "  1. Install Docker Desktop for Windows"
    echo "  2. Enable WSL 2 backend in Docker Desktop settings"
    echo "  3. Enable integration with 'kali-linux' in Resources > WSL Integration"
    echo "  4. Restart WSL: wsl --shutdown (from Windows PowerShell)"
    exit 1
fi

print_success "Docker found: $(docker --version)"

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed."
    exit 1
fi

print_success "Docker Compose found: $(docker-compose --version)"

# Check Docker service
if ! docker info &> /dev/null; then
    print_error "Docker daemon is not running or not accessible."
    echo ""
    echo "Please ensure:"
    echo "  1. Docker Desktop is running on Windows"
    echo "  2. WSL integration is enabled for kali-linux"
    echo "  3. Try: wsl --shutdown (from PowerShell), then restart WSL"
    exit 1
fi

print_success "Docker daemon is accessible"

# Create directory structure
echo ""
print_step "Creating directory structure..."

mkdir -p data/results
mkdir -p wordlists

print_success "Directories created"

# Set permissions (WSL-friendly)
print_step "Setting permissions..."
chmod 755 data
chmod 755 data/results
chmod 755 wordlists

# Try to set ownership (may not work without sudo, but that's okay)
if [ -w data ]; then
    print_success "Directory permissions set"
else
    print_warning "Could not set all permissions (may need sudo)"
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    print_step "Creating .env file..."
    if [ -f .env.template ]; then
        cp .env.template .env
        print_success ".env file created from template"
    else
        cat > .env << 'EOF'
WPSCAN_API_TOKEN=
SCAN_DB_PATH=/data/scans.db
RESULTS_PATH=/data/results
TZ=America/New_York
LOG_LEVEL=INFO
EOF
        print_success ".env file created with defaults"
    fi
else
    print_info ".env file already exists, skipping"
fi

# Ask about WPScan API token
echo ""
read -p "Do you have a WPScan API token? (yes/no): " has_token
if [[ "$has_token" =~ ^[Yy]es$ ]]; then
    read -p "Enter your WPScan API token: " wpscan_token
    if [ -n "$wpscan_token" ]; then
        # WSL-compatible sed
        sed -i "s/^WPSCAN_API_TOKEN=.*/WPSCAN_API_TOKEN=$wpscan_token/" .env
        print_success "WPScan API token configured"
    fi
else
    print_info "WPScan will run without API token (limited vulnerability data)"
    print_info "Get a free token at: https://wpscan.com/api"
fi

# Build the container
echo ""
print_step "Building Docker container..."
print_warning "This will take 10-15 minutes. Time to grab a coffee! ☕"
echo ""

if docker-compose build; then
    print_success "Container built successfully"
else
    print_error "Container build failed. Check the output above for errors."
    exit 1
fi

# Start the container
echo ""
print_step "Starting MCP Security Server..."

if docker-compose up -d; then
    print_success "Container started successfully"
else
    print_error "Failed to start container"
    docker-compose logs
    exit 1
fi

# Wait for container to be ready
print_info "Waiting for container to initialize..."
sleep 5

# Verify container is running
if docker-compose ps | grep -q "Up"; then
    print_success "Container is running"
else
    print_error "Container failed to start properly"
    echo ""
    echo "Checking logs:"
    docker-compose logs --tail=50
    exit 1
fi

# Download common wordlists (optional)
echo ""
read -p "Download rockyou.txt wordlist (~134MB)? (yes/no): " download_wordlists
if [[ "$download_wordlists" =~ ^[Yy]es$ ]]; then
    print_step "Downloading wordlist..."
    
    if [ ! -f wordlists/rockyou.txt ]; then
        print_info "Downloading rockyou.txt..."
        if curl -L "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
            -o wordlists/rockyou.txt --progress-bar; then
            print_success "Wordlist downloaded"
        else
            print_warning "Failed to download wordlist (you can do this manually later)"
        fi
    else
        print_info "Wordlist already exists"
    fi
fi

# Display status
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}     MCP Security Server is ready! 🔒${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo ""

print_info "📍 Project Location:"
echo "   WSL:     $(pwd)"
echo "   Windows: \\\\wsl\$\\kali-linux$(pwd)"
echo ""

print_info "📂 Access from Windows Explorer:"
echo "   1. Press Win+R"
echo "   2. Type: \\\\wsl\$\\kali-linux$(pwd)"
echo "   3. Press Enter"
echo ""

print_info "🎯 Quick Start Commands:"
echo ""
echo "  View logs:           docker-compose logs -f"
echo "  Stop server:         docker-compose down"
echo "  Restart server:      docker-compose restart"
echo "  Access shell:        docker-compose exec mcp-security bash"
echo "  View scan history:   ls -lh data/results/"
echo ""

print_info "🛠️ Available Tools:"
echo "  ✓ Nmap          - Network scanning"
echo "  ✓ Nikto         - Web vulnerability scanning"
echo "  ✓ SQLmap        - SQL injection testing"
echo "  ✓ WPScan        - WordPress security"
echo "  ✓ Dirb          - Directory brute-forcing"
echo "  ✓ Searchsploit  - Exploit database"
echo "  ✓ Metasploit    - Penetration testing framework"
echo "  ✓ Hydra         - Password attacks"
echo ""

print_warning "⚠️  Remember: Only test systems you own or have permission to test!"
echo ""

# Test connection
print_step "Testing MCP server..."
if docker-compose exec -T mcp-security python3 -c "import sys; sys.exit(0)" 2>/dev/null; then
    print_success "MCP server is responding"
else
    print_warning "Could not verify MCP server (may still be initializing)"
fi

echo ""
print_success "Setup complete! Happy (ethical) hacking! 🔒"
echo ""
print_info "Next step: Configure Claude Desktop and start scanning!"
