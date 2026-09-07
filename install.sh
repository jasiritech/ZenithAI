#!/bin/bash

# ╔═══════════════════════════════════════════════════════╗
# ║        ZENITH AI SECURITY SCANNER - INSTALLER         ║
# ║     Automated setup script for Linux (Kali/Ubuntu)    ║
# ╚═══════════════════════════════════════════════════════╝

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo " ███████╗███████╗███╗   ██╗██╗████████╗██╗  ██╗"
echo " ╚══███╔╝██╔════╝████╗  ██║██║╚══██╔══╝██║  ██║"
echo "   ███╔╝ █████╗  ██╔██╗ ██║██║   ██║   ███████║"
echo "  ███╔╝  ██╔══╝  ██║╚██╗██║██║   ██║   ██╔══██║"
echo " ███████╗███████╗██║ ╚████║██║   ██║   ██║  ██║"
echo " ╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝   ╚═╝   ╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "${YELLOW}  ⚡ AI Security Scanner - Installer${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] Not running as root. Some tools may need sudo.${NC}"
fi

# ═══════════════════════════════════════
# STEP 1: System Update
# ═══════════════════════════════════════
echo -e "\n${CYAN}[1/5] Updating system packages...${NC}"
sudo apt-get update -y 2>/dev/null || true

# ═══════════════════════════════════════
# STEP 2: Install Python & pip
# ═══════════════════════════════════════
echo -e "\n${CYAN}[2/5] Installing Python 3 & pip...${NC}"
sudo apt-get install -y python3 python3-pip python3-venv 2>/dev/null || true

# ═══════════════════════════════════════
# STEP 3: Create Python Virtual Environment & Install Dependencies
# ═══════════════════════════════════════
echo -e "\n${CYAN}[3/6] Setting up Python virtual environment...${NC}"

VENV_DIR="$(pwd)/venv"

if [ -d "$VENV_DIR" ]; then
    echo -e "  ${GREEN}[✓]${NC} Virtual environment already exists"
else
    echo -e "  ${YELLOW}[*]${NC} Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    echo -e "  ${GREEN}[✓]${NC} Virtual environment created at: $VENV_DIR"
fi

# Activate venv and install packages
echo -e "  ${YELLOW}[*]${NC} Activating venv and installing Python packages..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip 2>/dev/null || true
pip install -r requirements.txt
echo -e "  ${GREEN}[✓]${NC} Python packages installed in venv"

# ═══════════════════════════════════════
# STEP 4: Install common security tools
# ═══════════════════════════════════════
echo -e "\n${CYAN}[4/6] Installing security tools...${NC}"

# Core tools
TOOLS="nmap nikto sqlmap whatweb dirb gobuster hydra curl wget whois dnsutils net-tools"

for tool in $TOOLS; do
    if command -v $tool &> /dev/null; then
        echo -e "  ${GREEN}[✓]${NC} $tool already installed"
    else
        echo -e "  ${YELLOW}[*]${NC} Installing $tool..."
        sudo apt-get install -y $tool 2>/dev/null || echo -e "  ${RED}[!]${NC} Failed to install $tool"
    fi
done

# Install Go-based tools (nuclei, subfinder, httpx)
echo -e "\n  ${YELLOW}[*]${NC} Checking Go-based tools (step 5/6)..."
if command -v go &> /dev/null; then
    echo -e "  ${GREEN}[✓]${NC} Go is installed"
    
    # Nuclei
    if ! command -v nuclei &> /dev/null; then
        echo -e "  ${YELLOW}[*]${NC} Installing nuclei..."
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true
    else
        echo -e "  ${GREEN}[✓]${NC} nuclei already installed"
    fi
    
    # Subfinder
    if ! command -v subfinder &> /dev/null; then
        echo -e "  ${YELLOW}[*]${NC} Installing subfinder..."
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
    else
        echo -e "  ${GREEN}[✓]${NC} subfinder already installed"
    fi
    
    # httpx
    if ! command -v httpx &> /dev/null; then
        echo -e "  ${YELLOW}[*]${NC} Installing httpx..."
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true
    else
        echo -e "  ${GREEN}[✓]${NC} httpx already installed"
    fi
else
    echo -e "  ${YELLOW}[!]${NC} Go not installed. Nuclei/subfinder/httpx will be installed at runtime if needed."
    echo -e "  ${YELLOW}[!]${NC} Install Go: sudo apt install golang-go"
fi

# ═══════════════════════════════════════
# STEP 6: Setup permissions
# ═══════════════════════════════════════
echo -e "\n${CYAN}[6/6] Setting up permissions...${NC}"
chmod +x zenith.py
chmod +x install.sh
chmod +x run.sh 2>/dev/null || true

# Create workspace directory
mkdir -p /tmp/zenith_workspace

# Deactivate venv (user will activate it themselves)
deactivate 2>/dev/null || true

# ═══════════════════════════════════════
# DONE!
# ═══════════════════════════════════════
echo -e "\n${GREEN}${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ✓ ZENITH AI SCANNER - INSTALLATION COMPLETE!${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}Quick Start:${NC}"
echo -e "  ${BOLD}1.${NC} Activate the virtual environment:"
echo -e "     ${YELLOW}source venv/bin/activate${NC}"
echo ""
echo -e "  ${BOLD}2.${NC} Set your API key:"
echo -e "     ${YELLOW}export GEMINI_API_KEY='your-api-key-here'${NC}"
echo ""
echo -e "  ${BOLD}3.${NC} Run Zenith (interactive):"
echo -e "     ${YELLOW}python3 zenith.py${NC}"
echo ""
echo -e "  ${BOLD}4.${NC} Or use the quick run script (auto-activates venv):"
echo -e "     ${YELLOW}./run.sh${NC}"
echo ""
echo -e "  ${BOLD}5.${NC} Run with scan profile:"
echo -e "     ${YELLOW}python3 zenith.py -t https://target.com -p web${NC}"
echo ""
echo -e "  ${BOLD}6.${NC} Run via Tor:"
echo -e "     ${YELLOW}python3 zenith.py -t https://target.com --tor${NC}"
echo ""
echo -e "  ${CYAN}Get Gemini API Key:${NC}"
echo -e "     ${YELLOW}https://aistudio.google.com/apikey${NC}"
echo ""
echo -e "  ${CYAN}Deactivate venv when done:${NC}"
echo -e "     ${YELLOW}deactivate${NC}"
echo ""
