#!/bin/bash

# ╔═══════════════════════════════════════╗
# ║     ZENITH AI - QUICK RUN SCRIPT      ║
# ╚═══════════════════════════════════════╝

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check if zenith.py exists
if [ ! -f "zenith.py" ]; then
    echo -e "${RED}[!] zenith.py not found. Make sure you're in the project directory.${NC}"
    exit 1
fi

# Check for API key
if [ -z "$GEMINI_API_KEY" ]; then
    echo -e "${YELLOW}[!] GEMINI_API_KEY environment variable not set.${NC}"
    echo -e "${CYAN}You can set it with: export GEMINI_API_KEY='your-key-here'${NC}"
    echo -e "${CYAN}Or you'll be prompted to enter it.${NC}"
    echo ""
fi

# Check if requirements are installed
python3 -c "import google.generativeai" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[!] Dependencies not installed. Running install script...${NC}"
    bash install.sh
fi

# Run Zenith with all arguments passed through
python3 zenith.py "$@"
