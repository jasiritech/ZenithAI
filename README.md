# 🔱 ZENITH AI - Autonomous Security Scanner

```
 ███████╗███████╗███╗   ██╗██╗████████╗██╗  ██╗     █████╗ ██╗
 ╚══███╔╝██╔════╝████╗  ██║██║╚══██╔══╝██║  ██║    ██╔══██╗██║
   ███╔╝ █████╗  ██╔██╗ ██║██║   ██║   ███████║    ███████║██║
  ███╔╝  ██╔══╝  ██║╚██╗██║██║   ██║   ██╔══██║    ██╔══██║██║
 ███████╗███████╗██║ ╚████║██║   ██║   ██║  ██║    ██║  ██║██║
 ╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝   ╚═╝   ╚═╝  ╚═╝    ╚═╝  ╚═╝
```

**Autonomous AI-Powered Vulnerability Scanner** powered by Gemini 2.5 Pro/Flash

---

## ⚡ How It Works

1. **Clone** → install on Linux
2. **Set API Key** for Gemini (2.5 Pro or Flash)
3. **Set Target** (website URL or IP)
4. **AI thinks** → runs commands automatically → reads output → thinks of new approaches → loop
5. **Report** → all findings are saved as JSON

### AI Loop:
```
┌──────────────────────────────────────────────────┐
│  🧠 AI THINKS (analyzes current state)           │
│  ↓                                               │
│  ▶ RUNS COMMAND (nmap, nuclei, sqlmap, etc.)     │
│  ↓                                               │
│  📖 READS OUTPUT (parses results)                │
│  ↓                                               │
│  🔄 THINKS OF NEW APPROACH (adapts strategy)     │
│  ↓                                               │
│  🔁 LOOP (until goal is achieved)                │
│  ↓                                               │
│  📋 FINAL REPORT (comprehensive findings)        │
└──────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Clone and Install

```bash
# Clone the repo
git clone https://github.com/jasiritech/ZenithAI.git
cd ZenithAI

# Install (creates venv + installs everything)
chmod +x install.sh
./install.sh
```

The installer automatically:
- Creates a Python virtual environment (`venv/`)
- Installs all Python dependencies inside the venv
- Installs security tools (nmap, nikto, sqlmap, nuclei, etc.)

### 2. Activate Virtual Environment

```bash
# Activate the venv (REQUIRED before running)
source venv/bin/activate

# You'll see (venv) in your prompt:
# (venv) ┌──(user㉿kali)-[~/ZenithAI]
# (venv) └─$
```

### 3. Set API Key

Get your Gemini API key here: **https://aistudio.google.com/apikey**

```bash
export GEMINI_API_KEY="your-api-key-here"
```

### 4. Run!

```bash
# Interactive mode (recommended - guides you step by step)
python3 zenith.py

# Or use the quick run script (auto-activates venv for you)
./run.sh

# Direct mode
python3 zenith.py -t https://target.com

# With Gemini Pro (deep thinking mode)
python3 zenith.py -t https://target.com -m pro

# With a scan profile
python3 zenith.py -t https://target.com -p web

# Via Tor
python3 zenith.py -t https://target.com --tor

# With a custom goal
python3 zenith.py -t https://target.com -g "Find SQL injection and XSS vulnerabilities"

# Resume an interrupted scan
python3 zenith.py --resume zenith_1234567_example_com

# List all saved sessions
python3 zenith.py --sessions
```

### 5. Deactivate When Done

```bash
# When you're finished, deactivate the venv
deactivate
```

> **💡 Tip:** You can also use `./run.sh` which automatically activates the venv for you — no need to manually `source venv/bin/activate` every time.

---

## 📋 Features

| Feature | Description |
|---------|-------------|
| 🧠 **AI Autonomous Agent** | Gemini 2.5 Pro/Flash thinks and decides the next action |
| 🔄 **Auto Loop** | Runs commands, reads output, thinks again automatically |
| 🔍 **Reconnaissance** | Nmap, WhatWeb, Subfinder, DNS recon |
| 🔎 **Vulnerability Scanning** | Nuclei, Nikto, SQLMap, Directory bruteforce |
| 💥 **Smart Exploitation** | AI selects exploits based on findings |
| 📊 **Knowledge Base** | Stores everything discovered during the scan |
| 📋 **HTML Reports** | Beautiful standalone HTML security reports |
| 🛡️ **Command Validation** | Blocks dangerous commands & validates target scope |
| 🎯 **Target Validation** | Prevents accidental shell commands as targets |
| 📂 **Scan Profiles** | Quick, Full, Stealth, Web, Network, API, Recon-Only |
| 💾 **Session Resume** | Save & resume interrupted scans anytime |
| 🔒 **Proxy / Tor Support** | Route traffic through Tor, SOCKS5, or proxychains |
| 📱 **Notifications** | Telegram, Discord, Slack alerts on findings |
| 🧠 **Model Fallback** | Auto-switches to working Gemini model if one fails |
| 🎨 **Beautiful UI** | Colored terminal output with real-time stats |

---

## 🛠️ Command Line Options

```
Usage: python3 zenith.py [OPTIONS]

Options:
  -t, --target         Target URL, IP address, or domain
  -k, --api-key        Gemini API key
  -m, --model          AI model: 'pro' or 'flash' (default: flash)
  -g, --goal           Scanning goal description
  -p, --profile        Scan profile: quick, full, stealth, web, network, api, recon-only
  -i, --max-iterations Maximum AI iterations (default: 100)
  -o, --output-dir     Output directory for reports
  --config             Path to JSON config file
  --tor                Route scan traffic through Tor
  --proxy URL          Custom proxy (e.g. socks5://127.0.0.1:1080)
  --resume SESSION_ID  Resume an interrupted scan session
  --sessions           List all saved scan sessions
```

### Scan Profiles

| Profile | Description | Max Iterations |
|---------|-------------|----------------|
| ⚡ `quick` | Fast surface-level scan | 30 |
| 🔥 `full` | Comprehensive deep scan | 150 |
| 🥷 `stealth` | Low and slow, avoids IDS/WAF | 80 |
| 🌐 `web` | Web app focused (SQLi, XSS, LFI) | 100 |
| 🔌 `network` | Network services & ports | 80 |
| 🔗 `api` | REST/GraphQL API testing | 80 |
| 🔍 `recon-only` | Recon only, no exploitation | 50 |

---

## 🧠 System Prompt Location

The **system prompt** (the instructions that tell the AI how to behave) is located in:

```
zenith/core/ai_brain.py → think() method (line ~55)
```

This is the main prompt that controls how the AI:
- Decides which commands to run
- Analyzes command output
- Chooses the next attack vector
- Switches between scanning phases (RECON → SCAN → EXPLOIT → POST_EXPLOIT → REPORT)

To **customize the AI behavior**, edit the `prompt` variable inside the `think()` method.

There is also a **report generation prompt** in the `analyze_findings()` method (~line 171) that controls how the final report is structured.

---

## 📁 Project Structure

```
ZenithAI/
├── zenith.py                # 🚀 Main entry point (interactive + CLI)
├── install.sh               # 📦 Auto installer (creates venv)
├── run.sh                   # ▶️  Quick run (auto-activates venv)
├── requirements.txt         # 📋 Python dependencies
├── config.example.json      # ⚙️  Config template
├── README.md                # 📖 This file
├── .gitignore               # 🚫 Git ignore rules
├── venv/                    # 🐍 Python virtual environment (created by install.sh)
│
└── zenith/
    ├── __init__.py
    ├── core/
    │   ├── __init__.py
    │   ├── ai_brain.py      # 🧠 Gemini AI integration (⭐ SYSTEM PROMPT HERE)
    │   ├── executor.py      # ▶️  Linux command executor with safety checks
    │   ├── scanner.py       # 🔄 Main autonomous scanning engine (loop)
    │   ├── knowledge_base.py # 📊 Findings database with auto-parsing
    │   ├── session.py       # 💾 Session save/resume manager
    │   ├── profiles.py      # 📂 Scan profile templates
    │   ├── validator.py     # 🛡️  Command validation & sanitization
    │   └── proxy.py         # 🔒 Proxy/Tor traffic routing
    │
    └── utils/
        ├── __init__.py
        ├── display.py       # 🎨 Terminal UI & colors
        ├── report_generator.py # 📄 HTML report generator
        └── notifier.py      # 📱 Telegram/Discord/Slack notifications
```

---

## ⚙️ Config File Example

```json
{
    "api_key": "YOUR_GEMINI_API_KEY",
    "target": "https://example.com",
    "goal": "Find all security vulnerabilities",
    "model": "flash",
    "max_iterations": 100,
    "output_dir": "/tmp/zenith_results"
}
```

---

## 🔑 Getting a Gemini API Key

1. Go to **https://aistudio.google.com/apikey**
2. Sign in with your Google account
3. Click "Create API Key"
4. Copy the API key

---

## 📊 Output

Zenith generates three report files:
- **`target_report.html`** - Beautiful standalone HTML security report (open in browser)
- **`target_kb.json`** - Full Knowledge Base (ports, vulnerabilities, commands, credentials, etc.)
- **`target_ai_analysis.json`** - AI-generated analysis with recommendations

### Session Data

Scan sessions are saved to `~/.zenith/sessions/` and can be resumed at any time:
```bash
# List all sessions
python3 zenith.py --sessions

# Resume a session
python3 zenith.py --resume zenith_1234567_example_com
```

### Notifications

Set environment variables to enable alerts:
```bash
# Telegram
export ZENITH_TELEGRAM_TOKEN="your-bot-token"
export ZENITH_TELEGRAM_CHAT_ID="your-chat-id"

# Discord
export ZENITH_DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."

# Slack
export ZENITH_SLACK_WEBHOOK="https://hooks.slack.com/services/..."
```

---

## ⚠️ Disclaimer

This tool is for **authorized security testing ONLY**.
Do not use it on systems you don't have permission to test.
The user is solely responsible for how this tool is used.

---

## 🔧 Requirements

- **OS:** Linux (Kali Linux, Parrot OS, Ubuntu recommended)
- **Python:** 3.8+ with `python3-venv`
- **API:** Google Gemini API key (free at https://aistudio.google.com/apikey)
- **Network:** Internet connection

### Python Dependencies (auto-installed in venv)

| Package | Purpose |
|---------|---------|
| `google-generativeai` | Gemini AI API client |
| `requests` | HTTP requests for notifications & proxy verification |

### Manual venv Setup (if install.sh fails)

```bash
# Create venv manually
python3 -m venv venv

# Activate it
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run
python3 zenith.py

# When done
deactivate
```

---

## 📜 License

MIT License - Free to use and modify.
