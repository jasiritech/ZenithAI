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
| 📂 **Scan Profiles** | Quick, Full, Deep, Stealth, Web, Network, API, Recon-Only |
| 🚀 **Turbo Profile** | High-speed profile for fast actionable results |
| 🧠 **Deep Profile** | Advanced attack modules (IDOR, SSRF, JWT, SSTI, Race Conditions) |
| 💾 **Session Resume** | Save & resume interrupted scans anytime |
| 🔒 **Proxy / Tor Support** | Route traffic through Tor, SOCKS5, or proxychains |
| 📱 **Notifications** | Telegram, Discord, Slack alerts on findings |
| 🧠 **Model Fallback** | Auto-switches to working Gemini model if one fails |
| 🎨 **Modern Live Dashboard** | Real-time terminal dashboard (AI calls, success rate, avg duration, cache hits) |
| ⚡ **Smart Executor Cache** | Reuses recent read-only command results for faster loops |

---

## 🛠️ Command Line Options

```
Usage: python3 zenith.py [OPTIONS]

Options:
  -t, --target         Target URL, IP address, or domain
  -k, --api-key        Gemini API key
  -m, --model          AI model: 'pro' or 'flash' (default: flash)
  -g, --goal           Scanning goal description
  -p, --profile        Scan profile: turbo, quick, full, stealth, web, network, api, recon-only
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
| 🚀 `turbo` | High-speed modern scan | 40 |
| ⚡ `quick` | Fast surface-level scan | 30 |
| 🧠 `deep` | Advanced modules (IDOR, SSRF, JWT, SSTI, Race) | 120 |
| 🔥 `full` | Comprehensive deep scan | 150 |
| 🥷 `stealth` | Low and slow, avoids IDS/WAF | 80 |
| 🌐 `web` | Web app focused (SQLi, XSS, LFI) | 100 |
| 🔌 `network` | Network services & ports | 80 |
| 🔗 `api` | REST/GraphQL API testing | 80 |
| 🔍 `recon-only` | Recon only, no exploitation | 50 |

### 🧠 Advanced Attack Modules

Zenith includes 5 professional-grade attack modules that the AI automatically uses:

| Module | What It Does | Severity |
|--------|-------------|----------|
| **IDOR Scanner** | Tests API endpoints for Insecure Direct Object References by manipulating IDs | 🔴 HIGH-CRITICAL |
| **SSRF Scanner** | Tests for Server-Side Request Forgery (AWS metadata, internal services, bypass techniques) | 🔴 CRITICAL |
| **JWT Attacker** | Tests JWT tokens for alg:none bypass, weak secrets, kid injection, expired token acceptance | 🔴 CRITICAL |
| **SSTI Scanner** | Tests for Server-Side Template Injection across 10+ engines (Jinja2, Twig, ERB → RCE) | 🔴 CRITICAL |
| **Race Condition** | Tests for concurrency bugs (double-spend, coupon abuse, rate limit bypass) | 🔴 HIGH-CRITICAL |

Modules are automatically used when running `deep` or `full` profiles, or the AI may choose them during any scan.

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
    ├── modules/             # 🧠 Advanced Attack Modules
    │   ├── __init__.py
    │   ├── idor_scanner.py  # 🔴 IDOR/BOLA vulnerability scanner
    │   ├── ssrf_scanner.py  # 🔴 SSRF (cloud metadata, internal services)
    │   ├── jwt_attacks.py   # 🔴 JWT alg:none, weak secrets, kid injection
    │   ├── ssti_scanner.py  # 🔴 SSTI → RCE (Jinja2, Twig, ERB, etc.)
    │   └── race_condition.py # 🔴 Race conditions, double-spend, rate limits
    │
    ├── agents/              # 🤖 Multi-Agent Architecture
    │   ├── __init__.py
    │   ├── base_agent.py    # 🔧 Abstract base agent class
    │   ├── planner.py       # 🧠 Attack planning & orchestration
    │   ├── recon.py         # 🔍 Reconnaissance pipeline
    │   ├── web.py           # 🌐 Web security testing (Playwright)
    │   ├── exploit.py       # 💥 Exploitation agent
    │   ├── intelligence.py  # 📚 CVE/NVD lookup & research
    │   └── reporter.py      # 📊 Report generation agent
    │
    ├── memory/              # 💾 Shared Memory & Attack Graph
    │   ├── __init__.py
    │   ├── shared_memory.py # 🔗 Thread-safe agent communication
    │   └── attack_graph.py  # 🕸️ Target relationship graph
    │
    ├── parsers/             # 📝 Smart Output Parsers
    │   ├── __init__.py
    │   ├── nmap_parser.py   # 🔌 Nmap XML/grepable output
    │   ├── nuclei_parser.py # 🔬 Nuclei JSONL/text output
    │   └── generic_parser.py # 🤖 AI-powered generic parsing
    │
    ├── plugins/             # 🔌 Modular Plugin System
    │   ├── __init__.py
    │   ├── base_plugin.py   # 🔧 Plugin base class
    │   ├── loader.py        # 📦 Auto-discovery loader
    │   └── custom/          # 📁 User custom plugins
    │
    ├── bot/                 # 📱 Remote Control Bots
    │   ├── __init__.py
    │   ├── telegram_bot.py  # 🤖 Telegram with live logs
    │   ├── whatsapp_bot.py  # 📲 WhatsApp MD integration
    │   ├── command_parser.py # 🧠 Natural language parsing
    │   └── runner.py        # ▶️ Bot startup script
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

## 📱 Remote Control via Telegram/WhatsApp

Control ZenithAI from anywhere using Telegram or WhatsApp! Send commands in natural language and receive **live scan updates** in real-time.

### 🤖 Telegram Bot Setup

1. **Create a Bot:**
   - Open Telegram and message **@BotFather**
   - Send `/newbot` and follow instructions
   - Copy the bot token

2. **Get Your User ID:**
   - Message **@userinfobot** on Telegram
   - Copy your user ID

3. **Configure:**
   ```bash
   export TELEGRAM_BOT_TOKEN="your-bot-token"
   export GEMINI_API_KEY="your-gemini-key"
   ```

4. **Start Bot:**
   ```bash
   python -m zenith.bot.runner --telegram
   ```

5. **Send Commands:**
   - `/scan https://target.com` - Start quick scan
   - `deep scan example.com` - Deep comprehensive scan
   - `/status` - Check progress
   - `/stop` - Stop current scan
   - `/report` - Get results
   - Or just send any URL!

### 📲 WhatsApp Bot Setup

1. **Install Node.js:** https://nodejs.org/

2. **Start Bot:**
   ```bash
   python -m zenith.bot.runner --whatsapp
   ```

3. **Scan QR Code:** Open WhatsApp → Settings → Linked Devices → Link a Device

4. **Send Commands:** Same as Telegram!

### 🔴 Live Streaming

Both bots show **real-time progress** with:
- 📊 Progress bars updating live
- 📝 Log messages streaming in real-time
- 🚨 Instant vulnerability alerts
- 📋 Final report delivery

### Example Telegram Session:

```
You: scan https://example.com

🟢 Scanning: example.com
Profile: QUICK
Phase: 🔍 Reconnaissance

[████████████░░░░░░░░] 60%

Live Logs:
• Starting reconnaissance...
• Found 3 subdomains
• Port 80/tcp open - HTTP
• Port 443/tcp open - HTTPS
• [HIGH] SQL Injection found

Updated: 14:32:45
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
