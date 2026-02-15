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
git clone https://github.com/YOUR_USERNAME/zenith-ai.git
cd zenith-ai

# Install (Kali Linux / Ubuntu / Parrot OS)
chmod +x install.sh
./install.sh
```

### 2. Set API Key

Get your Gemini API key here: **https://aistudio.google.com/apikey**

```bash
export GEMINI_API_KEY="your-api-key-here"
```

### 3. Run!

```bash
# Interactive mode (asks you questions step by step)
python3 zenith.py

# Direct mode
python3 zenith.py -t https://target.com

# With Gemini Pro (deep thinking mode)
python3 zenith.py -t https://target.com -m pro

# With a custom goal
python3 zenith.py -t https://target.com -g "Find SQL injection and XSS vulnerabilities"

# With a config file
cp config.example.json config.json
# Edit config.json with your settings
python3 zenith.py --config config.json
```

---

## 📋 Features

| Feature | Description |
|---------|-------------|
| 🧠 **AI Autonomous Agent** | Gemini 2.5 thinks and decides the next action |
| 🔄 **Auto Loop** | Runs commands, reads output, thinks again automatically |
| 🔍 **Reconnaissance** | Nmap, WhatWeb, Subfinder, DNS recon |
| 🔎 **Vulnerability Scanning** | Nuclei, Nikto, SQLMap, Directory bruteforce |
| 💥 **Smart Exploitation** | AI selects exploits based on findings |
| 📊 **Knowledge Base** | Stores everything discovered during the scan |
| 📋 **Auto Report** | JSON report with AI analysis |
| 🛡️ **Safety Checks** | Dangerous commands are blocked |
| 🎨 **Beautiful UI** | Colored terminal output with real-time stats |

---

## 🛠️ Command Line Options

```
Usage: python3 zenith.py [OPTIONS]

Options:
  -t, --target         Target URL or IP address
  -k, --api-key        Gemini API key
  -m, --model          AI model: 'pro' or 'flash' (default: flash)
  -g, --goal           Scanning goal description
  -i, --max-iterations Maximum AI iterations (default: 100)
  -o, --output-dir     Output directory for reports
  --config             Path to JSON config file
```

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
zenith-ai/
├── zenith.py              # 🚀 Main entry point
├── install.sh             # 📦 Auto installer for Linux
├── run.sh                 # ▶️  Quick run script
├── requirements.txt       # 📋 Python dependencies
├── config.example.json    # ⚙️  Config template
├── README.md              # 📖 This file
│
└── zenith/
    ├── __init__.py
    ├── core/
    │   ├── __init__.py
    │   ├── ai_brain.py    # 🧠 Gemini AI integration (⭐ SYSTEM PROMPT IS HERE)
    │   ├── executor.py    # ▶️  Linux command executor with safety checks
    │   ├── scanner.py     # 🔄 Main autonomous scanning engine (loop)
    │   └── knowledge_base.py  # 📊 Findings database with auto-parsing
    │
    └── utils/
        ├── __init__.py
        └── display.py     # 🎨 Terminal UI & colors
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

Zenith generates two report files:
- **`target_kb.json`** - Full Knowledge Base (ports, vulnerabilities, commands, credentials, etc.)
- **`target_ai_analysis.json`** - AI-generated analysis with recommendations

---

## ⚠️ Disclaimer

This tool is for **authorized security testing ONLY**.
Do not use it on systems you don't have permission to test.
The user is solely responsible for how this tool is used.

---

## 🔧 Requirements

- **OS:** Linux (Kali Linux, Parrot OS, Ubuntu recommended)
- **Python:** 3.8+
- **API:** Google Gemini API key
- **Network:** Internet connection

---

## 📜 License

MIT License - Free to use and modify.
