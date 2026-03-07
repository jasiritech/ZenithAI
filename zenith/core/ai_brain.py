"""
Zenith AI Brain - Multi-Provider AI Integration
Supports: Gemini (Google) and Groq (Fast & Free)
This is the brain of the tool - it thinks, plans, and decides the next action.
"""

import json
import time
from datetime import datetime

# Try to import Gemini
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    genai = None
    GEMINI_AVAILABLE = False

# Try to import Groq
try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False


class AIBrain:
    """
    AI Brain powered by Gemini or Groq for security scanning decisions.
    Thinks like a HACKER - selects tools,writie a script, reads results, finds new attack paths.
    
    Providers:
    - Gemini (Google): Default, good quality
    - Groq: FAST & FREE (14,400 requests/day!) - use key starting with 'gsk_'
    """

    # Model fallback chains - tries each until one works
    # Tested & verified working as of Feb 2026
    MODEL_CHAINS = {
        "pro": [
            "gemini-2.5-pro",
            "gemini-2.5-flash",
            "gemini-1.5-flash",
            "gemini-2.0-flash",
            "gemini-2.0-flash-lite",
        ],
        "flash": [
            "gemini-2.5-flash",
            "gemini-1.5-flash",
            "gemini-2.0-flash",
            "gemini-2.0-flash-lite",
            "gemini-2.5-pro",
        ],
    }
    
    # Groq models - FAST and FREE! (Updated Feb 2026)
    # Production models with good context windows
    GROQ_MODELS = [
        "llama-3.3-70b-versatile",    # Best quality, 131k ctx, 32k output
        "llama-3.1-8b-instant",       # Fast, 131k ctx
        "qwen/qwen3-32b",             # Good alternative, 131k ctx
        "meta-llama/llama-4-scout-17b-16e-instruct",  # Llama 4! 131k ctx
    ]

    # Keep for backward compat - points to first in chain
    SUPPORTED_MODELS = {
        "pro": "gemini-2.5-pro",
        "flash": "gemini-2.5-flash",
        "groq": "llama-3.3-70b-versatile",
    }

    def __init__(self, api_key, model_choice="flash"):
        """
        Initialize AI Brain with automatic provider detection and model fallback.
        
        Args:
            api_key: API key (Gemini: AIza..., Groq: gsk_...)
            model_choice: 'pro' for deep thinking, 'flash' for speed, 'groq' for Groq
        """
        if not api_key or api_key == "":
            raise ValueError("[!] API Key is required! Please provide your API key.")
        
        self.api_key = api_key
        self.model_choice = model_choice
        self.total_tokens = 0
        self.call_count = 0
        self.consecutive_errors = 0
        self.max_consecutive_errors = 5
        self.chat_history = []
        
        # Detect provider: key format OR explicit model_choice
        # Key starting with gsk_ = always Groq
        # model_choice == 'groq' = user explicitly chose Groq
        if api_key.startswith("gsk_") or model_choice == "groq":
            self.provider = "groq"
            self._init_groq(api_key)
        else:
            self.provider = "gemini"
            self._init_gemini(api_key, model_choice)
    
    def _init_groq(self, api_key):
        """Initialize Groq provider."""
        if not GROQ_AVAILABLE:
            raise ValueError(
                "[!] Groq library not installed!\n"
                "    Run: pip install groq\n"
                "    Or: pip install -r requirements.txt"
            )
        
        self.groq_client = Groq(api_key=api_key)
        self.model = None
        self.model_name = None
        
        for model_name in self.GROQ_MODELS:
            try:
                print(f"    [*] Trying Groq model: {model_name}...")
                # Test the model
                response = self.groq_client.chat.completions.create(
                    model=model_name,
                    messages=[{"role": "user", "content": "Reply with OK"}],
                    max_tokens=10
                )
                _ = response.choices[0].message.content
                
                self.model_name = model_name
                print(f"    [✓] AI Brain initialized: Groq/{model_name}")
                print(f"    [💡] Groq FREE tier: 30 req/min, 14,400 req/day!")
                break
            except Exception as e:
                err = str(e)
                print(f"    [!] Groq model {model_name} failed: {err[:80]}")
                continue
        
        if self.model_name is None:
            raise ValueError(
                "[!] No working Groq model found!\n"
                "    Get your FREE API key at: https://console.groq.com/keys"
            )
    
    def _init_gemini(self, api_key, model_choice):
        """Initialize Gemini provider."""
        if not GEMINI_AVAILABLE:
            # Only fall back to Groq if the API key is actually a Groq key
            if GROQ_AVAILABLE and api_key.startswith("gsk_"):
                print("    [!] google-generativeai not installed, falling back to Groq...")
                self.provider = "groq"
                self._init_groq(api_key)
                return
            
            # Gemini key but no Gemini library - tell user exactly what to do
            raise ValueError(
                "[!] google-generativeai library not installed!\n"
                "    Your Gemini API key needs this library.\n\n"
                "    Fix: Run this command on your terminal:\n"
                "      pip install --break-system-packages google-generativeai\n\n"
                "    OR switch to Groq (FREE, no extra install needed):\n"
                "      Get key at: https://console.groq.com/keys\n"
                "      Then choose [2] Groq when starting ZenithAI"
            )
        genai.configure(api_key=api_key)
        
        # Try models in the fallback chain until one works
        chain = self.MODEL_CHAINS.get(model_choice, self.MODEL_CHAINS["flash"])
        self.model = None
        self.model_name = None
        
        for model_name in chain:
            try:
                print(f"    [*] Trying model: {model_name}...")
                candidate = genai.GenerativeModel(
                    model_name=model_name,
                    generation_config={
                        "temperature": 0.7,
                        "top_p": 0.95,
                        "top_k": 40,
                        "max_output_tokens": 8192,
                    },
                    safety_settings=[
                        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                    ]
                )
                # Test with a quick call to verify the model exists
                test_resp = candidate.generate_content("Reply with OK")
                _ = test_resp.text  # Force evaluation
                
                self.model = candidate
                self.model_name = model_name
                print(f"    [✓] AI Brain initialized: {model_name}")
                break
            except Exception as e:
                err = str(e)
                if "404" in err or "not found" in err.lower():
                    print(f"    [!] Model {model_name} not available, trying next...")
                    continue
                elif "429" in err or "quota" in err.lower():
                    print(f"    [!] Rate limited on {model_name}, waiting 10s...")
                    time.sleep(10)
                    continue
                else:
                    print(f"    [!] Error with {model_name}: {err}")
                    continue
        
        if self.model is None:
            raise ValueError(
                "[!] No working Gemini model found! Tried: " + ", ".join(chain) +
                "\n    Check your API key and available models at https://aistudio.google.com"
            )
        
        self.chat = self.model.start_chat(history=[])

    def _build_groq_prompt(self, target, goal, knowledge_base, last_command, last_output, phase):
        """Build a focused prompt for Groq (limited context window)."""
        # Extract only essential KB info
        vulns = knowledge_base.get("vulnerabilities", [])
        ports = knowledge_base.get("open_ports", [])
        commands_run = knowledge_base.get("commands_executed", 0)
        
        kb_summary = ""
        if ports:
            kb_summary += f"Open Ports: {ports[:8]}\n"
        if vulns:
            kb_summary += f"Vulns Found: {[v.get('title','')[:40] for v in vulns[:5]]}\n"
        if commands_run:
            kb_summary += f"Commands run: {commands_run}\n"
        
        prompt = f"""You are ZenithAI - an elite autonomous penetration testing AI. You execute advanced security assessments using Python scripts.
Target: {target} | Phase: {phase}
Goal: {goal[:400]}

{kb_summary}
Last action: {last_command[:150] if last_command else 'None (first action)'}
Output (IMPORTANT - read carefully):
{last_output[:800] if last_output else 'None yet - start with recon'}

RULES:
1. ONLY use action "SCRIPT" with script_type "python". No COMMAND action.
2. Write self-contained Python scripts using requests, socket, subprocess, urllib, etc.
3. Read the LAST OUTPUT carefully - DO NOT repeat the same scan. Build on previous results.
4. If ports were found, scan services. If paths found, test them. If vulns found, exploit.
5. NEVER add proxychains/torsocks. Proxy is automatic.
6. If a tool is "not found", use pure Python instead (socket, urllib, requests).
7. Each script should do ONE focused task and print clear results.
8. If output says "PROXY IS DOWN" or "Connection refused through proxy" → the proxy is broken. Use DNS tools (dig, host via subprocess) that bypass proxy. The system will auto-disable proxy after 3 failures.
9. If output says "Proxy has been AUTO-DISABLED" → great, retry your HTTP approach with direct connections.

=== ADVANCED ATTACK MODULES (import and use in your scripts!) ===
from zenith.modules.idor_scanner import IDORScanner  # IDOR/BOLA testing - #1 bug bounty finding
from zenith.modules.ssrf_scanner import SSRFScanner  # SSRF - cloud metadata, internal services
from zenith.modules.jwt_attacks import JWTAttacker    # JWT alg:none, weak secret, kid injection
from zenith.modules.ssti_scanner import SSTIScanner   # SSTI - Jinja2, Twig, Freemarker → RCE
from zenith.modules.race_condition import RaceConditionTester  # Race conditions, double-spend

Usage example: scanner = IDORScanner('{target}'); results = scanner.scan()
Each module auto-discovers endpoints, tests payloads, and prints structured results.

CRITICAL: Output ONLY raw JSON. No markdown, no ``` blocks.

FORMAT:
{{"reasoning":"what and why","action":"SCRIPT","script_type":"python","script":"import socket\\nprint('hello')","phase":"{phase}","expected_outcome":"what to expect"}}

DONE FORMAT:
{{"reasoning":"summary","action":"GOAL_ACHIEVED","findings_summary":"all findings","phase":"REPORT"}}
"""
        return prompt

    def _build_gemini_prompt(self, target, goal, knowledge_base, last_command, last_output, phase):
        """Build full prompt for Gemini (larger context) - uses SCRIPT action for file-based scripts."""
        kb_json = json.dumps(knowledge_base, indent=2, default=str)[:3000]
        last_cmd_str = last_command if last_command else "None (this is your FIRST action)"
        last_out_str = last_output[:2000] if last_output else "None yet - begin reconnaissance"
        
        prompt = f"""You are ZenithAI - an elite autonomous penetration testing AI engine.
You analyze outputs carefully, choose the BEST next action, write Python scripts, execute them, read results, and plan next steps.

=== MISSION ===
Target: {target}
Goal: {goal[:2000]}
Phase: {phase}

=== KNOWLEDGE BASE ===
{kb_json}

=== LAST ACTION & OUTPUT (READ THIS CAREFULLY!) ===
Action: {last_cmd_str}
Output:
{last_out_str}

=== CRITICAL RULES ===
1. ALWAYS use action "SCRIPT" with script_type "python". This is the ONLY allowed action type.
2. NEVER use action "COMMAND". Everything must be a Python script.
3. READ THE LAST OUTPUT above. Do NOT repeat the same scan. Build on what you learned.
4. If ports were discovered → scan their services. If paths found → test them for vulns. If vulns found → exploit them.
5. Your Python scripts should be self-contained (import socket, requests, urllib, subprocess, etc.).
6. To use external tools like nmap, call them via subprocess.run() in your Python script.
7. NEVER add proxychains/torsocks. Proxy is handled automatically.
8. If a tool says "not found", use pure Python (socket, urllib) instead.
9. If connection refused through PROXY → the proxy/Tor is DOWN, not the target. Use DNS tools (dig, host via subprocess) that bypass proxy. System auto-disables proxy after 3 failures.
10. If output says "Proxy has been AUTO-DISABLED" → retry your HTTP approach, it will now use direct connections.
11. If connection refused WITHOUT proxy → target is blocking. Switch to passive OSINT (crt.sh, wayback, whois via Python).
10. Each script = ONE focused task. Print clear, structured results.

=== AVAILABLE TOOLS (call via subprocess from Python) ===
nmap, nikto, sqlmap, nuclei, ffuf, gobuster, curl, dig, whois, host, assetfinder, hydra, searchsploit, wpscan, sslscan, openssl, dirsearch, python3, bash

=== OUTPUT FORMAT (JSON ONLY - NO MARKDOWN!) ===

SCRIPT ACTION:
{{"reasoning":"Explain what you're doing and why based on previous results","action":"SCRIPT","script_type":"python","script":"import socket\\nprint('hello')","phase":"{phase}","expected_outcome":"What you expect to find"}}

GOAL ACHIEVED (when scan is complete):
{{"reasoning":"Summary of all findings","action":"GOAL_ACHIEVED","findings_summary":"Detailed list of all vulnerabilities and findings","phase":"REPORT"}}

PHASE SWITCH:
{{"reasoning":"Why switching phase","action":"SWITCH_PHASE","new_phase":"scan","phase":"scan"}}

=== ADVANCED ATTACK MODULES (import in your Python scripts!) ===
Zenith has built-in advanced security modules. Import and use them in your scripts:

1. IDOR Scanner (Insecure Direct Object Reference):
   from zenith.modules.idor_scanner import IDORScanner
   scanner = IDORScanner('{target}')
   results = scanner.scan()  # Auto-discovers API endpoints and tests ID manipulation

2. SSRF Scanner (Server-Side Request Forgery):
   from zenith.modules.ssrf_scanner import SSRFScanner
   scanner = SSRFScanner('{target}')
   results = scanner.scan()  # Tests AWS metadata, localhost, internal services

3. JWT Attacker (JSON Web Token Attacks):
   from zenith.modules.jwt_attacks import JWTAttacker
   attacker = JWTAttacker('{target}')
   results = attacker.scan()  # Tests alg:none, weak secrets, kid injection

4. SSTI Scanner (Server-Side Template Injection → RCE):
   from zenith.modules.ssti_scanner import SSTIScanner
   scanner = SSTIScanner('{target}')
   results = scanner.scan()  # Tests Jinja2, Twig, Freemarker, ERB, etc.

5. Race Condition Tester:
   from zenith.modules.race_condition import RaceConditionTester
   tester = RaceConditionTester('{target}')
   results = tester.scan()  # Tests double-spend, coupon reuse, rate limits

All modules accept optional cookies='...' and headers={{...}} parameters.
Use these for deep vulnerability testing - they are more thorough than manual scripts.

=== ADVANCED SCRIPT TIPS ===
- Use concurrent.futures.ThreadPoolExecutor for fast parallel scanning
- Use subprocess.run() with timeout parameter for external tools  
- Parse HTML with re module for web crawling
- Use socket for port scanning, banner grabbing
- Use urllib.request for HTTP requests (no install needed)
- Try 'requests' library first, fall back to urllib if not available
"""
        return prompt

    def think(self, target, goal, knowledge_base, last_command="", last_output="", phase="recon"):
        """
        AI thinks and decides the next action to take.
        
        Returns:
            dict: {"action": "COMMAND|ANALYZE|GOAL_ACHIEVED|SWITCH_PHASE", 
                   "command": "...", "reasoning": "...", "phase": "..."}
        """
        
        # Use shorter prompt for Groq to avoid 413 errors
        if self.provider == "groq":
            prompt = self._build_groq_prompt(target, goal, knowledge_base, last_command, last_output, phase)
        else:
            prompt = self._build_gemini_prompt(target, goal, knowledge_base, last_command, last_output, phase)

        try:
            self.call_count += 1
            
            # Call the appropriate provider
            if self.provider == "groq":
                raw_text = self._call_groq(prompt)
            else:
                raw_text = self._call_gemini(prompt)
            
            # Clean up response - remove markdown code blocks if present
            # Handle ```json ... ``` and ``` ... ``` blocks
            import re as _re
            # Strip all ```...``` code fences (greedy inner match)
            if "```" in raw_text:
                code_block = _re.search(r'```(?:json)?\s*\n?(.*?)\n?```', raw_text, _re.DOTALL)
                if code_block:
                    raw_text = code_block.group(1)
                else:
                    # Partial fence - strip prefix/suffix
                    if raw_text.startswith("```"):
                        raw_text = raw_text.split("\n", 1)[1] if "\n" in raw_text else raw_text[3:]
                    if raw_text.endswith("```"):
                        raw_text = raw_text[:-3]
            raw_text = raw_text.strip()
            # If there's text before the JSON object, strip it
            if raw_text and not raw_text.startswith("{"):
                json_start = raw_text.find("{")
                if json_start > 0:
                    raw_text = raw_text[json_start:]
            
            # ── Robust JSON parser with multiple fallback strategies ──
            import re as _re
            
            def _fix_json_escapes(text):
                """Fix invalid JSON escape sequences that AI produces."""
                def _replace_invalid(m):
                    return '\\\\' + m.group(1)
                return _re.sub(r'\\([^"\\/bfnrtu])', _replace_invalid, text)
            
            def _balanced_json_extract(text):
                """Extract the first balanced JSON object from text using brace counting."""
                start = text.find('{')
                if start == -1:
                    return None
                depth = 0
                in_string = False
                escape_next = False
                for i in range(start, len(text)):
                    c = text[i]
                    if escape_next:
                        escape_next = False
                        continue
                    if c == '\\' and in_string:
                        escape_next = True
                        continue
                    if c == '"' and not escape_next:
                        in_string = not in_string
                        continue
                    if in_string:
                        continue
                    if c == '{':
                        depth += 1
                    elif c == '}':
                        depth -= 1
                        if depth == 0:
                            return text[start:i+1]
                return None
            
            def _try_parse(text):
                """Try to parse JSON text, return dict or None."""
                if not text:
                    return None
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    pass
                try:
                    return json.loads(_fix_json_escapes(text))
                except json.JSONDecodeError:
                    pass
                return None
            
            # Strategy 1: Direct parse
            decision = _try_parse(raw_text)
            
            # Strategy 2: Extract balanced JSON object
            if decision is None:
                balanced = _balanced_json_extract(raw_text)
                if balanced:
                    decision = _try_parse(balanced)
            
            # Strategy 3: Greedy regex extract
            if decision is None:
                json_match = _re.search(r'\{.*\}', raw_text, _re.DOTALL)
                if json_match:
                    decision = _try_parse(json_match.group())
            
            # Strategy 4: Try to fix truncated JSON (missing closing braces)
            if decision is None and raw_text.count('{') > raw_text.count('}'):
                patched = raw_text + '}' * (raw_text.count('{') - raw_text.count('}'))
                decision = _try_parse(patched)
            
            # Final fallback
            if decision is None:
                print(f"    [DEBUG] JSON parse failed. Raw response (first 300 chars):")
                print(f"    [DEBUG] {raw_text[:300]}")
                decision = self._fallback_decision(target, phase)
            
            # Success - reset error counter
            self.consecutive_errors = 0
            return decision
            
        except Exception as e:
            error_msg = str(e)
            self.consecutive_errors += 1
            print(f"    [!] AI Error ({self.consecutive_errors}/{self.max_consecutive_errors}): {error_msg[:150]}")
            
            # MODEL NOT FOUND - fatal, don't retry with same model
            if "404" in error_msg or "not found" in error_msg.lower():
                print("    [!] Model not found! Attempting to switch model...")
                if self._try_switch_model():
                    self.consecutive_errors = 0
                    return self.think(target, goal, knowledge_base, last_command, last_output, phase)
                else:
                    return {
                        "reasoning": "FATAL: No working AI model found. Cannot continue scanning.",
                        "action": "GOAL_ACHIEVED",
                        "findings_summary": "Scan aborted - AI model not available. Check your API key and model availability.",
                        "phase": "REPORT"
                    }
            
            # RATE LIMITED - wait and retry (but respect max errors)
            if "429" in error_msg or "quota" in error_msg.lower():
                # Rate limit hit - ask user for new API key
                print(f"\n    {'='*50}")
                print(f"    ⚠️  RATE LIMIT HIT - API quota exhausted!")
                print(f"    {'='*50}")
                print(f"    Current API key: {self.api_key[:10]}...{self.api_key[-4:]}")
                print(f"    \n    Options:")
                print(f"    1. Enter new API key to continue")
                print(f"    2. Press Enter to wait 60s and retry")
                print(f"    3. Type 'quit' to stop scan")
                print()
                
                try:
                    user_input = input("    🔑 New API Key (or Enter to wait): ").strip()
                    
                    if user_input.lower() == 'quit':
                        return {
                            "reasoning": "User chose to stop scan after rate limit.",
                            "action": "GOAL_ACHIEVED",
                            "findings_summary": "Scan stopped by user after API rate limit.",
                            "phase": "REPORT"
                        }
                    elif user_input and len(user_input) > 20:
                        # User provided new API key
                        if self._switch_api_key(user_input):
                            print(f"    [✓] Switched to new API key! Continuing scan...")
                            self.consecutive_errors = 0
                            return self.think(target, goal, knowledge_base, last_command, last_output, phase)
                        else:
                            print(f"    [!] New API key failed. Waiting 60s and retrying with old key...")
                            time.sleep(60)
                            return self.think(target, goal, knowledge_base, last_command, last_output, phase)
                    else:
                        # User pressed Enter - wait and retry
                        print(f"    [*] Waiting 60 seconds before retry...")
                        time.sleep(60)
                        return self.think(target, goal, knowledge_base, last_command, last_output, phase)
                        
                except EOFError:
                    # Non-interactive mode - just wait
                    time.sleep(60)
                    return self.think(target, goal, knowledge_base, last_command, last_output, phase)
            
            # TOO MANY CONSECUTIVE ERRORS - stop
            if self.consecutive_errors >= self.max_consecutive_errors:
                print(f"    [!] {self.max_consecutive_errors} consecutive errors. Stopping scan.")
                return {
                    "reasoning": f"Too many consecutive AI errors ({self.consecutive_errors}). Last error: {error_msg[:100]}",
                    "action": "GOAL_ACHIEVED",
                    "findings_summary": "Scan stopped due to repeated AI errors. Check API key, quota, and model availability.",
                    "phase": "REPORT"
                }
            
            # Other errors - fallback action
            return self._fallback_decision(target, phase, f"AI error: {error_msg[:80]}")

    def _fallback_decision(self, target, phase, reason="JSON parse failed"):
        """Generate diverse Python SCRIPT fallbacks when AI fails.
        15+ unique scripts covering different recon/scan techniques."""
        if not hasattr(self, '_fallback_index'):
            self._fallback_index = 0
        
        fallback_options = [
            {
                "reasoning": f"{reason} - running Python TCP port scan.",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import socket, concurrent.futures\ntarget='{target}'\nports=list(range(1,1025))+[3306,3389,5432,5900,6379,8080,8443,8888,9090,27017]\ndef scan(p):\n    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n    s.settimeout(0.3)\n    r=s.connect_ex((target,p))\n    s.close()\n    return p if r==0 else None\nprint(f'=== TCP Port Scan: {{target}} ({{len(ports)}} ports) ===')\nwith concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:\n    results=[p for p in ex.map(scan,ports) if p]\nif results:\n    for p in sorted(results): print(f'[OPEN] Port {{p}}')\nelse:\n    print('No open ports found')\nprint(f'\\nScanned {{len(ports)}} ports, {{len(results)}} open')",
                "phase": phase, "expected_outcome": "Discover open ports via fast threaded TCP scan."
            },
            {
                "reasoning": f"{reason} - running Python HTTP headers + security check.",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import urllib.request, ssl, json\nctx=ssl._create_unverified_context()\ntarget='{target}'\nprint(f'=== HTTP Security Headers: {{target}} ===')\nfor proto in ['https','http']:\n    try:\n        r=urllib.request.urlopen(f'{{proto}}://{{target}}',context=ctx,timeout=10)\n        print(f'\\n[{{proto.upper()}}] Status: {{r.status}}')\n        print(f'Server: {{r.getheader(\"Server\",\"hidden\")}}')\n        security_headers=['Strict-Transport-Security','Content-Security-Policy','X-Frame-Options','X-Content-Type-Options','X-XSS-Protection','Permissions-Policy','Referrer-Policy']\n        for h in security_headers:\n            v=r.getheader(h)\n            status='✓ '+v[:60] if v else '✗ MISSING'\n            print(f'  {{h}}: {{status}}')\n        print(f'All headers: '+'\\n  '.join(f'{{k}}: {{v}}' for k,v in r.getheaders()))\n        break\n    except Exception as e:\n        print(f'[{{proto}}] Error: {{e}}')",
                "phase": phase, "expected_outcome": "HTTP headers and missing security headers."
            },
            {
                "reasoning": f"{reason} - running Python DNS + WHOIS recon.",
                "action": "SCRIPT", "script_type": "python",
                "script": "import socket, subprocess\ntarget='" + target + "'\nprint(f'=== DNS & Network Recon: {target} ===')\ntry:\n    ip=socket.gethostbyname(target)\n    print(f'IP: {ip}')\nexcept: ip='unknown'\ntry:\n    names=socket.getaddrinfo(target,None)\n    ips=set(a[4][0] for a in names)\n    print(f'All IPs: {ips}')\nexcept: pass\nfor cmd in [['dig',target,'ANY','+short'],['dig',target,'MX','+short'],['dig',target,'TXT','+short'],['dig',target,'NS','+short'],['whois',target]]:\n    try:\n        r=subprocess.run(cmd,capture_output=True,text=True,timeout=15)\n        if r.stdout.strip():\n            label=' '.join(cmd)\n            print(f'\\n--- {label} ---')\n            print(r.stdout[:500])\n    except: pass",
                "phase": phase, "expected_outcome": "DNS records, IP addresses, WHOIS data."
            },
            {
                "reasoning": f"{reason} - running Python web crawler + link extractor.",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import urllib.request, ssl, re, html.parser\nctx=ssl._create_unverified_context()\ntarget='{target}'\nprint(f'=== Web Crawler: {{target}} ===')\ntry:\n    r=urllib.request.urlopen(f'https://{{target}}',context=ctx,timeout=15)\n    body=r.read(50000).decode(errors='ignore')\n    links=set(re.findall(r'href=[\"\\']([^\"\\'>]+)',body))\n    forms=re.findall(r'<form[^>]*action=[\"\\']([^\"\\'>]*)[\"\\'][^>]*method=[\"\\']([^\"\\'>]*)',body,re.I)\n    scripts=set(re.findall(r'src=[\"\\']([^\"\\'>]+\\.js)',body))\n    emails=set(re.findall(r'[\\w.+-]+@[\\w-]+\\.[\\w.]+',body))\n    apis=set(l for l in links if any(k in l.lower() for k in ['api','graphql','rest','v1','v2','json','xml']))\n    print(f'Title: {{re.findall(r\"<title>(.*?)</title>\",body,re.I)}}')\n    print(f'\\nLinks found: {{len(links)}}')\n    for l in sorted(links)[:30]: print(f'  {{l}}')\n    if apis: print(f'\\nPotential API endpoints: {{apis}}')\n    if forms: print(f'\\nForms: {{forms}}')\n    if scripts: print(f'\\nJS files: {{scripts}}')\n    if emails: print(f'\\nEmails: {{emails}}')\nexcept Exception as e:\n    print(f'Error: {{e}}')",
                "phase": phase, "expected_outcome": "Links, forms, JS files, API endpoints from crawling."
            },
            {
                "reasoning": f"{reason} - running Python sensitive path scanner.",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import urllib.request, ssl, concurrent.futures\nctx=ssl._create_unverified_context()\ntarget='{target}'\npaths=['.env','.git/config','.git/HEAD','.gitignore','wp-config.php','robots.txt','sitemap.xml',\n  '.htaccess','web.config','crossdomain.xml','.well-known/security.txt',\n  'server-status','server-info','phpinfo.php','info.php','test.php',\n  'admin','administrator','login','wp-admin','wp-login.php','dashboard',\n  'api','api/v1','api/v2','graphql','swagger.json','openapi.json',\n  'actuator','actuator/env','actuator/health','debug','trace','console',\n  '.DS_Store','backup','backup.zip','backup.sql','db.sql','dump.sql',\n  'config.json','config.yaml','config.yml','package.json','composer.json']\ndef check(p):\n    try:\n        r=urllib.request.urlopen(f'https://{{target}}/{{p}}',context=ctx,timeout=5)\n        body=r.read(200).decode(errors='ignore')\n        return f'[{{r.status}}] /{{p}} ({{r.length}}b) {{body[:80]}}'\n    except urllib.error.HTTPError as e:\n        if e.code not in (404,403): return f'[{{e.code}}] /{{p}}'\n    except: pass\n    return None\nprint(f'=== Sensitive Path Scanner: {{target}} ({{len(paths)}} paths) ===')\nwith concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:\n    for r in ex.map(check,paths):\n        if r: print(r)\nprint('Done.')",
                "phase": phase, "expected_outcome": "Discover sensitive files, admin panels, API endpoints."
            },
            {
                "reasoning": f"{reason} - running Python SSL/TLS analysis.",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import ssl, socket, datetime\ntarget='{target}'\nprint(f'=== SSL/TLS Analysis: {{target}} ===')\ntry:\n    ctx=ssl.create_default_context()\n    ctx.check_hostname=False\n    ctx.verify_mode=ssl.CERT_NONE\n    with ctx.wrap_socket(socket.socket(),server_hostname=target) as s:\n        s.settimeout(10)\n        s.connect((target,443))\n        cert=s.getpeercert(binary_form=True)\n        cipher=s.cipher()\n        ver=s.version()\n        print(f'Protocol: {{ver}}')\n        print(f'Cipher: {{cipher}}')\n    ctx2=ssl.create_default_context()\n    try:\n        with ctx2.wrap_socket(socket.socket(),server_hostname=target) as s2:\n            s2.settimeout(10)\n            s2.connect((target,443))\n            cert_info=s2.getpeercert()\n            print(f'\\nCert Subject: {{cert_info.get(\"subject\")}}')\n            print(f'Issuer: {{cert_info.get(\"issuer\")}}')\n            print(f'Not After: {{cert_info.get(\"notAfter\")}}')\n            print(f'SANs: {{cert_info.get(\"subjectAltName\")}}')\n            exp=datetime.datetime.strptime(cert_info['notAfter'],'%b %d %H:%M:%S %Y %Z')\n            days=(exp-datetime.datetime.utcnow()).days\n            print(f'Expires in: {{days}} days')\n            if days<30: print('⚠ CERTIFICATE EXPIRING SOON!')\n    except ssl.SSLCertVerificationError as e:\n        print(f'⚠ CERT VERIFICATION FAILED: {{e}}')\nexcept Exception as e:\n    print(f'SSL Error: {{e}}')",
                "phase": phase, "expected_outcome": "SSL/TLS version, cipher, certificate details."
            },
            {
                "reasoning": f"{reason} - running Python subdomain discovery via crt.sh.",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import urllib.request, json, ssl\ntarget='{target}'\n# Strip subdomain to get root domain\nparts=target.split('.')\nroot='.'.join(parts[-2:]) if len(parts)>2 else target\nprint(f'=== Subdomain Discovery (crt.sh): {{root}} ===')\ntry:\n    ctx=ssl._create_unverified_context()\n    url=f'https://crt.sh/?q=%25.{{root}}&output=json'\n    r=urllib.request.urlopen(url,context=ctx,timeout=20)\n    data=json.loads(r.read())\n    subs=set()\n    for entry in data:\n        for name in entry.get('name_value','').split('\\n'):\n            name=name.strip().lower()\n            if name and '*' not in name:\n                subs.add(name)\n    print(f'Found {{len(subs)}} unique subdomains:')\n    for s in sorted(subs): print(f'  {{s}}')\nexcept Exception as e:\n    print(f'Error: {{e}}')",
                "phase": phase, "expected_outcome": "List of subdomains from Certificate Transparency logs."
            },
            {
                "reasoning": f"{reason} - running Python technology fingerprinter.",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import urllib.request, ssl, re\nctx=ssl._create_unverified_context()\ntarget='{target}'\nprint(f'=== Technology Fingerprint: {{target}} ===')\ntry:\n    req=urllib.request.Request(f'https://{{target}}',headers={{'User-Agent':'Mozilla/5.0'}})\n    r=urllib.request.urlopen(req,context=ctx,timeout=15)\n    headers=dict(r.getheaders())\n    body=r.read(100000).decode(errors='ignore')\n    techs=[]\n    if 'X-Powered-By' in headers: techs.append(('X-Powered-By',headers['X-Powered-By']))\n    if 'Server' in headers: techs.append(('Server',headers['Server']))\n    checks={{'WordPress':['wp-content','wp-includes'],'React':['react','__NEXT'],'Angular':['ng-version','angular'],'Vue':['vue.','__vue'],'Laravel':['laravel','csrf-token'],'Django':['csrfmiddlewaretoken','django'],'Express':['express'],'PHP':['<?php','.php'],'ASP.NET':['__VIEWSTATE','asp.net']}}\n    for tech,signs in checks.items():\n        for s in signs:\n            if s.lower() in body.lower() or s.lower() in str(headers).lower():\n                techs.append(('Framework',tech))\n                break\n    cookies=headers.get('Set-Cookie','')\n    if 'PHPSESSID' in cookies: techs.append(('Language','PHP'))\n    if 'JSESSIONID' in cookies: techs.append(('Language','Java'))\n    if 'ASP.NET' in cookies: techs.append(('Language','ASP.NET'))\n    metas=re.findall(r'<meta[^>]*name=[\"\\']generator[\"\\'][^>]*content=[\"\\']([^\"\\'>]+)',body,re.I)\n    for m in metas: techs.append(('Generator',m))\n    for t in techs: print(f'  {{t[0]}}: {{t[1]}}')\n    if not techs: print('  No technologies confidently identified')\nexcept Exception as e:\n    print(f'Error: {{e}}')",
                "phase": phase, "expected_outcome": "Detected web technologies, frameworks, languages."
            },
            {
                "reasoning": f"{reason} - running Python Nmap service scan via subprocess.",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import subprocess\ntarget='{target}'\nprint(f'=== Nmap Service Version Scan: {{target}} ===')\ntry:\n    r=subprocess.run(['nmap','-sV','-sC','-T4','--top-ports','200','-Pn',target],\n        capture_output=True,text=True,timeout=180)\n    print(r.stdout)\n    if r.stderr: print('Errors:',r.stderr[:300])\nexcept FileNotFoundError:\n    print('nmap not installed, using Python socket scan...')\n    import socket\n    for p in [21,22,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443]:\n        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(0.5)\n        if s.connect_ex((target,p))==0:\n            try: banner=s.recv(1024).decode(errors='ignore')[:100]\n            except: banner=''\n            print(f'Port {{p}}: OPEN {{banner}}')\n        s.close()\nexcept subprocess.TimeoutExpired:\n    print('Scan timed out after 180s')",
                "phase": phase, "expected_outcome": "Service versions and scripts output from Nmap."
            },
            {
                "reasoning": f"{reason} - running Python CORS + security misconfig checker.",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import urllib.request, ssl, json\nctx=ssl._create_unverified_context()\ntarget='{target}'\nprint(f'=== Security Misconfiguration Check: {{target}} ===')\n# CORS check\nfor origin in ['https://evil.com','null','https://'+target]:\n    try:\n        req=urllib.request.Request(f'https://{{target}}',headers={{'Origin':origin,'User-Agent':'Mozilla/5.0'}})\n        r=urllib.request.urlopen(req,context=ctx,timeout=10)\n        acao=r.getheader('Access-Control-Allow-Origin')\n        acac=r.getheader('Access-Control-Allow-Credentials')\n        if acao:\n            vuln='⚠ VULNERABLE' if acao=='*' or acao==origin else '✓ OK'\n            print(f'CORS Origin={{origin}}: ACAO={{acao}} ACAC={{acac}} {{vuln}}')\n    except: pass\n# Method check\nfor method in ['OPTIONS','PUT','DELETE','TRACE','PATCH']:\n    try:\n        req=urllib.request.Request(f'https://{{target}}',method=method)\n        r=urllib.request.urlopen(req,context=ctx,timeout=5)\n        print(f'HTTP {{method}}: {{r.status}} (allowed!)')\n        if method=='TRACE': print('⚠ TRACE enabled - XST possible!')\n    except urllib.error.HTTPError as e:\n        if e.code!=405: print(f'HTTP {{method}}: {{e.code}}')\n    except: pass\n# robots.txt\ntry:\n    r=urllib.request.urlopen(f'https://{{target}}/robots.txt',context=ctx,timeout=5)\n    content=r.read(2000).decode(errors='ignore')\n    print(f'\\nrobots.txt:\\n{{content}}')\nexcept: print('\\nNo robots.txt found')",
                "phase": phase, "expected_outcome": "CORS misconfigs, HTTP methods allowed, robots.txt."
            },
            {
                "reasoning": f"{reason} - running Python nuclei vulnerability scanner.",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import subprocess\ntarget='{target}'\nprint(f'=== Nuclei Vulnerability Scan: {{target}} ===')\ntry:\n    r=subprocess.run(['nuclei','-u',f'https://{{target}}','-severity','critical,high,medium',\n        '-silent','-nc','-timeout','10','-retries','1','-rl','50'],\n        capture_output=True,text=True,timeout=300)\n    if r.stdout.strip():\n        print('FINDINGS:')\n        print(r.stdout)\n    else:\n        print('No critical/high/medium vulnerabilities found by nuclei.')\n    if r.stderr and 'ERR' in r.stderr: print('Errors:',r.stderr[:200])\nexcept FileNotFoundError:\n    print('nuclei not installed. Trying nikto...')\n    try:\n        r=subprocess.run(['nikto','-h',f'https://{{target}}','-Tuning','1234567890abc','-timeout','10','-maxtime','120s'],\n            capture_output=True,text=True,timeout=180)\n        print(r.stdout[:3000])\n    except FileNotFoundError:\n        print('Neither nuclei nor nikto installed.')\nexcept subprocess.TimeoutExpired:\n    print('Scan timed out')",
                "phase": phase, "expected_outcome": "Known vulnerabilities from nuclei or nikto."
            },
            {
                "reasoning": f"{reason} - running Python ffuf directory brute-force.",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import subprocess, os\ntarget='{target}'\nprint(f'=== Directory Bruteforce: {{target}} ===')\nwordlists=['/usr/share/wordlists/dirb/common.txt','/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt','/usr/share/seclists/Discovery/Web-Content/common.txt']\nwl=None\nfor w in wordlists:\n    if os.path.exists(w): wl=w; break\nif not wl:\n    print('No wordlist found, using built-in list...')\n    paths=['admin','login','api','dashboard','config','backup','test','dev','staging','debug',\n      'console','portal','panel','manager','phpmyadmin','wp-admin','assets','static','uploads',\n      'images','css','js','fonts','includes','vendor','node_modules','.git','cgi-bin']\n    import urllib.request, ssl, concurrent.futures\n    ctx=ssl._create_unverified_context()\n    def check(p):\n        try:\n            r=urllib.request.urlopen(f'https://{{target}}/{{p}}',context=ctx,timeout=5)\n            return f'[{{r.status}}] /{{p}} ({{r.length}}b)'\n        except urllib.error.HTTPError as e:\n            if e.code not in (404,): return f'[{{e.code}}] /{{p}}'\n        except: pass\n    with concurrent.futures.ThreadPoolExecutor(15) as ex:\n        for r in ex.map(check,paths):\n            if r: print(r)\nelse:\n    print(f'Using wordlist: {{wl}}')\n    try:\n        r=subprocess.run(['ffuf','-u',f'https://{{target}}/FUZZ','-w',wl,'-mc','200,201,301,302,401,403','-t','50','-timeout','10','-s'],\n            capture_output=True,text=True,timeout=120)\n        if r.stdout.strip(): print(r.stdout[:3000])\n        else: print('No results from ffuf')\n    except FileNotFoundError:\n        print('ffuf not installed')\n    except subprocess.TimeoutExpired:\n        print('Timed out')",
                "phase": phase, "expected_outcome": "Discovered directories and files on the target."
            },
            {
                "reasoning": f"{reason} - running Python Wayback Machine URL discovery.",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import urllib.request, json, ssl\nctx=ssl._create_unverified_context()\ntarget='{target}'\nprint(f'=== Wayback Machine URL Discovery: {{target}} ===')\ntry:\n    url=f'https://web.archive.org/cdx/search/cdx?url=*.{{target}}/*&output=json&fl=original&collapse=urlkey&limit=100'\n    r=urllib.request.urlopen(url,context=ctx,timeout=20)\n    data=json.loads(r.read())\n    urls=set()\n    for row in data[1:]:\n        urls.add(row[0])\n    print(f'Found {{len(urls)}} archived URLs:')\n    for u in sorted(urls)[:50]: print(f'  {{u}}')\n    api_urls=[u for u in urls if any(k in u.lower() for k in ['api','json','xml','graphql','rest','v1','v2','webhook','callback'])]\n    if api_urls:\n        print(f'\\n⚡ Potential API URLs:')\n        for u in api_urls: print(f'  {{u}}')\nexcept Exception as e:\n    print(f'Error: {{e}}')",
                "phase": phase, "expected_outcome": "Historical URLs from Wayback Machine, potential API endpoints."
            },
            {
                "reasoning": f"{reason} - running Python SQL injection probe.",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import urllib.request, ssl, urllib.parse\nctx=ssl._create_unverified_context()\ntarget='{target}'\nprint(f'=== SQL Injection Probe: {{target}} ===')\npayloads=[\"'\",\"1' OR '1'='1\",\"1 OR 1=1\",\"' OR ''='\",\"1' AND '1'='2\",\"1; SELECT 1--\",\"' UNION SELECT NULL--\"]\ntest_paths=['/','/search?q=','login?user=','/api/user?id=','/product?id=','/page?id=']\nfor path in test_paths:\n    for payload in payloads:\n        url=f'https://{{target}}{{path}}{{urllib.parse.quote(payload)}}'\n        try:\n            req=urllib.request.Request(url,headers={{'User-Agent':'Mozilla/5.0'}})\n            r=urllib.request.urlopen(req,context=ctx,timeout=5)\n            body=r.read(5000).decode(errors='ignore').lower()\n            sql_errors=['sql syntax','mysql','sqlite','postgresql','oracle','sql server','syntax error','unclosed quotation','quoted string not properly terminated']\n            for err in sql_errors:\n                if err in body:\n                    print(f'⚠ POTENTIAL SQLi: {{url}}')\n                    print(f'  Error keyword: {{err}}')\n                    break\n        except urllib.error.HTTPError as e:\n            if e.code==500:\n                print(f'[500] Possible error-based SQLi: {{path}} + {{payload[:20]}}')\n        except: pass\nprint('SQLi probe complete.')",
                "phase": phase, "expected_outcome": "Potential SQL injection points based on error responses."
            },
            {
                "reasoning": f"{reason} - running Python XSS reflection scanner.",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import urllib.request, ssl, urllib.parse\nctx=ssl._create_unverified_context()\ntarget='{target}'\nprint(f'=== XSS Reflection Scanner: {{target}} ===')\ncanary='z3n1th7357'\ntest_params=['q','search','query','s','keyword','name','user','input','text','url','redirect','next','return','callback','ref']\nfor param in test_params:\n    url=f'https://{{target}}/?{{param}}={{canary}}'\n    try:\n        req=urllib.request.Request(url,headers={{'User-Agent':'Mozilla/5.0'}})\n        r=urllib.request.urlopen(req,context=ctx,timeout=5)\n        body=r.read(50000).decode(errors='ignore')\n        if canary in body:\n            count=body.count(canary)\n            print(f'⚠ REFLECTED: ?{{param}}={{canary}} ({{count}}x in response)')\n            # Check if it's in a dangerous context\n            import re\n            if re.search(f'<[^>]*{{canary}}',body): print(f'  → Inside HTML tag!')\n            if re.search(f'\"[^\"]*{{canary}}',body): print(f'  → Inside attribute!')\n            if re.search(f'<script[^>]*>[^<]*{{canary}}',body): print(f'  → Inside <script>!')\n    except: pass\nprint('XSS reflection scan complete.')",
                "phase": phase, "expected_outcome": "Parameters reflecting input - potential XSS vectors."
            },
            # ── Advanced Module-Based Fallbacks ──
            {
                "reasoning": f"{reason} - running IDOR/BOLA Scanner module (top bug bounty finding).",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import sys, os\nsys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath('.'))))\ntry:\n    from zenith.modules.idor_scanner import IDORScanner\n    scanner = IDORScanner('{target}')\n    results = scanner.scan()\n    if results:\n        print(f'\\n⚠ TOTAL IDOR FINDINGS: {{len(results)}}')\n        for r in results:\n            print(f'  [{{r.get(\"severity\",\"?\")}}] {{r.get(\"type\",\"\")}}: {{r.get(\"detail\",\"\")}}')\n    else:\n        print('No IDOR vulnerabilities found.')\nexcept ImportError:\n    print('Module import failed, running inline IDOR test...')\n    import urllib.request, ssl\n    ctx=ssl._create_unverified_context()\n    target='{target}'\n    for path in ['/api/v1/users/1','/api/v1/users/2','/api/user/1','/api/user/2','/api/account/1','/user/1','/profile/1']:\n        try:\n            r=urllib.request.urlopen(f'https://{{target}}{{path}}',context=ctx,timeout=5)\n            print(f'[{{r.status}}] {{path}} ({{r.length}}b)')\n        except Exception as e: print(f'[ERR] {{path}}: {{e}}')",
                "phase": phase, "expected_outcome": "IDOR/BOLA vulnerabilities via automatic ID manipulation."
            },
            {
                "reasoning": f"{reason} - running SSRF Scanner module (cloud metadata, internal services).",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import sys, os\nsys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath('.'))))\ntry:\n    from zenith.modules.ssrf_scanner import SSRFScanner\n    scanner = SSRFScanner('{target}')\n    results = scanner.scan()\n    if results:\n        print(f'\\n⚠ TOTAL SSRF FINDINGS: {{len(results)}}')\n        for r in results:\n            print(f'  [{{r.get(\"severity\",\"?\")}}] {{r.get(\"type\",\"\")}}: {{r.get(\"detail\",\"\")}}')\n    else:\n        print('No SSRF vulnerabilities found.')\nexcept ImportError:\n    print('Module import failed, running inline SSRF test...')\n    import urllib.request, ssl\n    ctx=ssl._create_unverified_context()\n    target='{target}'\n    ssrf_params=['url','uri','link','redirect','callback','fetch','load','proxy']\n    for param in ssrf_params:\n        for payload in ['http://169.254.169.254/latest/meta-data/','http://127.0.0.1/']:\n            try:\n                r=urllib.request.urlopen(f'https://{{target}}/?{{param}}={{payload}}',context=ctx,timeout=5)\n                body=r.read(500).decode(errors='ignore')\n                if any(w in body for w in ['ami-id','instance','root:']): print(f'⚠ SSRF: ?{{param}}={{payload}}')\n            except: pass",
                "phase": phase, "expected_outcome": "SSRF vulnerabilities via cloud metadata and internal service probing."
            },
            {
                "reasoning": f"{reason} - running JWT Attack module (alg:none, weak secrets).",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import sys, os\nsys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath('.'))))\ntry:\n    from zenith.modules.jwt_attacks import JWTAttacker\n    attacker = JWTAttacker('{target}')\n    results = attacker.scan()\n    if results:\n        print(f'\\n⚠ TOTAL JWT FINDINGS: {{len(results)}}')\n        for r in results:\n            print(f'  [{{r.get(\"severity\",\"?\")}}] {{r.get(\"type\",\"\")}}: {{r.get(\"detail\",\"\")}}')\n    else:\n        print('No JWT vulnerabilities found.')\nexcept ImportError:\n    print('Module import failed, running inline JWT check...')\n    import urllib.request, ssl, re\n    ctx=ssl._create_unverified_context()\n    target='{target}'\n    print(f'=== JWT Discovery: {{target}} ===')\n    for path in ['/','/api/auth/login','/login','/api/token']:\n        try:\n            r=urllib.request.urlopen(f'https://{{target}}{{path}}',context=ctx,timeout=5)\n            body=r.read(50000).decode(errors='ignore')\n            tokens=re.findall(r'eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*',body)\n            if tokens: print(f'JWT found at {{path}}: {{tokens[0][:60]}}...')\n        except: pass",
                "phase": phase, "expected_outcome": "JWT vulnerabilities - alg:none bypass, weak secrets, forged tokens."
            },
            {
                "reasoning": f"{reason} - running SSTI Scanner module (template injection → RCE).",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import sys, os\nsys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath('.'))))\ntry:\n    from zenith.modules.ssti_scanner import SSTIScanner\n    scanner = SSTIScanner('{target}')\n    results = scanner.scan()\n    if results:\n        print(f'\\n⚠ TOTAL SSTI FINDINGS: {{len(results)}}')\n        for r in results:\n            print(f'  [{{r.get(\"severity\",\"?\")}}] {{r.get(\"type\",\"\")}}: {{r.get(\"detail\",\"\")}}')\n    else:\n        print('No SSTI vulnerabilities found.')\nexcept ImportError:\n    print('Module import failed, running inline SSTI test...')\n    import urllib.request, ssl, urllib.parse\n    ctx=ssl._create_unverified_context()\n    target='{target}'\n    payloads=[('{{{{7*7}}}}','49'),('${{7*7}}','49'),('<%= 7*7 %>','49')]\n    params=['name','q','search','template','text','message','input']\n    for param in params:\n        for payload,expected in payloads:\n            try:\n                url=f'https://{{target}}/?{{param}}={{urllib.parse.quote(payload)}}'\n                r=urllib.request.urlopen(url,context=ctx,timeout=5)\n                body=r.read(50000).decode(errors='ignore')\n                if expected in body and payload not in body: print(f'⚠ SSTI: ?{{param}} with {{payload}} → {{expected}}')\n            except: pass",
                "phase": phase, "expected_outcome": "SSTI vulnerabilities - template injection leading to RCE."
            },
            {
                "reasoning": f"{reason} - running Race Condition Tester module (double-spend, rate limit bypass).",
                "action": "SCRIPT", "script_type": "python",
                "script": f"import sys, os\nsys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath('.'))))\ntry:\n    from zenith.modules.race_condition import RaceConditionTester\n    tester = RaceConditionTester('{target}')\n    results = tester.scan()\n    if results:\n        print(f'\\n⚠ TOTAL RACE CONDITION FINDINGS: {{len(results)}}')\n        for r in results:\n            print(f'  [{{r.get(\"severity\",\"?\")}}] {{r.get(\"type\",\"\")}}: {{r.get(\"detail\",\"\")}}')\n    else:\n        print('No race condition vulnerabilities found.')\nexcept ImportError:\n    print('Module import failed, running inline rate limit test...')\n    import urllib.request, ssl, concurrent.futures, time\n    ctx=ssl._create_unverified_context()\n    target='{target}'\n    print(f'=== Rate Limit Test: {{target}} ===')\n    def fire(i):\n        try:\n            r=urllib.request.urlopen(f'https://{{target}}/',context=ctx,timeout=5)\n            return r.status\n        except: return 0\n    with concurrent.futures.ThreadPoolExecutor(20) as ex:\n        results=list(ex.map(fire,range(30)))\n    success=sum(1 for r in results if r==200)\n    print(f'Concurrent test: {{success}}/30 requests succeeded')\n    if success>=25: print('⚠ No rate limiting detected!')",
                "phase": phase, "expected_outcome": "Race conditions, double-spend, rate limit bypass."
            },
        ]
        # Rotate through options sequentially to avoid duplicates
        choice = fallback_options[self._fallback_index % len(fallback_options)]
        self._fallback_index += 1
        return choice

    def _call_groq(self, prompt):
        """Call Groq API and return response text."""
        # Truncate prompt if too long (Groq has ~8k context for llama models)
        if len(prompt) > 6000:
            prompt = prompt[:6000] + "\n...[truncated]...\nRespond with JSON only."
        
        # Build messages with system message for JSON compliance
        system_msg = {
            "role": "system",
            "content": "You are a pentesting AI assistant. You MUST respond with ONLY a single valid JSON object. No markdown, no explanations, no code fences. Just raw JSON."
        }
        
        # Add current prompt to chat history
        self.chat_history.append({"role": "user", "content": prompt})
        
        # Keep only last 4 user/assistant messages to avoid context overflow
        if len(self.chat_history) > 4:
            self.chat_history = self.chat_history[-4:]
        
        # Always prepend system message (not in history to save space)
        messages = [system_msg] + self.chat_history
        
        response = self.groq_client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            max_tokens=2048,
            temperature=0.7,
            response_format={"type": "json_object"},
        )
        
        assistant_msg = response.choices[0].message.content
        self.chat_history.append({"role": "assistant", "content": assistant_msg})
        
        return assistant_msg.strip()
    
    def _call_gemini(self, prompt):
        """Call Gemini API and return response text."""
        response = self.chat.send_message(prompt)
        return response.text.strip()

    def _switch_api_key(self, new_api_key):
        """
        Switch to a new API key and reinitialize the model.
        Returns True if successful, False if the key doesn't work.
        """
        try:
            print(f"    [*] Testing new API key: {new_api_key[:10]}...{new_api_key[-4:]}")
            
            # Auto-detect provider for new key
            if new_api_key.startswith("gsk_"):
                return self._switch_to_groq(new_api_key)
            
            # Default to Gemini
            genai.configure(api_key=new_api_key)
            
            # Try to create a model and test it
            candidate = genai.GenerativeModel(
                model_name=self.model_name if self.provider == "gemini" else "gemini-2.5-flash",
                generation_config={
                    "temperature": 0.7,
                    "top_p": 0.95,
                    "top_k": 40,
                    "max_output_tokens": 8192,
                },
                safety_settings=[
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                ]
            )
            
            # Test the new key
            test_resp = candidate.generate_content("Reply with OK")
            _ = test_resp.text
            
            # Success! Update everything
            self.api_key = new_api_key
            self.provider = "gemini"
            self.model = candidate
            self.chat = self.model.start_chat(history=[])
            print(f"    [✓] New Gemini API key is working!")
            return True
            
        except Exception as e:
            print(f"    [!] New API key failed: {str(e)[:100]}")
            # Revert to old key
            if self.provider == "gemini":
                genai.configure(api_key=self.api_key)
            return False
    
    def _switch_to_groq(self, new_api_key):
        """Switch to Groq provider with new key."""
        if not GROQ_AVAILABLE:
            print("    [!] Groq library not installed. Run: pip install groq")
            return False
        
        try:
            new_client = Groq(api_key=new_api_key)
            
            # Test the key
            for model_name in self.GROQ_MODELS:
                try:
                    response = new_client.chat.completions.create(
                        model=model_name,
                        messages=[{"role": "user", "content": "Reply with OK"}],
                        max_tokens=10
                    )
                    _ = response.choices[0].message.content
                    
                    # Success!
                    self.api_key = new_api_key
                    self.provider = "groq"
                    self.groq_client = new_client
                    self.model_name = model_name
                    self.chat_history = []
                    print(f"    [✓] Switched to Groq/{model_name}!")
                    return True
                except:
                    continue
            
            print("    [!] Groq key failed on all models")
            return False
        except Exception as e:
            print(f"    [!] Groq switch failed: {str(e)[:80]}")
            return False

    def _try_switch_model(self):
        """
        Try to switch to a different working model.
        Returns True if successful, False if no model works.
        """
        if self.provider == "groq":
            # Try other Groq models
            for model_name in self.GROQ_MODELS:
                if model_name == self.model_name:
                    continue
                try:
                    print(f"    [*] Trying Groq fallback: {model_name}...")
                    response = self.groq_client.chat.completions.create(
                        model=model_name,
                        messages=[{"role": "user", "content": "Reply with OK"}],
                        max_tokens=10
                    )
                    _ = response.choices[0].message.content
                    self.model_name = model_name
                    self.chat_history = []
                    print(f"    [✓] Switched to Groq model: {model_name}")
                    return True
                except Exception:
                    continue
            print("    [!] No fallback Groq model available!")
            return False
        
        # Gemini fallback
        all_models = []
        for chain in self.MODEL_CHAINS.values():
            for m in chain:
                if m != self.model_name and m not in all_models:
                    all_models.append(m)
        
        for model_name in all_models:
            try:
                print(f"    [*] Trying fallback model: {model_name}...")
                candidate = genai.GenerativeModel(
                    model_name=model_name,
                    generation_config={
                        "temperature": 0.7,
                        "top_p": 0.95,
                        "top_k": 40,
                        "max_output_tokens": 8192,
                    },
                    safety_settings=[
                        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                    ]
                )
                test_resp = candidate.generate_content("Reply with OK")
                _ = test_resp.text
                
                self.model = candidate
                self.model_name = model_name
                self.chat = self.model.start_chat(history=[])
                print(f"    [✓] Switched to model: {model_name}")
                return True
            except Exception:
                continue
        
        print("    [!] No fallback model available!")
        return False

    def analyze_findings(self, knowledge_base, target, goal):
        """
        AI analyzes all findings and generates a comprehensive report.
        """
        # Truncate KB for Groq (small context) vs Gemini (large context)
        max_kb = 2000 if self.provider == "groq" else 10000
        kb_str = json.dumps(knowledge_base, indent=2, default=str)[:max_kb]
        
        prompt = f"""
Analyze all the security findings from this penetration test and create a detailed report.

Target: {target}
Goal: {goal}

Knowledge Base:
{kb_str}

Create a comprehensive security report in this JSON format:
{{
    "executive_summary": "Brief overview",
    "target": "{target}",
    "total_vulnerabilities": number,
    "critical_findings": [
        {{"title": "", "severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO", "description": "", "evidence": "", "recommendation": ""}}
    ],
    "all_findings": [
        {{"title": "", "severity": "", "description": "", "evidence": "", "recommendation": ""}}
    ],
    "open_ports": [],
    "technologies_detected": [],
    "recommendations": [],
    "risk_rating": "CRITICAL/HIGH/MEDIUM/LOW"
}}

Output ONLY the JSON object.
"""
        try:
            # Call appropriate provider
            if self.provider == "groq":
                raw_text = self._call_groq(prompt)
            else:
                response = self.model.generate_content(prompt)
                raw_text = response.text.strip()
            
            if raw_text.startswith("```"):
                raw_text = raw_text.split("\n", 1)[1] if "\n" in raw_text else raw_text[3:]
            if raw_text.endswith("```"):
                raw_text = raw_text[:-3]
            
            return json.loads(raw_text.strip())
        except Exception as e:
            return {
                "executive_summary": f"Auto-analysis failed: {e}",
                "findings": knowledge_base.get("vulnerabilities", []),
                "risk_rating": "UNKNOWN"
            }

    def get_stats(self):
        """Return AI usage statistics."""
        return {
            "provider": self.provider.upper(),
            "model": self.model_name,
            "total_calls": self.call_count,
        }
