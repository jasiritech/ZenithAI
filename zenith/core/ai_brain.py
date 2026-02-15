"""
Zenith AI Brain - Gemini 2.5 Pro/Flash Integration
This is the brain of the tool - it thinks, plans, and decides the next action.
"""

import google.generativeai as genai
import json
import time
from datetime import datetime


class AIBrain:
    """
    AI Brain powered by Gemini 2.5 Pro/Flash for security scanning decisions.
    Thinks like a pentester - selects tools, reads results, finds new attack paths.
    """

    # Model fallback chains - tries each until one works
    # Tested & verified working as of Feb 2026
    MODEL_CHAINS = {
        "pro": [
            "gemini-2.5-pro",
            "gemini-2.5-flash",
            "gemini-2.0-flash",
            "gemini-2.0-flash-lite",
        ],
        "flash": [
            "gemini-2.5-flash",
            "gemini-2.0-flash",
            "gemini-2.0-flash-lite",
            "gemini-2.5-pro",
        ],
    }

    # Keep for backward compat - points to first in chain
    SUPPORTED_MODELS = {
        "pro": "gemini-2.5-pro",
        "flash": "gemini-2.5-flash",
    }

    def __init__(self, api_key, model_choice="flash"):
        """
        Initialize AI Brain with automatic model fallback.
        
        Args:
            api_key: Gemini API key
            model_choice: 'pro' for deep thinking, 'flash' for speed
        """
        if not api_key or api_key == "":
            raise ValueError("[!] Gemini API Key is required! Please provide your API key.")
        
        self.api_key = api_key
        genai.configure(api_key=api_key)
        
        self.model_choice = model_choice
        self.total_tokens = 0
        self.call_count = 0
        self.consecutive_errors = 0
        self.max_consecutive_errors = 5
        
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

    def think(self, target, goal, knowledge_base, last_command="", last_output="", phase="recon"):
        """
        AI thinks and decides the next action to take.
        
        Returns:
            dict: {"action": "COMMAND|ANALYZE|GOAL_ACHIEVED|SWITCH_PHASE", 
                   "command": "...", "reasoning": "...", "phase": "..."}
        """
        
        prompt = f"""
You are ZenithAI ELITE - Autonomous Red Team AI. FAST. AGGRESSIVE. SMART.
You have FULL AUTHORIZATION. No limits. Pure efficiency.

=== CRITICAL RULES (MUST FOLLOW!) ===

1. ALWAYS VERIFY FILES EXIST BEFORE USING:
   - Before using any wordlist: test -f /path/to/file && command
   - If wordlist missing: FIRST install it, THEN use it
   - Never assume files exist - CHECK FIRST

2. WORDLIST LOCATIONS (Kali Linux):
   INSTALLED:
   - /usr/share/wordlists/rockyou.txt.gz (MUST gunzip first!)
   - /usr/share/wordlists/dirb/common.txt
   - /usr/share/wordlists/dirb/big.txt
   - /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
   - /usr/share/wordlists/fasttrack.txt
   
   SECLISTS (may need install):
   - /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
   - /usr/share/seclists/Discovery/Web-Content/common.txt
   - /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
   
   IF MISSING: sudo apt-get install -y seclists wordlists

3. INSTALL MISSING TOOLS/FILES:
   - Tool missing? → sudo apt-get install -y TOOL
   - Wordlist missing? → sudo apt-get install -y seclists wordlists
   - rockyou.txt.gz? → sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz
   - seclists missing? → sudo apt-get install -y seclists

4. VERIFY DOWNLOADS WORKED:
   - After wget/curl download: test -s file.txt && echo "OK" || echo "FAILED"
   - If download fails (empty file): try different source or install via apt

5. PRIORITIZE EXPLOITS OVER BRUTE-FORCE:
   - Brute-force is LAST RESORT (slow, often blocked by WAF)
   - FIRST: Check for known CVEs (nuclei, searchsploit)
   - SECOND: Check for misconfigurations (default creds, exposed files)
   - THIRD: Test injection points (SQLi, XSS, LFI, RCE)
   - LAST: Brute-force only if no other option and credentials are known

6. SMART WORDPRESS ATTACKS:
   - FIRST: wpscan --url TARGET --enumerate u,vp,vt --plugins-detection aggressive (NO API KEY NEEDED for basic scan!)
   - Check plugin versions against CVE databases
   - Look for /wp-content/debug.log, /wp-config.php.bak, /.git
   - XML-RPC abuse: curl -X POST TARGET/xmlrpc.php -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'

7. SPEED RULES:
   - NEVER run nmap -p- → Use --top-ports 100 or -F
   - NEVER use slow wordlists (rockyou has 14M lines!) → Use small lists first
   - If command takes >60s with no output → KILL IT and try different approach
   - Chain commands: cmd1 && cmd2

=== CURRENT MISSION ===
Target: {target}
Goal: {goal}
Phase: {phase}

=== KNOWLEDGE BASE ===
{json.dumps(knowledge_base, indent=2, default=str)[:3000]}

=== LAST ACTION ===
Command: {last_command if last_command else "None yet"}
Output: {last_output[:2000] if last_output else "No output yet"}

=== FILE CHECK PATTERN ===
Before using wordlist: test -f /path/file && hydra ... -P /path/file || echo "File missing, installing..."
Install if missing: sudo apt-get install -y seclists && hydra ...

=== JSON RESPONSE FORMAT ===
{{
    "reasoning": "Brief explanation (max 50 words)",
    "action": "COMMAND",
    "command": "linux command (use test -f for wordlists!)",
    "phase": "{phase}",
    "expected_outcome": "what you expect"
}}

OR if goal achieved:
{{
    "reasoning": "Summary",
    "action": "GOAL_ACHIEVED",
    "findings_summary": "All vulns found",
    "phase": "REPORT"
}}

CRITICAL: Verify files exist! Install missing tools! Prioritize exploits over brute-force!
Output ONLY JSON.
"""

        try:
            self.call_count += 1
            response = self.chat.send_message(prompt)
            raw_text = response.text.strip()
            
            # Clean up response - remove markdown code blocks if present
            if raw_text.startswith("```"):
                raw_text = raw_text.split("\n", 1)[1] if "\n" in raw_text else raw_text[3:]
            if raw_text.endswith("```"):
                raw_text = raw_text[:-3]
            raw_text = raw_text.strip()
            
            # Parse JSON
            try:
                decision = json.loads(raw_text)
            except json.JSONDecodeError:
                # Try to extract JSON from the response
                import re
                json_match = re.search(r'\{.*\}', raw_text, re.DOTALL)
                if json_match:
                    decision = json.loads(json_match.group())
                else:
                    decision = {
                        "reasoning": "Failed to parse AI response, retrying with basic scan",
                        "action": "COMMAND",
                        "command": f"nmap -sV -sC {target}",
                        "phase": phase,
                        "expected_outcome": "Basic port scan results"
                    }
            
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
                if self.consecutive_errors < self.max_consecutive_errors:
                    wait_time = min(30 * self.consecutive_errors, 120)
                    print(f"    [!] Rate limit hit, waiting {wait_time} seconds...")
                    time.sleep(wait_time)
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
            return {
                "reasoning": f"AI error occurred: {error_msg[:100]}. Falling back to basic scan.",
                "action": "COMMAND",
                "command": f"nmap -sV {target}",
                "phase": "recon",
                "expected_outcome": "Basic port scan"
            }

    def _try_switch_model(self):
        """
        Try to switch to a different working model.
        Returns True if successful, False if no model works.
        """
        # Build a list of all models we haven't tried yet
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
        prompt = f"""
Analyze all the security findings from this penetration test and create a detailed report.

Target: {target}
Goal: {goal}

Full Knowledge Base:
{json.dumps(knowledge_base, indent=2, default=str)}

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
            "model": self.model_name,
            "total_calls": self.call_count,
        }
