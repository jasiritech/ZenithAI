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

=== RULE #1: READ THE GOAL CAREFULLY! ===
The user's GOAL may contain important information like:
- Previous scan results (ports, services, versions)
- Known vulnerabilities (CVEs, misconfigs)
- Credentials or usernames found
- Technology stack details

**IF THE GOAL CONTAINS SCAN RESULTS OR VULN INFO:**
- DO NOT repeat recon! Skip whatweb, nmap, etc.
- GO DIRECTLY TO EXPLOITATION based on the info provided!
- Use the exact versions/ports/vulns mentioned in the goal

=== TOOL SYNTAX (CORRECT COMMANDS!) ===
NUCLEI (CVE scanning):
  nuclei -u https://target.com -tags cve -silent
  nuclei -u https://target.com -t /path/to/template.yaml
  (Note: -t cves,vulnerabilities is WRONG - use -tags or template path)

HTTPX (http probing) - USE ECHO PIPE:
  echo "https://target.com" | httpx -silent -status-code -title
  (Note: httpx https://url -title is WRONG on some versions)

WAFW00F (WAF detection):
  wafw00f https://target.com
  (Note: -H flag is WRONG - wafw00f doesn't take -H)

FFUF (fuzzing):
  ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302

WPSCAN (WordPress):
  wpscan --url https://target.com --enumerate u,vp,vt --plugins-detection aggressive

SQLMAP:
  sqlmap -u "https://target.com/page?id=1" --batch --dbs --threads=10

SEARCHSPLOIT:
  searchsploit mysql 5.7
  searchsploit exim 4.99
  searchsploit openssh 7.4

=== EXPLOIT STRATEGIES BASED ON COMMON VULNS ===
MySQL 5.7.x (EOL): searchsploit mysql 5.7 | Try default creds: mysql -h IP -u root -p
Exim 4.99.x: searchsploit exim | CVE-2019-15846, CVE-2019-16928
OpenSSH 7.4: Usually safe, but try ssh enum users
WordPress admin user: Try wp-admin with common passwords, XML-RPC brute
Apache: Check mod_status, server-info, .htaccess leaks

=== CRITICAL RULES ===
1. READ THE GOAL - if it contains vuln info, EXPLOIT IT directly!
2. Don't repeat scans that are already in the goal/knowledge base
3. Use CORRECT tool syntax (see above)
4. Prioritize: Exploits > Misconfigs > Brute-force
5. If something fails, try different approach immediately

=== CURRENT MISSION ===
Target: {target}
Goal: {goal[:4000]}
Phase: {phase}

=== KNOWLEDGE BASE ===
{json.dumps(knowledge_base, indent=2, default=str)[:2500]}

=== LAST ACTION ===
Command: {last_command if last_command else "None yet"}
Output: {last_output[:1500] if last_output else "No output yet"}

=== DECISION LOGIC ===
1. IF goal contains vuln info (MySQL 5.7, Exim 4.99, admin user, etc.):
   → Skip recon, go directly to: searchsploit, exploit attempts, cred attacks
   
2. IF goal is generic (find vulns, full scan):
   → Start with fast recon: nmap --top-ports 50, whatweb
   
3. IF last command failed:
   → Try different tool/syntax, don't repeat same mistake

=== JSON RESPONSE FORMAT ===
{{
    "reasoning": "Brief explanation (max 50 words)",
    "action": "COMMAND",
    "command": "linux command with CORRECT syntax",
    "phase": "{phase}",
    "expected_outcome": "what you expect"
}}

OR if goal achieved:
{{
    "reasoning": "Summary",
    "action": "GOAL_ACHIEVED", 
    "findings_summary": "All vulns found/exploited",
    "phase": "REPORT"
}}

CRITICAL: 
- Read the GOAL first! Use info provided!
- Use CORRECT tool syntax (see examples above)
- Output ONLY valid JSON
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
            return {
                "reasoning": f"AI error occurred: {error_msg[:100]}. Falling back to basic scan.",
                "action": "COMMAND",
                "command": f"nmap -sV {target}",
                "phase": "recon",
                "expected_outcome": "Basic port scan"
            }

    def _switch_api_key(self, new_api_key):
        """
        Switch to a new API key and reinitialize the model.
        Returns True if successful, False if the key doesn't work.
        """
        try:
            print(f"    [*] Testing new API key: {new_api_key[:10]}...{new_api_key[-4:]}")
            
            # Configure with new key
            genai.configure(api_key=new_api_key)
            
            # Try to create a model and test it
            candidate = genai.GenerativeModel(
                model_name=self.model_name,
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
            self.model = candidate
            self.chat = self.model.start_chat(history=[])
            print(f"    [✓] New API key is working!")
            return True
            
        except Exception as e:
            print(f"    [!] New API key failed: {str(e)[:100]}")
            # Revert to old key
            genai.configure(api_key=self.api_key)
            return False

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
