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

    SUPPORTED_MODELS = {
        "pro": "gemini-2.5-pro-preview-06-05",
        "flash": "gemini-2.5-flash-preview-05-20",
    }

    def __init__(self, api_key, model_choice="flash"):
        """
        Initialize AI Brain.
        
        Args:
            api_key: Gemini API key
            model_choice: 'pro' for deep thinking, 'flash' for speed
        """
        if not api_key or api_key == "":
            raise ValueError("[!] Gemini API Key is required! Please provide your API key.")
        
        genai.configure(api_key=api_key)
        
        model_name = self.SUPPORTED_MODELS.get(model_choice, self.SUPPORTED_MODELS["flash"])
        
        self.model = genai.GenerativeModel(
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
        
        self.chat = self.model.start_chat(history=[])
        self.model_name = model_name
        self.total_tokens = 0
        self.call_count = 0
        
        print(f"    [✓] AI Brain initialized: {model_name}")

    def think(self, target, goal, knowledge_base, last_command="", last_output="", phase="recon"):
        """
        AI thinks and decides the next action to take.
        
        Returns:
            dict: {"action": "COMMAND|ANALYZE|GOAL_ACHIEVED|SWITCH_PHASE", 
                   "command": "...", "reasoning": "...", "phase": "..."}
        """
        
        prompt = f"""
You are ZenithAI, an expert autonomous security assessment agent operating on a Linux system.
You are conducting an AUTHORIZED penetration test / vulnerability assessment.

=== CURRENT MISSION ===
Target: {target}
Goal: {goal}
Current Phase: {phase}

=== KNOWLEDGE BASE (What you know so far) ===
{json.dumps(knowledge_base, indent=2, default=str)}

=== LAST ACTION ===
Command executed: {last_command if last_command else "None yet - this is the first action"}
Output received:
{last_output[:3000] if last_output else "No output yet"}

=== YOUR TASK ===
Analyze everything you know and decide the SINGLE BEST next action.

PHASES you should follow:
1. RECON - Discover information (nmap, whatweb, subfinder, dig, whois, curl headers)
2. SCAN - Scan for vulnerabilities (nikto, nuclei, sqlmap test, directory bruteforce)
3. EXPLOIT - Try to exploit found vulnerabilities
4. POST_EXPLOIT - After getting access, escalate privileges, find sensitive data
5. REPORT - Summarize all findings

RULES:
- Output ONLY valid JSON, no markdown, no explanation outside JSON
- One command at a time
- If a tool is not installed, install it first (apt install, pip install, go install)
- Read and analyze the output carefully before deciding next step
- If you're stuck or a command fails, try a different approach
- Think about what information you still need
- Be thorough - check everything

RESPOND WITH THIS EXACT JSON FORMAT:
{{
    "reasoning": "Brief explanation of your thinking",
    "action": "COMMAND",
    "command": "the exact linux command to run",
    "phase": "current phase name",
    "expected_outcome": "what you expect to find"
}}

OR if the goal is achieved:
{{
    "reasoning": "Summary of what was accomplished",
    "action": "GOAL_ACHIEVED",
    "findings_summary": "Complete summary of all vulnerabilities and findings",
    "phase": "REPORT"
}}

OR to switch phase:
{{
    "reasoning": "Why switching phase",
    "action": "SWITCH_PHASE",
    "new_phase": "next phase name",
    "phase": "current phase"
}}

IMPORTANT: Output ONLY the JSON object. No other text.
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
            
            return decision
            
        except Exception as e:
            error_msg = str(e)
            print(f"    [!] AI Error: {error_msg}")
            
            if "429" in error_msg or "quota" in error_msg.lower():
                print("    [!] Rate limit hit, waiting 30 seconds...")
                time.sleep(30)
                return self.think(target, goal, knowledge_base, last_command, last_output, phase)
            
            # Fallback action
            return {
                "reasoning": f"AI error occurred: {error_msg}. Falling back to basic scan.",
                "action": "COMMAND",
                "command": f"nmap -sV {target}",
                "phase": "recon",
                "expected_outcome": "Basic port scan"
            }

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
