"""
Zenith Strategy Manager — Tracks attack progress, failed approaches, 
discovered surfaces, and suggests intelligent next moves.

This is the "memory & brain" that makes ZenithAI a REAL autonomous agent
instead of a simple scanner. It remembers everything, knows what hasn't
been tried, and escalates when stuck.
"""

import time
import json
from typing import List, Dict, Optional, Set
from datetime import datetime


class StrategyManager:
    """
    Intelligent attack strategy tracker.
    
    Maintains full state of the penetration test:
    - What approaches have been tried
    - What failed and why
    - What attack surfaces were discovered but not yet explored
    - Current escalation level (1-7)
    - Whether the agent is "stuck" (no progress for N iterations)
    
    Provides rich context to the AI for intelligent decision-making.
    """

    # Escalation levels with descriptions
    ESCALATION_LEVELS = {
        1: {
            "name": "Standard Recon",
            "description": "Port scanning, subdomain enum, tech fingerprinting, standard vuln scans",
            "tools": ["nmap", "nikto", "nuclei", "dig", "whois", "curl"],
        },
        2: {
            "name": "Deep Crawling & Fuzzing",
            "description": "Directory brute-force, parameter mining, hidden endpoint discovery, API fuzzing",
            "tools": ["ffuf", "gobuster", "dirsearch", "wfuzz", "paramspider"],
        },
        3: {
            "name": "Targeted Exploitation",
            "description": "SQLi, XSS, SSRF, SSTI, IDOR, JWT attacks, file inclusion, command injection",
            "tools": ["sqlmap", "IDORScanner", "SSRFScanner", "SSTIScanner", "JWTAttacker"],
        },
        4: {
            "name": "OSINT & Intelligence",
            "description": "crt.sh, Wayback Machine, GitHub dorks, leaked credentials, Shodan, email harvest",
            "tools": ["crt.sh", "wayback", "github_dorks", "theHarvester", "shodan"],
        },
        5: {
            "name": "Advanced & Custom Exploits",
            "description": "Race conditions, timing attacks, deserialization, prototype pollution, custom scripts",
            "tools": ["RaceConditionTester", "custom_python", "timing_attacks"],
        },
        6: {
            "name": "Supply Chain & Infrastructure",
            "description": "JS library CVEs, outdated CMS exploits, DNS zone transfer, cloud misconfig, S3 buckets",
            "tools": ["retire.js", "wpscan", "dns_zone", "cloud_enum", "s3scanner"],
        },
        7: {
            "name": "Full Offensive",
            "description": "Brute force, credential stuffing, WAF bypass, chained exploits, persistence",
            "tools": ["hydra", "waf_bypass", "chained_exploits", "reverse_shell"],
        },
    }

    def __init__(self, target: str, max_escalation: int = 7):
        self.target = target
        self.max_escalation = min(max_escalation, 7)
        self.start_time = time.time()
        
        # Attack tracking
        self.tried_approaches: List[Dict] = []       # All attempts with results
        self.failed_approaches: List[Dict] = []       # Failed attempts with reasons
        self.successful_approaches: List[Dict] = []   # Approaches that found something
        
        # Surface tracking
        self.discovered_surfaces: List[Dict] = []     # All found attack surfaces
        self.explored_surfaces: Set[str] = set()      # Already explored
        self.unexplored_surfaces: List[Dict] = []     # Found but not yet attacked
        
        # Findings
        self.findings: List[Dict] = []                # Actual vulnerabilities
        self.info_gathered: List[Dict] = []           # Non-vuln intel (tech, versions, etc.)
        
        # State
        self.escalation_level: int = 1
        self.stuck_counter: int = 0
        self.total_iterations: int = 0
        self.last_progress_iteration: int = 0
        self.user_guidance: Optional[str] = None       # User-provided hints
        
        # WAF/Defense tracking
        self.detected_defenses: List[str] = []        # ["cloudflare", "modsecurity"]
        self.bypass_attempts: Dict[str, int] = {}     # defense → attempt count

    def record_attempt(self, approach: str, category: str, result: str, 
                       found_something: bool, new_surfaces: List[Dict] = None,
                       new_findings: List[Dict] = None, new_info: List[Dict] = None,
                       blocked_by: str = None):
        """
        Record an attack attempt and its outcome.
        
        Args:
            approach: Description of what was tried (e.g., "nmap_full_port_scan")
            category: Category (e.g., "recon", "exploit", "osint", "fuzzing")
            result: Brief result description
            found_something: Whether new information/vulns were discovered
            new_surfaces: New attack surfaces discovered
            new_findings: New vulnerabilities found
            new_info: New intelligence gathered
            blocked_by: If blocked, by what (e.g., "cloudflare", "rate_limit")
        """
        self.total_iterations += 1
        
        attempt = {
            "approach": approach,
            "category": category,
            "result": result[:500],
            "found_something": found_something,
            "iteration": self.total_iterations,
            "timestamp": datetime.now().isoformat(),
            "escalation_level": self.escalation_level,
            "blocked_by": blocked_by,
        }
        self.tried_approaches.append(attempt)
        
        if found_something:
            self.successful_approaches.append(attempt)
            self.stuck_counter = 0
            self.last_progress_iteration = self.total_iterations
        else:
            self.failed_approaches.append(attempt)
            self.stuck_counter += 1
        
        if blocked_by:
            if blocked_by not in self.detected_defenses:
                self.detected_defenses.append(blocked_by)
            self.bypass_attempts[blocked_by] = self.bypass_attempts.get(blocked_by, 0) + 1
        
        # Add new attack surfaces
        if new_surfaces:
            for surface in new_surfaces:
                surface_key = surface.get("key", str(surface))
                if surface_key not in self.explored_surfaces:
                    self.discovered_surfaces.append(surface)
                    self.unexplored_surfaces.append(surface)
        
        # Add findings
        if new_findings:
            self.findings.extend(new_findings)
        
        # Add intel
        if new_info:
            self.info_gathered.extend(new_info)

    def mark_explored(self, surface_key: str):
        """Mark an attack surface as explored."""
        self.explored_surfaces.add(surface_key)
        self.unexplored_surfaces = [
            s for s in self.unexplored_surfaces 
            if s.get("key", str(s)) != surface_key
        ]

    def should_escalate(self, stuck_threshold: int = 5) -> bool:
        """
        Check if we should escalate to a more aggressive level.
        
        Returns True if:
        - Agent has been stuck for stuck_threshold+ iterations
        - Current level hasn't been exhausted
        - We haven't hit max escalation
        """
        if self.escalation_level >= self.max_escalation:
            return False
        return self.stuck_counter >= stuck_threshold

    def escalate(self) -> Dict:
        """
        Escalate to next aggression level.
        
        Returns the new level info dict.
        """
        if self.escalation_level < self.max_escalation:
            self.escalation_level += 1
            self.stuck_counter = 0  # Reset stuck counter on escalation
        return self.ESCALATION_LEVELS.get(self.escalation_level, {})

    def get_untried_categories(self) -> List[str]:
        """Get attack categories that haven't been tried yet."""
        tried_cats = set(a["category"] for a in self.tried_approaches)
        all_cats = {
            "port_scan", "subdomain_enum", "tech_fingerprint", "directory_fuzz",
            "parameter_mine", "sqli", "xss", "ssrf", "ssti", "idor", "jwt",
            "race_condition", "file_inclusion", "command_injection", "xxe",
            "deserialization", "osint_crtsh", "osint_wayback", "osint_github",
            "credential_brute", "cms_exploit", "api_fuzz", "dns_enum",
            "cloud_misconfig", "ssl_audit", "cors_test", "redirect_test",
            "header_injection", "websocket_test",
        }
        return list(all_cats - tried_cats)

    def get_context_for_ai(self) -> str:
        """
        Generate rich context string for the AI prompt.
        
        This is THE KEY to making the agent smart — it tells the AI:
        - Everything we've tried
        - Everything that failed (and why)
        - Everything we haven't tried yet
        - All unexplored attack surfaces
        - Current escalation level and what's expected
        - User guidance (if any)
        """
        elapsed = int(time.time() - self.start_time)
        level_info = self.ESCALATION_LEVELS.get(self.escalation_level, {})
        
        context = f"""
=== STRATEGY STATUS ===
Target: {self.target}
Elapsed: {elapsed}s | Iterations: {self.total_iterations} | Stuck: {self.stuck_counter}
Escalation: Level {self.escalation_level}/7 — {level_info.get('name', 'Unknown')}
Level Focus: {level_info.get('description', '')}
Suggested Tools: {', '.join(level_info.get('tools', []))}

=== FINDINGS SO FAR ({len(self.findings)} vulns) ===
"""
        if self.findings:
            for f in self.findings[-10:]:
                context += f"  🔴 {f.get('title', 'Unknown')}: {f.get('description', '')[:100]}\n"
        else:
            context += "  ⚠️ NO VULNERABILITIES FOUND YET — keep digging!\n"

        context += f"\n=== INTELLIGENCE GATHERED ({len(self.info_gathered)} items) ===\n"
        for info in self.info_gathered[-15:]:
            context += f"  📌 {info.get('type', '')}: {info.get('value', '')[:100]}\n"

        context += f"\n=== DEFENSES DETECTED ===\n"
        if self.detected_defenses:
            for d in self.detected_defenses:
                attempts = self.bypass_attempts.get(d, 0)
                context += f"  🛡️ {d} (bypass attempts: {attempts})\n"
        else:
            context += "  None detected\n"

        context += f"\n=== UNEXPLORED ATTACK SURFACES ({len(self.unexplored_surfaces)}) ===\n"
        for s in self.unexplored_surfaces[:10]:
            context += f"  🎯 {s.get('type', 'unknown')}: {s.get('value', str(s)[:80])}\n"

        context += f"\n=== FAILED APPROACHES (last 10) ===\n"
        for a in self.failed_approaches[-10:]:
            blocked = f" [BLOCKED BY: {a['blocked_by']}]" if a.get('blocked_by') else ""
            context += f"  ❌ {a['approach'][:60]}{blocked}\n"

        untried = self.get_untried_categories()
        context += f"\n=== UNTRIED ATTACK CATEGORIES ({len(untried)}) ===\n"
        for cat in untried[:15]:
            context += f"  💡 {cat}\n"

        if self.user_guidance:
            context += f"\n=== USER GUIDANCE ===\n"
            context += f"  💬 User says: {self.user_guidance}\n"
            self.user_guidance = None  # Clear after showing once

        context += f"""
=== YOUR MISSION ===
You have found {len(self.findings)} vulnerabilities so far.
{"KEEP GOING — no vulns yet! Try harder, try different approaches!" if not self.findings else "Good progress! Dig deeper into what you found, or explore new surfaces."}
{"⚡ ESCALATION NEEDED — standard approaches failed. Be MORE creative and aggressive!" if self.stuck_counter > 3 else ""}
{"🎯 UNEXPLORED SURFACES AVAILABLE — investigate them before trying new things!" if self.unexplored_surfaces else ""}
Remember: There is ALWAYS a way in. No system is 100% secure.
"""
        return context

    def get_summary(self) -> Dict:
        """Get a summary of the strategy state."""
        return {
            "target": self.target,
            "total_iterations": self.total_iterations,
            "escalation_level": self.escalation_level,
            "findings_count": len(self.findings),
            "surfaces_discovered": len(self.discovered_surfaces),
            "surfaces_unexplored": len(self.unexplored_surfaces),
            "approaches_tried": len(self.tried_approaches),
            "approaches_failed": len(self.failed_approaches),
            "stuck_counter": self.stuck_counter,
            "defenses": self.detected_defenses,
            "elapsed_seconds": int(time.time() - self.start_time),
        }

    def save_state(self, filepath: str):
        """Save strategy state to file for resume."""
        state = {
            "target": self.target,
            "tried_approaches": self.tried_approaches,
            "failed_approaches": self.failed_approaches,
            "successful_approaches": self.successful_approaches,
            "discovered_surfaces": self.discovered_surfaces,
            "explored_surfaces": list(self.explored_surfaces),
            "unexplored_surfaces": self.unexplored_surfaces,
            "findings": self.findings,
            "info_gathered": self.info_gathered,
            "escalation_level": self.escalation_level,
            "stuck_counter": self.stuck_counter,
            "total_iterations": self.total_iterations,
            "detected_defenses": self.detected_defenses,
            "bypass_attempts": self.bypass_attempts,
        }
        with open(filepath, 'w') as f:
            json.dump(state, f, indent=2, default=str)

    @classmethod
    def load_state(cls, filepath: str) -> 'StrategyManager':
        """Load strategy state from file."""
        with open(filepath, 'r') as f:
            state = json.load(f)
        
        mgr = cls(state["target"])
        mgr.tried_approaches = state.get("tried_approaches", [])
        mgr.failed_approaches = state.get("failed_approaches", [])
        mgr.successful_approaches = state.get("successful_approaches", [])
        mgr.discovered_surfaces = state.get("discovered_surfaces", [])
        mgr.explored_surfaces = set(state.get("explored_surfaces", []))
        mgr.unexplored_surfaces = state.get("unexplored_surfaces", [])
        mgr.findings = state.get("findings", [])
        mgr.info_gathered = state.get("info_gathered", [])
        mgr.escalation_level = state.get("escalation_level", 1)
        mgr.stuck_counter = state.get("stuck_counter", 0)
        mgr.total_iterations = state.get("total_iterations", 0)
        mgr.detected_defenses = state.get("detected_defenses", [])
        mgr.bypass_attempts = state.get("bypass_attempts", {})
        return mgr
