"""
Planner Agent - Analyzes the target and generates a structured attack plan.

Responsibilities:
  - Assess target type (web app, API, network, CMS, etc.)
  - Generate a phased attack plan with agent assignments
  - Determine stealth requirements from context (WAF detected, etc.)
  - Adapt the plan as new information becomes available
"""

import json
import re
from typing import Dict, List, Optional

from zenith.agents.base_agent import BaseAgent, AgentResult
from zenith.memory.shared_memory import SharedMemory


_PLAN_PROMPT = """You are a senior red-team engineer planning a penetration test.

Target: {target}
Objective: {goal}

Current knowledge:
{context}

Generate a structured JSON attack plan with the following schema:
{{
  "target_type": "web_app | api | network | cms | cloud | unknown",
  "risk_level": "low | medium | high | critical",
  "stealth_required": true | false,
  "phases": [
    {{
      "id": "recon",
      "name": "Reconnaissance",
      "priority": 1,
      "agents": ["recon"],
      "focus": "Discover subdomains, IPs, open ports, services, tech stack",
      "tools": ["amass", "subfinder", "httpx", "nmap", "whatweb"],
      "estimated_minutes": 15,
      "requires": []
    }},
    {{
      "id": "web_analysis",
      "name": "Web Surface Mapping",
      "priority": 2,
      "agents": ["web"],
      "focus": "Map endpoints, forms, JS files, API routes",
      "tools": ["playwright", "dirsearch", "ffuf"],
      "estimated_minutes": 10,
      "requires": ["recon"]
    }},
    {{
      "id": "intelligence",
      "name": "Vulnerability Intelligence",
      "priority": 2,
      "agents": ["intelligence"],
      "focus": "Match discovered software to known CVEs and exploits",
      "tools": ["nvd_api", "exploitdb"],
      "estimated_minutes": 5,
      "requires": ["recon"]
    }},
    {{
      "id": "exploitation",
      "name": "Exploitation",
      "priority": 3,
      "agents": ["exploit"],
      "focus": "Exploit highest-value findings",
      "tools": ["sqlmap", "nuclei", "custom_modules"],
      "estimated_minutes": 20,
      "requires": ["web_analysis", "intelligence"]
    }},
    {{
      "id": "reporting",
      "name": "Report Generation",
      "priority": 4,
      "agents": ["reporter"],
      "focus": "Generate HTML/JSON/Markdown report with evidence",
      "tools": ["report_generator"],
      "estimated_minutes": 3,
      "requires": ["exploitation"]
    }}
  ],
  "priority_checks": ["SQLi", "default credentials", "exposed admin panels"],
  "skip_agents": [],
  "notes": "Any special instructions for this target"
}}

Return ONLY valid JSON, no explanation."""


class PlannerAgent(BaseAgent):
    """
    Generates and manages the master attack plan.
    Called at scan start and can be re-invoked mid-scan to adapt the plan.
    """

    NAME        = "planner"
    DESCRIPTION = "Generates structured multi-phase attack plans and coordinates agent order"
    PROVIDES    = ["attack_plan", "target_type", "stealth_required"]

    def run(self, target: str, goal: str = "", **kwargs) -> AgentResult:
        self._start()
        self.memory.set_agent_status(self.NAME, "running")
        self._log(f"Planning attack on {target} …", "info")

        try:
            context = self.memory.get_ai_context_string(max_chars=800)
            prompt  = _PLAN_PROMPT.format(
                target  = target,
                goal    = (goal or f"Comprehensive security assessment of {target}")[:400],
                context = context or "No prior knowledge — this is the first planning call.",
            )

            raw      = self.ai.think(prompt)
            plan     = self._parse_json(raw) or self._default_plan(target)

            # ── persist into shared memory ──
            self._write("attack_plan",      plan)
            self._write("target",           target)
            self._write("goal",             goal)
            self._update("target_type",     plan.get("target_type", "unknown"))
            self._update("stealth_mode",    plan.get("stealth_required", False))
            if plan.get("stealth_required"):
                self._update("scan_speed",  "slow")

            self._emit("plan_ready", plan)

            n_phases = len(plan.get("phases", []))
            risk     = plan.get("risk_level", "unknown")
            self._log(f"Plan ready: {n_phases} phases, risk={risk}", "success")

            self.memory.set_agent_status(self.NAME, "done")
            self.memory.store_agent_result(self.NAME, plan)

            return AgentResult(
                agent_name = self.NAME,
                status     = "success",
                data       = plan,
                duration   = self._elapsed(),
                message    = f"Generated {n_phases}-phase attack plan (risk={risk})",
            )

        except Exception as exc:
            self.memory.set_agent_status(self.NAME, "failed")
            self._log(f"Planning failed: {exc}", "error")
            fallback = self._default_plan(target)
            self._write("attack_plan", fallback)
            return AgentResult(
                agent_name = self.NAME,
                status     = "partial",
                data       = fallback,
                errors     = [str(exc)],
                duration   = self._elapsed(),
                message    = "Used default plan (AI planning failed)",
            )

    # ──────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────

    def _parse_json(self, text: str) -> Optional[Dict]:
        """Extract and parse first JSON object in text."""
        match = re.search(r'\{[\s\S]*\}', text)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        return None

    def _default_plan(self, target: str) -> Dict:
        """Fallback plan when AI is unavailable."""
        return {
            "target_type":      "unknown",
            "risk_level":       "medium",
            "stealth_required": False,
            "phases": [
                {"id": "recon",        "priority": 1, "agents": ["recon"],        "requires": [], "estimated_minutes": 15},
                {"id": "web_analysis", "priority": 2, "agents": ["web"],          "requires": ["recon"], "estimated_minutes": 10},
                {"id": "intelligence", "priority": 2, "agents": ["intelligence"], "requires": ["recon"], "estimated_minutes": 5},
                {"id": "exploitation", "priority": 3, "agents": ["exploit"],      "requires": ["web_analysis", "intelligence"], "estimated_minutes": 20},
                {"id": "reporting",    "priority": 4, "agents": ["reporter"],     "requires": ["exploitation"], "estimated_minutes": 3},
            ],
            "priority_checks": [],
            "skip_agents":      [],
            "notes":            "Default plan (AI planning unavailable)",
        }
