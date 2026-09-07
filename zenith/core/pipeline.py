"""
Zenith Multi-Agent Pipeline Orchestrator.
Coordinates specialized agents into an autonomous penetration testing swarm:
  PlannerAgent -> ReconAgent -> WebAgent -> ExploitAgent -> ReporterAgent
"""

import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional

from zenith.memory.shared_memory import SharedMemory
from zenith.memory.attack_graph import AttackGraph
from zenith.agents.planner import PlannerAgent
from zenith.agents.recon import ReconAgent
from zenith.agents.web import WebAgent
from zenith.agents.exploit import ExploitAgent
from zenith.agents.reporter import ReporterAgent
from zenith.utils.display import Display, Colors


class AgentPipeline:
    """Orchestrates the Zenith Multi-Agent Security Swarm."""

    def __init__(
        self,
        target: str,
        goal: Optional[str] = None,
        ai_brain = None,
        executor = None,
        output_dir: Optional[str] = None,
        proxy_config: Optional[Dict] = None
    ):
        self.target = target
        self.goal = goal or f"Perform a comprehensive multi-agent security assessment of {target}"
        self.ai = ai_brain
        self.executor = executor
        self.output_dir = output_dir or os.path.join(os.path.expanduser("~"), "zenith_reports")
        os.makedirs(self.output_dir, exist_ok=True)
        self.proxy_config = proxy_config

        # Core state
        self.memory = SharedMemory(target=self.target)
        self.graph = AttackGraph(target=self.target)
        self.start_time = time.time()
        self.results: Dict[str, any] = {}

    def run(self):
        """Execute all phases in the multi-agent swarm."""
        Display.banner()
        Display.section("🔱 MULTI-AGENT SWARM PIPELINE ACTIVE")
        Display.info(f"Target: {Colors.BOLD}{self.target}{Colors.RESET}")
        Display.info(f"AI Provider: {Colors.CYAN}{self.ai.provider.upper()} ({self.ai.model_name}){Colors.RESET}")
        Display.info(f"Goal: {self.goal}")
        print()

        # Phase 1: Planning
        Display.section("PHASE 1: TACTICAL ATTACK PLANNING")
        planner = PlannerAgent(self.executor, self.ai, self.memory, self.graph, Display)
        plan_result = planner.run(self.target, goal=self.goal)
        self.results["planner"] = plan_result

        # Phase 2: Reconnaissance
        Display.section("PHASE 2: SURFACE RECONNAISSANCE")
        recon = ReconAgent(self.executor, self.ai, self.memory, self.graph, Display)
        recon_result = recon.run(self.target)
        self.results["recon"] = recon_result

        # Phase 3: Web Surface & Application Crawl
        Display.section("PHASE 3: WEB SURFACE & API MAPPING")
        web = WebAgent(self.executor, self.ai, self.memory, self.graph, Display)
        web_result = web.run(self.target)
        self.results["web"] = web_result

        # Phase 4: Targeted Exploitation & Vulnerability Testing
        Display.section("PHASE 4: VULNERABILITY TESTING & EXPLOITATION")
        exploit = ExploitAgent(self.executor, self.ai, self.memory, self.graph, Display)
        exploit_result = exploit.run(self.target)
        self.results["exploit"] = exploit_result

        # Phase 5: AI Executive Reporting
        Display.section("PHASE 5: COMPREHENSIVE SECURITY REPORTING")
        reporter = ReporterAgent(self.executor, self.ai, self.memory, self.graph, Display)
        report_result = reporter.run(self.target, output_dir=self.output_dir)
        self.results["reporter"] = report_result

        # Summary
        elapsed = round(time.time() - self.start_time, 2)
        print()
        Display.section("SWARM EXECUTION COMPLETE")
        Display.success(f"Total time: {elapsed} seconds")
        
        vulns = self.memory.get_context("vulnerabilities") or []
        Display.info(f"Total Vulnerabilities Discovered: {Colors.BOLD}{len(vulns)}{Colors.RESET}")
        
        report_path = report_result.data.get("html_report") if hasattr(report_result, "data") else None
        if report_path:
            Display.success(f"HTML Security Report Generated: {report_path}")

        return self.results