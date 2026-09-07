"""
Zenith Multi-Agent Pipeline Orchestrator v2 — ITERATIVE PERSISTENT SWARM.

Instead of a linear pipeline (plan→recon→web→exploit→report→done),
this runs in CYCLES. After each cycle, it evaluates progress and 
either digs deeper, changes strategy, or escalates.

Coordinates specialized agents into an autonomous penetration testing swarm:
  PlannerAgent → ReconAgent → WebAgent → ExploitAgent → (evaluate) → repeat or ReporterAgent
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
    """Orchestrates the Zenith Multi-Agent Security Swarm with PERSISTENCE."""

    def __init__(
        self,
        target: str,
        goal: Optional[str] = None,
        ai_brain = None,
        executor = None,
        output_dir: Optional[str] = None,
        proxy_config: Optional[Dict] = None,
        max_cycles: int = 5,
    ):
        self.target = target
        self.goal = goal or f"Perform a comprehensive multi-agent security assessment of {target}"
        self.ai = ai_brain
        self.executor = executor
        self.output_dir = output_dir or os.path.join(os.path.expanduser("~"), "zenith_reports")
        os.makedirs(self.output_dir, exist_ok=True)
        self.proxy_config = proxy_config
        self.max_cycles = max_cycles

        # Core state
        self.memory = SharedMemory(target=self.target)
        self.graph = AttackGraph(target=self.target)
        self.start_time = time.time()
        self.results: Dict[str, any] = {}

    def _count_vulns(self) -> int:
        """Count total vulnerabilities found so far."""
        vulns = self.memory.get_context("vulnerabilities") or []
        return len(vulns)

    def run(self):
        """Execute ITERATIVE multi-agent swarm — cycles until progress stops."""
        Display.banner()
        Display.section("🔱 MULTI-AGENT SWARM PIPELINE ACTIVE")
        Display.info(f"Target: {Colors.BOLD}{self.target}{Colors.RESET}")
        Display.info(f"AI Provider: {Colors.CYAN}{self.ai.provider.upper()} ({self.ai.model_name}){Colors.RESET}")
        Display.info(f"Goal: {self.goal}")
        Display.info(f"Max Cycles: {self.max_cycles}")
        print()

        cycle = 0
        prev_vuln_count = 0
        no_progress_cycles = 0

        while cycle < self.max_cycles:
            cycle += 1
            cycle_start = time.time()
            
            Display.section(f"═══ SWARM CYCLE {cycle}/{self.max_cycles} ═══")
            
            # ─── Phase 1: Planning ───
            Display.section(f"PHASE 1: TACTICAL ATTACK PLANNING (Cycle {cycle})")
            planner = PlannerAgent(self.executor, self.ai, self.memory, self.graph, Display)
            
            # Give planner context about previous cycles
            cycle_goal = self.goal
            if cycle > 1:
                vulns_so_far = self._count_vulns()
                cycle_goal += (
                    f"\n\nThis is CYCLE {cycle}. Previous cycles found {vulns_so_far} vulnerabilities. "
                    f"{'Try HARDER and DIFFERENT approaches!' if vulns_so_far == 0 else 'Dig DEEPER into findings!'} "
                    f"Do NOT repeat what was already tried."
                )
            
            plan_result = planner.run(self.target, goal=cycle_goal)
            self.results[f"planner_c{cycle}"] = plan_result

            # ─── Phase 2: Recon ───
            Display.section(f"PHASE 2: SURFACE RECONNAISSANCE (Cycle {cycle})")
            recon = ReconAgent(self.executor, self.ai, self.memory, self.graph, Display)
            recon_result = recon.run(self.target)
            self.results[f"recon_c{cycle}"] = recon_result

            # ─── Phase 3: Web ───
            Display.section(f"PHASE 3: WEB SURFACE & API MAPPING (Cycle {cycle})")
            web = WebAgent(self.executor, self.ai, self.memory, self.graph, Display)
            web_result = web.run(self.target)
            self.results[f"web_c{cycle}"] = web_result

            # ─── Phase 4: Exploit ───
            Display.section(f"PHASE 4: VULNERABILITY TESTING & EXPLOITATION (Cycle {cycle})")
            exploit = ExploitAgent(self.executor, self.ai, self.memory, self.graph, Display)
            exploit_result = exploit.run(self.target)
            self.results[f"exploit_c{cycle}"] = exploit_result

            # ─── Evaluate Progress ───
            current_vuln_count = self._count_vulns()
            new_vulns = current_vuln_count - prev_vuln_count
            cycle_time = round(time.time() - cycle_start, 1)
            
            Display.section(f"CYCLE {cycle} EVALUATION")
            Display.info(f"⏱  Cycle time: {cycle_time}s")
            Display.info(f"🔴 New vulnerabilities this cycle: {new_vulns}")
            Display.info(f"📊 Total vulnerabilities: {current_vuln_count}")
            
            if new_vulns > 0:
                Display.success(f"✅ Progress! Found {new_vulns} new vuln(s) — continuing to dig deeper...")
                no_progress_cycles = 0
                prev_vuln_count = current_vuln_count
            else:
                no_progress_cycles += 1
                if no_progress_cycles >= 2:
                    Display.warning(f"⚠ No new findings for {no_progress_cycles} cycles — moving to report phase")
                    break
                else:
                    Display.warning(f"⚠ No new findings this cycle — will try one more with different strategy")
                    prev_vuln_count = current_vuln_count

        # ─── Phase 5: Final Report ───
        Display.section("PHASE 5: COMPREHENSIVE SECURITY REPORTING")
        reporter = ReporterAgent(self.executor, self.ai, self.memory, self.graph, Display)
        report_result = reporter.run(self.target, output_dir=self.output_dir)
        self.results["reporter"] = report_result

        # ─── Summary ───
        elapsed = round(time.time() - self.start_time, 2)
        print()
        Display.section("SWARM EXECUTION COMPLETE")
        Display.success(f"Total time: {elapsed} seconds")
        Display.info(f"Total Cycles: {cycle}")
        
        vulns = self.memory.get_context("vulnerabilities") or []
        Display.info(f"Total Vulnerabilities Discovered: {Colors.BOLD}{len(vulns)}{Colors.RESET}")
        
        report_path = report_result.data.get("html_report") if hasattr(report_result, "data") else None
        if report_path:
            Display.success(f"HTML Security Report Generated: {report_path}")

        return self.results