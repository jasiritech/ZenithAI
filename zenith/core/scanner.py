"""
Zenith Scanner - The main autonomous scanning engine.
This is the core engine - it connects the AI Brain, Terminal, and Knowledge Base.
"""

import json
import time
import os
import sys
import signal
from datetime import datetime, timedelta

from zenith.core.ai_brain import AIBrain
from zenith.core.executor import TerminalExecutor
from zenith.core.knowledge_base import KnowledgeBase
from zenith.utils.display import Display, Colors


class ZenithScanner:
    """
    Zenith Autonomous AI Security Scanner.
    
    Flow:
    1. User provides API key and target
    2. AI thinks about the first action (recon)
    3. Terminal executes the command
    4. Output is returned to the AI
    5. AI thinks again, chooses a new action
    6. Loop continues until the goal is achieved or user stops it
    """

    PHASES = ["recon", "scan", "exploit", "post_exploit", "report"]
    
    # Maximum iterations to prevent infinite loops
    MAX_ITERATIONS = 200
    MAX_PHASE_ITERATIONS = 50

    def __init__(self, api_key, target, goal=None, model="flash", max_iterations=None, working_dir=None):
        """
        Initialize Zenith Scanner.
        
        Args:
            api_key: Gemini API key
            target: Target URL or IP
            goal: Scanning goal (default: find all vulnerabilities)
            model: 'pro' or 'flash'
            max_iterations: Maximum AI iterations
            working_dir: Working directory for output files
        """
        Display.banner()
        Display.section("INITIALIZING ZENITH AI SCANNER")

        self.target = target
        self.goal = goal or f"Find all security vulnerabilities on {target}. Perform thorough reconnaissance, scan for vulnerabilities, and report findings."
        self.max_iterations = max_iterations or self.MAX_ITERATIONS
        self.start_time = datetime.now()
        self.running = True
        self.current_phase = "recon"
        self.phase_iteration = 0
        self.iteration = 0
        
        working_dir = working_dir or f"/tmp/zenith_{int(time.time())}"

        # Initialize components
        Display.info("Initializing AI Brain...")
        self.ai = AIBrain(api_key, model_choice=model)
        
        Display.info("Initializing Terminal Executor...")
        self.executor = TerminalExecutor(working_dir=working_dir)
        
        Display.info("Initializing Knowledge Base...")
        self.kb = KnowledgeBase(target, save_dir=working_dir)
        
        # Setup signal handler for graceful stop
        signal.signal(signal.SIGINT, self._signal_handler)
        
        Display.success("All systems initialized!")
        Display.info(f"Target: {Colors.BOLD}{target}{Colors.RESET}")
        Display.info(f"Goal: {self.goal[:80]}...")
        Display.info(f"Model: {self.ai.model_name}")
        Display.info(f"Max iterations: {self.max_iterations}")
        print()

    def _signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully."""
        print(f"\n\n  {Colors.YELLOW}[!] Ctrl+C detected - Stopping gracefully...{Colors.RESET}")
        self.running = False

    def run(self):
        """
        Run the autonomous scanning loop.
        This is the main engine - AI thinks, executes, learns, repeats.
        """
        Display.section("STARTING AUTONOMOUS SCAN")
        Display.phase(self.current_phase)

        last_command = ""
        last_output = ""
        consecutive_errors = 0
        max_consecutive_errors = 5

        while self.running and self.iteration < self.max_iterations:
            self.iteration += 1
            self.phase_iteration += 1

            # Show progress
            elapsed = str(datetime.now() - self.start_time).split('.')[0]
            Display.stats(
                self.ai.get_stats(),
                self.executor.get_stats(),
                self.kb.get_vulnerability_count(),
                elapsed
            )

            # ═══════════════════════════════════════
            # STEP 1: AI THINKS
            # ═══════════════════════════════════════
            Display.thinking(f"AI is thinking... (iteration {self.iteration}/{self.max_iterations})")
            
            try:
                decision = self.ai.think(
                    target=self.target,
                    goal=self.goal,
                    knowledge_base=self.kb.get_context(),
                    last_command=last_command,
                    last_output=last_output,
                    phase=self.current_phase
                )
            except Exception as e:
                Display.error(f"AI thinking failed: {e}")
                consecutive_errors += 1
                if consecutive_errors >= max_consecutive_errors:
                    Display.error("Too many consecutive errors. Stopping.")
                    break
                time.sleep(5)
                continue

            consecutive_errors = 0  # Reset on success

            # Show AI's reasoning
            reasoning = decision.get("reasoning", "No reasoning provided")
            Display.info(f"AI Reasoning: {Colors.DIM}{reasoning[:150]}{Colors.RESET}")

            action = decision.get("action", "COMMAND")

            # ═══════════════════════════════════════
            # STEP 2: HANDLE AI DECISION
            # ═══════════════════════════════════════

            # --- GOAL ACHIEVED ---
            if action == "GOAL_ACHIEVED":
                Display.success("🎯 AI reports GOAL ACHIEVED!")
                summary = decision.get("findings_summary", "")
                if summary:
                    Display.info(f"Summary: {summary[:200]}")
                self.kb.add_note(f"Goal achieved: {summary[:300]}")
                break

            # --- SWITCH PHASE ---
            elif action == "SWITCH_PHASE":
                new_phase = decision.get("new_phase", "scan")
                Display.info(f"Switching from {self.current_phase} → {new_phase}")
                self.current_phase = new_phase
                self.kb.update_phase(new_phase)
                self.phase_iteration = 0
                Display.phase(new_phase)
                last_output = f"Phase switched to {new_phase}"
                continue

            # --- EXECUTE COMMAND ---
            elif action == "COMMAND":
                command = decision.get("command", "")
                
                if not command:
                    Display.warning("AI returned empty command, asking to rethink...")
                    last_output = "ERROR: Empty command received. Please provide a valid command."
                    continue

                expected = decision.get("expected_outcome", "")
                if expected:
                    Display.info(f"Expected: {Colors.DIM}{expected[:100]}{Colors.RESET}")

                # Execute the command
                Display.command(command)
                result = self.executor.execute(command)

                # Show output
                combined_output = result["output"]
                if result["error"] and not result["success"]:
                    combined_output += f"\nSTDERR: {result['error']}"
                
                Display.output(combined_output)

                # Show execution info
                if result["success"]:
                    Display.success(f"Command completed in {result['duration']}s")
                else:
                    Display.warning(f"Command failed (code: {result['return_code']}) in {result['duration']}s")

                # Log to KB
                self.kb.log_command(command, combined_output, result["success"])

                # Check for new vulnerabilities
                old_vuln_count = sum(self.kb.get_vulnerability_count().values())
                # KB auto-parsing happens in log_command
                new_vuln_count = sum(self.kb.get_vulnerability_count().values())
                
                if new_vuln_count > old_vuln_count:
                    diff = new_vuln_count - old_vuln_count
                    Display.success(f"🔓 {diff} new vulnerability(ies) discovered!")
                    for vuln in self.kb.data["vulnerabilities"][-diff:]:
                        Display.vulnerability(
                            vuln["title"],
                            vuln["severity"],
                            vuln.get("description", "")
                        )

                # Update for next iteration
                last_command = command
                last_output = combined_output[:3000]  # Limit for AI context

            else:
                Display.warning(f"Unknown action: {action}")
                last_output = f"Unknown action '{action}'. Please use COMMAND, SWITCH_PHASE, or GOAL_ACHIEVED."

            # Check if we should auto-switch phase
            if self.phase_iteration >= self.MAX_PHASE_ITERATIONS:
                current_idx = self.PHASES.index(self.current_phase) if self.current_phase in self.PHASES else 0
                if current_idx < len(self.PHASES) - 1:
                    next_phase = self.PHASES[current_idx + 1]
                    Display.warning(f"Phase iteration limit reached. Auto-switching to {next_phase}")
                    self.current_phase = next_phase
                    self.kb.update_phase(next_phase)
                    self.phase_iteration = 0
                    Display.phase(next_phase)
                else:
                    Display.warning("All phases completed. Generating report.")
                    break

            # Small delay to avoid overwhelming the API
            time.sleep(1)

        # ═══════════════════════════════════════
        # STEP 3: GENERATE FINAL REPORT
        # ═══════════════════════════════════════
        self._generate_report()

    def _generate_report(self):
        """Generate the final security report."""
        Display.section("GENERATING FINAL REPORT")
        
        elapsed = str(datetime.now() - self.start_time).split('.')[0]
        Display.info(f"Total scan time: {elapsed}")
        Display.info(f"Total iterations: {self.iteration}")
        Display.info(f"Total commands executed: {self.executor.get_stats()['total_commands']}")

        # Ask AI to analyze all findings
        Display.thinking("AI is analyzing all findings and generating report...")
        
        try:
            ai_report = self.ai.analyze_findings(
                self.kb.get_full_data(),
                self.target,
                self.goal
            )
        except Exception as e:
            Display.error(f"AI report generation failed: {e}")
            ai_report = {
                "executive_summary": "Auto-analysis failed. See raw data in KB export.",
                "risk_rating": "UNKNOWN"
            }

        # Save reports
        kb_report_file = self.kb.export_report()
        Display.success(f"Knowledge Base report saved: {kb_report_file}")

        # Save AI analysis report
        ai_report_file = kb_report_file.replace("_report.json", "_ai_analysis.json")
        try:
            with open(ai_report_file, 'w') as f:
                json.dump(ai_report, f, indent=2, default=str)
            Display.success(f"AI analysis report saved: {ai_report_file}")
        except Exception as e:
            Display.error(f"Failed to save AI report: {e}")

        # Show final report
        Display.final_report(ai_report, kb_report_file)

        # Print vulnerability summary
        vuln_counts = self.kb.get_vulnerability_count()
        total_vulns = sum(vuln_counts.values())
        
        if total_vulns > 0:
            Display.subsection("VULNERABILITY SUMMARY")
            for vuln in self.kb.data["vulnerabilities"]:
                Display.vulnerability(
                    vuln["title"],
                    vuln["severity"],
                    vuln.get("description", "")
                )
        else:
            Display.info("No vulnerabilities were automatically detected.")
            Display.info("Check the full report for manual analysis results from AI.")

        # Final stats
        Display.subsection("FINAL STATISTICS")
        Display.info(f"Scan Duration: {elapsed}")
        Display.info(f"AI Model: {self.ai.model_name}")
        Display.info(f"AI Calls: {self.ai.get_stats()['total_calls']}")
        Display.info(f"Commands Executed: {self.executor.get_stats()['total_commands']}")
        Display.info(f"Commands Failed: {self.executor.get_stats()['failed_commands']}")
        Display.info(f"Vulnerabilities Found: {total_vulns}")
        
        for sev, count in vuln_counts.items():
            if count > 0:
                Display.info(f"  {sev}: {count}")
        
        print(f"\n  {Colors.GREEN}{Colors.BOLD}Scan complete! Check reports for full details.{Colors.RESET}\n")

    def stop(self):
        """Stop the scanner."""
        self.running = False
        Display.warning("Scanner stopping...")
