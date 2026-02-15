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
from zenith.core.session import SessionManager
from zenith.core.validator import CommandValidator
from zenith.core.proxy import ProxyManager
from zenith.utils.display import Display, Colors
from zenith.utils.report_generator import HTMLReportGenerator
from zenith.utils.notifier import Notifier


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

    def __init__(self, api_key, target, goal=None, model="flash", max_iterations=None, 
                 working_dir=None, profile=None, proxy_config=None, notify_config=None,
                 resume_session=None, sudo_password=None):
        """
        Initialize Zenith Scanner.
        
        Args:
            api_key: Gemini API key
            target: Target URL or IP
            goal: Scanning goal (default: find all vulnerabilities)
            model: 'pro' or 'flash'
            max_iterations: Maximum AI iterations
            working_dir: Working directory for output files
            profile: Scan profile name (quick, full, stealth, web, network, api)
            proxy_config: Proxy configuration dict
            notify_config: Notification configuration dict
            resume_session: Session ID to resume
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
        self.profile_name = profile or "custom"
        self.api_key = api_key
        self.model_choice = model
        
        working_dir = working_dir or f"/tmp/zenith_{int(time.time())}"
        self.working_dir = working_dir

        # Initialize Session Manager
        Display.info("Initializing Session Manager...")
        self.session_mgr = SessionManager()
        
        # Resume or create session
        if resume_session:
            self.session_id = resume_session
            session_data = self.session_mgr.load_session(resume_session)
            if session_data:
                self.iteration = session_data.get("current_iteration", 0)
                self.current_phase = session_data.get("current_phase", "recon")
                self.phase_iteration = session_data.get("phase_iteration", 0)
                Display.success(f"Resumed session: {resume_session}")
                Display.info(f"Resuming from iteration {self.iteration}, phase: {self.current_phase}")
        else:
            self.session_id = self.session_mgr.create_session(
                target=target, goal=self.goal, model=model,
                api_key_hash=SessionManager.hash_api_key(api_key),
                max_iterations=self.max_iterations
            )
            Display.info(f"Session: {self.session_id}")

        # Initialize components
        Display.info("Initializing AI Brain...")
        self.ai = AIBrain(api_key, model_choice=model)
        
        Display.info("Initializing Terminal Executor...")
        self.executor = TerminalExecutor(working_dir=working_dir, sudo_password=sudo_password)
        
        Display.info("Initializing Knowledge Base...")
        self.kb = KnowledgeBase(target, save_dir=working_dir)

        # Initialize Command Validator
        Display.info("Initializing Command Validator...")
        self.validator = CommandValidator(target=target)

        # Initialize Proxy Manager
        self.proxy = ProxyManager(proxy_config) if proxy_config else ProxyManager.from_env()
        if self.proxy.enabled:
            Display.info(f"Proxy: {self.proxy.get_status()}")
            ok, msg = self.proxy.verify()
            if ok:
                Display.success(f"Proxy verified: {msg}")
            else:
                Display.warning(f"Proxy verification failed: {msg}")

        # Initialize Notifier
        self.notifier = Notifier(notify_config) if notify_config else Notifier.from_env()
        if self.notifier.enabled:
            Display.success("Notifications enabled!")

        # Initialize HTML Report Generator
        self.html_reporter = HTMLReportGenerator()
        
        # Setup signal handler for graceful stop
        signal.signal(signal.SIGINT, self._signal_handler)
        
        Display.success("All systems initialized!")
        Display.info(f"Target: {Colors.BOLD}{target}{Colors.RESET}")
        Display.info(f"Profile: {self.profile_name}")
        Display.info(f"Goal: {self.goal[:80]}...")
        Display.info(f"Model: {self.ai.model_name}")
        Display.info(f"Max iterations: {self.max_iterations}")
        print()

    def _signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully - kills running command and exits."""
        # Second Ctrl+C = force exit immediately
        if not self.running:
            print(f"\n  {Colors.RED}[!] Force exit!{Colors.RESET}")
            # Kill any running subprocess
            self.executor.kill_current()
            os._exit(1)

        print(f"\n\n  {Colors.YELLOW}[!] Ctrl+C detected - Stopping...{Colors.RESET}")
        self.running = False

        # Kill the currently running command (nmap, nikto, etc.)
        if self.executor.kill_current():
            print(f"  {Colors.YELLOW}[!] Killed running command.{Colors.RESET}")

        # Save session for resume
        try:
            self.session_mgr.mark_interrupted(self.session_id)
            self.session_mgr.save_state(
                self.session_id,
                current_iteration=self.iteration,
                current_phase=self.current_phase,
                phase_iteration=self.phase_iteration,
                working_dir=self.working_dir,
                knowledge_base_file=self.kb.db_file,
            )
            Display.info(f"Session saved! Resume with: python3 zenith.py --resume {self.session_id}")
        except Exception:
            pass  # Don't crash on save failure during exit

    def run(self):
        """
        Run the autonomous scanning loop.
        This is the main engine - AI thinks, executes, learns, repeats.
        """
        Display.section("STARTING AUTONOMOUS SCAN")
        Display.phase(self.current_phase)

        # Send scan start notification
        self.notifier.notify_scan_start(self.target, self.ai.model_name, self.profile_name)

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

                # Validate command
                is_valid, cleaned_cmd, warnings = self.validator.validate(command)
                for w in warnings:
                    Display.warning(f"Validator: {w}")
                
                if not is_valid:
                    Display.error(f"Command rejected by validator")
                    last_output = f"ERROR: Command rejected - {'; '.join(warnings)}. Try a different approach."
                    continue
                
                command = cleaned_cmd
                
                # Wrap with proxy if enabled
                if self.proxy.enabled:
                    command = self.proxy.wrap_command(command)

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
                        # Send notification
                        self.notifier.notify_vulnerability(
                            vuln["title"], vuln["severity"],
                            vuln.get("description", ""), self.target
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

            # Save session state periodically (every 5 iterations)
            if self.iteration % 5 == 0:
                self.session_mgr.save_state(
                    self.session_id,
                    current_iteration=self.iteration,
                    current_phase=self.current_phase,
                    phase_iteration=self.phase_iteration,
                    ai_calls=self.ai.get_stats()["total_calls"],
                    commands_executed=self.executor.get_stats()["total_commands"],
                    commands_failed=self.executor.get_stats()["failed_commands"],
                    vulnerabilities_found=sum(self.kb.get_vulnerability_count().values()),
                    working_dir=self.working_dir,
                    knowledge_base_file=self.kb.db_file,
                )

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

        # Generate HTML Report
        try:
            scan_info = {
                "target": self.target,
                "model": self.ai.model_name,
                "duration": elapsed,
                "iterations": self.iteration,
                "commands_executed": self.executor.get_stats()["total_commands"],
                "working_dir": self.working_dir,
                "profile": self.profile_name,
            }
            html_file = self.html_reporter.generate(
                report_data=ai_report,
                kb_data=self.kb.get_full_data(),
                scan_info=scan_info
            )
            Display.success(f"📄 HTML report generated: {html_file}")
        except Exception as e:
            Display.error(f"HTML report generation failed: {e}")

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

        # Mark session complete
        self.session_mgr.mark_completed(self.session_id)
        self.session_mgr.save_state(
            self.session_id,
            current_iteration=self.iteration,
            current_phase="completed",
            ai_calls=self.ai.get_stats()["total_calls"],
            commands_executed=self.executor.get_stats()["total_commands"],
            vulnerabilities_found=total_vulns,
            status="completed",
        )

        # Send completion notification
        self.notifier.notify_scan_end(
            self.target, elapsed, vuln_counts,
            risk_rating=ai_report.get("risk_rating", "UNKNOWN") if isinstance(ai_report, dict) else "UNKNOWN"
        )

    def stop(self):
        """Stop the scanner."""
        self.running = False
        Display.warning("Scanner stopping...")
