"""
Zenith Display - Beautiful terminal output with colors and formatting.
"""

import os
import sys
from datetime import datetime


class Colors:
    """ANSI color codes for terminal."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
    # Severity colors
    CRITICAL = '\033[91m\033[1m'  # Bold Red
    HIGH = '\033[91m'              # Red
    MEDIUM = '\033[93m'            # Yellow
    LOW = '\033[94m'               # Blue
    INFO = '\033[96m'              # Cyan


class Display:
    """Beautiful terminal display for Zenith."""

    @staticmethod
    def banner():
        """Show the Zenith banner."""
        banner_text = f"""
{Colors.CYAN}{Colors.BOLD}
 ███████╗███████╗███╗   ██╗██╗████████╗██╗  ██╗     █████╗ ██╗
 ╚══███╔╝██╔════╝████╗  ██║██║╚══██╔══╝██║  ██║    ██╔══██╗██║
   ███╔╝ █████╗  ██╔██╗ ██║██║   ██║   ███████║    ███████║██║
  ███╔╝  ██╔══╝  ██║╚██╗██║██║   ██║   ██╔══██║    ██╔══██║██║
 ███████╗███████╗██║ ╚████║██║   ██║   ██║  ██║    ██║  ██║██║
 ╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝   ╚═╝   ╚═╝  ╚═╝    ╚═╝  ╚═╝
{Colors.RESET}
{Colors.YELLOW}  ⚡ Autonomous AI-Powered Security Scanner v2.0{Colors.RESET}
{Colors.DIM}  ─────────────────────────────────────────────────{Colors.RESET}
{Colors.CYAN}  AI: Gemini / Groq  │  Engine: Autonomous AI Agent{Colors.RESET}
{Colors.DIM}  ─────────────────────────────────────────────────{Colors.RESET}
"""
        print(banner_text)

    @staticmethod
    def section(title):
        """Print a section header."""
        print(f"\n{Colors.CYAN}{'═' * 60}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}  {title}{Colors.RESET}")
        print(f"{Colors.CYAN}{'═' * 60}{Colors.RESET}\n")

    @staticmethod
    def subsection(title):
        """Print a subsection header."""
        print(f"\n{Colors.YELLOW}  ── {title} ──{Colors.RESET}\n")

    @staticmethod
    def info(message):
        """Print info message."""
        print(f"  {Colors.BLUE}[ℹ]{Colors.RESET} {message}")

    @staticmethod
    def success(message):
        """Print success message."""
        print(f"  {Colors.GREEN}[✓]{Colors.RESET} {message}")

    @staticmethod
    def warning(message):
        """Print warning message."""
        print(f"  {Colors.YELLOW}[⚠]{Colors.RESET} {message}")

    @staticmethod
    def error(message):
        """Print error message."""
        print(f"  {Colors.RED}[✗]{Colors.RESET} {message}")

    @staticmethod
    def thinking(message):
        """Print AI thinking message."""
        print(f"  {Colors.MAGENTA}[🧠]{Colors.RESET} {Colors.DIM}{message}{Colors.RESET}")

    @staticmethod
    def command(cmd):
        """Print command being executed."""
        print(f"\n  {Colors.GREEN}[▶]{Colors.RESET} {Colors.BOLD}$ {cmd}{Colors.RESET}")

    @staticmethod
    def output(text, max_lines=30):
        """Print command output."""
        if not text:
            print(f"  {Colors.DIM}(no output){Colors.RESET}")
            return
        
        lines = text.strip().split('\n')
        shown = lines[:max_lines]
        
        for line in shown:
            print(f"  {Colors.DIM}│{Colors.RESET} {line}")
        
        if len(lines) > max_lines:
            print(f"  {Colors.DIM}│ ... ({len(lines) - max_lines} more lines){Colors.RESET}")

    @staticmethod
    def phase(phase_name, phase_num=0):
        """Print current phase."""
        phases = {
            "recon": ("🔍", "RECONNAISSANCE"),
            "scan": ("🔎", "VULNERABILITY SCANNING"),
            "exploit": ("💥", "EXPLOITATION"),
            "post_exploit": ("🏴", "POST-EXPLOITATION"),
            "report": ("📋", "REPORTING"),
        }
        emoji, label = phases.get(phase_name.lower(), ("⚙️", phase_name.upper()))
        print(f"\n  {Colors.CYAN}{Colors.BOLD}┌{'─' * 50}┐{Colors.RESET}")
        print(f"  {Colors.CYAN}{Colors.BOLD}│  {emoji}  PHASE: {label:<39}│{Colors.RESET}")
        print(f"  {Colors.CYAN}{Colors.BOLD}└{'─' * 50}┘{Colors.RESET}\n")

    @staticmethod
    def vulnerability(title, severity, description=""):
        """Print a discovered vulnerability."""
        sev_colors = {
            "CRITICAL": Colors.CRITICAL,
            "HIGH": Colors.HIGH,
            "MEDIUM": Colors.MEDIUM,
            "LOW": Colors.LOW,
            "INFO": Colors.INFO,
        }
        color = sev_colors.get(severity.upper(), Colors.WHITE)
        print(f"  {color}[{severity.upper()}]{Colors.RESET} {Colors.BOLD}{title}{Colors.RESET}")
        if description:
            print(f"         {Colors.DIM}{description[:100]}{Colors.RESET}")

    @staticmethod
    def stats(ai_stats, exec_stats, vuln_counts, elapsed):
        """Print current statistics."""
        print(f"\n  {Colors.DIM}{'─' * 50}{Colors.RESET}")
        print(f"  {Colors.CYAN}📊 Stats:{Colors.RESET} "
              f"AI calls: {ai_stats.get('total_calls', 0)} │ "
              f"Commands: {exec_stats.get('total_commands', 0)} │ "
              f"Time: {elapsed}")
        
        vuln_str = ""
        if vuln_counts.get("CRITICAL", 0) > 0:
            vuln_str += f" {Colors.CRITICAL}C:{vuln_counts['CRITICAL']}{Colors.RESET}"
        if vuln_counts.get("HIGH", 0) > 0:
            vuln_str += f" {Colors.HIGH}H:{vuln_counts['HIGH']}{Colors.RESET}"
        if vuln_counts.get("MEDIUM", 0) > 0:
            vuln_str += f" {Colors.MEDIUM}M:{vuln_counts['MEDIUM']}{Colors.RESET}"
        if vuln_counts.get("LOW", 0) > 0:
            vuln_str += f" {Colors.LOW}L:{vuln_counts['LOW']}{Colors.RESET}"
        
        if vuln_str:
            print(f"  {Colors.CYAN}🔓 Vulns:{Colors.RESET}{vuln_str}")
        print(f"  {Colors.DIM}{'─' * 50}{Colors.RESET}")

    @staticmethod
    def final_report(report_data, report_file):
        """Print final report summary."""
        print(f"\n{'='*60}")
        print(f"{Colors.CYAN}{Colors.BOLD}  📋 ZENITH AI - FINAL SECURITY REPORT{Colors.RESET}")
        print(f"{'='*60}")
        
        if isinstance(report_data, dict):
            summary = report_data.get("executive_summary", "No summary available")
            risk = report_data.get("risk_rating", "UNKNOWN")
            
            risk_colors = {
                "CRITICAL": Colors.CRITICAL,
                "HIGH": Colors.HIGH,
                "MEDIUM": Colors.MEDIUM,
                "LOW": Colors.LOW,
            }
            risk_color = risk_colors.get(risk, Colors.WHITE)
            
            print(f"\n  {Colors.BOLD}Risk Rating:{Colors.RESET} {risk_color}{risk}{Colors.RESET}")
            print(f"  {Colors.BOLD}Summary:{Colors.RESET} {summary}")
            
            findings = report_data.get("critical_findings", report_data.get("all_findings", []))
            if findings:
                print(f"\n  {Colors.BOLD}Key Findings:{Colors.RESET}")
                for i, f in enumerate(findings[:10], 1):
                    if isinstance(f, dict):
                        sev = f.get("severity", "INFO")
                        title = f.get("title", "Unknown")
                        sev_color = risk_colors.get(sev, Colors.WHITE)
                        print(f"    {i}. {sev_color}[{sev}]{Colors.RESET} {title}")
        
        print(f"\n  {Colors.GREEN}[✓] Full report saved: {report_file}{Colors.RESET}")
        print(f"{'='*60}\n")

    @staticmethod
    def progress(current, description=""):
        """Print progress indicator."""
        spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        idx = current % len(spinner)
        print(f"\r  {Colors.CYAN}{spinner[idx]}{Colors.RESET} {description}", end="", flush=True)
