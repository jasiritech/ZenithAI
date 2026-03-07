"""
Zenith Display - Modern terminal UI with rich formatting.
Pro-grade hacker dashboard aesthetics.
"""

import os
import sys
import shutil
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
    ITALIC = '\033[3m'
    
    # Background colors
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_DARK = '\033[48;5;235m'
    BG_DARKER = '\033[48;5;233m'
    
    # 256-color palette
    ORANGE = '\033[38;5;208m'
    PINK = '\033[38;5;205m'
    LIME = '\033[38;5;118m'
    TEAL = '\033[38;5;43m'
    PURPLE = '\033[38;5;141m'
    GRAY = '\033[38;5;245m'
    DARK_GRAY = '\033[38;5;238m'
    LIGHT_CYAN = '\033[38;5;117m'
    NEON_GREEN = '\033[38;5;46m'
    NEON_RED = '\033[38;5;196m'
    NEON_YELLOW = '\033[38;5;226m'
    STEEL_BLUE = '\033[38;5;67m'
    
    # Severity colors
    CRITICAL = '\033[91m\033[1m'  # Bold Red
    HIGH = '\033[91m'              # Red
    MEDIUM = '\033[93m'            # Yellow
    LOW = '\033[94m'               # Blue
    INFO = '\033[96m'              # Cyan


def _term_width():
    """Get terminal width safely."""
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 80


class Display:
    """Modern terminal display for Zenith - Pro hacker dashboard."""

    # Box drawing characters
    TL = '╭'  # top-left
    TR = '╮'  # top-right
    BL = '╰'  # bottom-left
    BR = '╯'  # bottom-right
    H = '─'   # horizontal
    V = '│'   # vertical
    LT = '├'  # left-tee
    RT = '┤'  # right-tee

    @staticmethod
    def _box(lines, color=Colors.CYAN, width=None, title=None, style="rounded"):
        """Draw a modern rounded box around text lines."""
        w = width or min(_term_width() - 4, 72)
        inner = w - 2  # space inside box
        
        tl, tr, bl, br, h, v = Display.TL, Display.TR, Display.BL, Display.BR, Display.H, Display.V
        if style == "double":
            tl, tr, bl, br, h, v = '╔', '╗', '╚', '╝', '═', '║'
        elif style == "heavy":
            tl, tr, bl, br, h, v = '┏', '┓', '┗', '┛', '━', '┃'
        
        # Top border (with optional title)
        if title:
            title_str = f" {title} "
            pad = inner - len(title_str)
            left_pad = pad // 2
            right_pad = pad - left_pad
            top = f"  {color}{tl}{h * left_pad}{Colors.BOLD}{title_str}{Colors.RESET}{color}{h * right_pad}{tr}{Colors.RESET}"
        else:
            top = f"  {color}{tl}{h * inner}{tr}{Colors.RESET}"
        
        print(top)
        
        # Content lines
        for line in lines:
            # Strip ANSI for length calculation
            import re
            clean = re.sub(r'\033\[[0-9;]*m', '', line)
            padding = inner - 2 - len(clean)
            if padding < 0:
                padding = 0
                # Truncate if too long
                line = line[:inner - 5] + "..."
            print(f"  {color}{v}{Colors.RESET} {line}{' ' * padding} {color}{v}{Colors.RESET}")
        
        # Bottom border
        print(f"  {color}{bl}{h * inner}{br}{Colors.RESET}")

    @staticmethod
    def _progress_bar(value, max_val, width=20, filled_color=Colors.NEON_GREEN, empty_color=Colors.DARK_GRAY):
        """Create a modern progress bar string."""
        if max_val <= 0:
            pct = 0
        else:
            pct = min(value / max_val, 1.0)
        filled = int(width * pct)
        empty = width - filled
        bar = f"{filled_color}{'█' * filled}{empty_color}{'░' * empty}{Colors.RESET}"
        pct_str = f"{pct * 100:.0f}%"
        return f"{bar} {Colors.BOLD}{pct_str}{Colors.RESET}"

    @staticmethod
    def banner():
        """Show the Zenith banner with modern styling."""
        w = min(_term_width() - 4, 72)
        
        banner_text = f"""
{Colors.CYAN}{Colors.BOLD} ███████╗███████╗███╗   ██╗██╗████████╗██╗  ██╗     █████╗ ██╗
 ╚══███╔╝██╔════╝████╗  ██║██║╚══██╔══╝██║  ██║    ██╔══██╗██║
   ███╔╝ █████╗  ██╔██╗ ██║██║   ██║   ███████║    ███████║██║
  ███╔╝  ██╔══╝  ██║╚██╗██║██║   ██║   ██╔══██║    ██╔══██║██║
 ███████╗███████╗██║ ╚████║██║   ██║   ██║  ██║    ██║  ██║██║
 ╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝   ╚═╝   ╚═╝  ╚═╝    ╚═╝  ╚═╝{Colors.RESET}
"""
        print(banner_text)
        
        Display._box([
            f"{Colors.NEON_GREEN}⚡{Colors.RESET} {Colors.BOLD}Autonomous AI-Powered Security Scanner{Colors.RESET}  {Colors.GRAY}v2.0{Colors.RESET}",
            f"{Colors.TEAL}🤖{Colors.RESET} {Colors.DIM}AI: Gemini / Groq{Colors.RESET}  {Colors.DARK_GRAY}│{Colors.RESET}  {Colors.DIM}Engine: Autonomous AI Agent{Colors.RESET}",
        ], color=Colors.CYAN, style="rounded")
        print()

    @staticmethod
    def section(title):
        """Print a modern section header with double-line box."""
        print()
        Display._box([
            f"{Colors.BOLD}{title}{Colors.RESET}"
        ], color=Colors.CYAN, style="double", title="")
        print()

    @staticmethod
    def subsection(title):
        """Print a modern subsection header."""
        w = min(_term_width() - 4, 60)
        line = Display.H * ((w - len(title) - 4) // 2)
        print(f"\n  {Colors.TEAL}{line} {Colors.BOLD}{title}{Colors.RESET} {Colors.TEAL}{line}{Colors.RESET}\n")

    @staticmethod
    def info(message):
        """Print info message with modern icon."""
        print(f"  {Colors.STEEL_BLUE}›{Colors.RESET} {Colors.BLUE}ℹ{Colors.RESET}  {message}")

    @staticmethod
    def success(message):
        """Print success message with modern icon."""
        print(f"  {Colors.NEON_GREEN}›{Colors.RESET} {Colors.GREEN}✔{Colors.RESET}  {message}")

    @staticmethod
    def warning(message):
        """Print warning message with modern icon."""
        print(f"  {Colors.ORANGE}›{Colors.RESET} {Colors.YELLOW}⚠{Colors.RESET}  {message}")

    @staticmethod
    def error(message):
        """Print error message with modern icon."""
        print(f"  {Colors.NEON_RED}›{Colors.RESET} {Colors.RED}✖{Colors.RESET}  {message}")

    @staticmethod
    def thinking(message):
        """Print AI thinking message with animated-style output."""
        print(f"  {Colors.PURPLE}›{Colors.RESET} {Colors.MAGENTA}🧠{Colors.RESET} {Colors.ITALIC}{Colors.DIM}{message}{Colors.RESET}")

    @staticmethod
    def command(cmd):
        """Print command being executed in a styled box."""
        print()
        print(f"  {Colors.NEON_GREEN}▶{Colors.RESET} {Colors.GREEN}{Colors.BOLD}${Colors.RESET} {Colors.WHITE}{Colors.BOLD}{cmd}{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}{'╌' * min(_term_width() - 6, 68)}{Colors.RESET}")

    @staticmethod
    def output(text, max_lines=30):
        """Print command output in a styled output block."""
        if not text:
            print(f"  {Colors.DARK_GRAY}  ∅ (no output){Colors.RESET}")
            return
        
        lines = text.strip().split('\n')
        shown = lines[:max_lines]
        
        for line in shown:
            # Color-code output lines by content
            if line.strip().startswith("STDERR:") or line.strip().startswith("Traceback"):
                print(f"  {Colors.RED}┃{Colors.RESET} {Colors.DIM}{Colors.RED}{line}{Colors.RESET}")
            elif "⚠" in line or "WARNING" in line.upper():
                print(f"  {Colors.YELLOW}┃{Colors.RESET} {Colors.YELLOW}{line}{Colors.RESET}")
            elif "✔" in line or "✓" in line or "found" in line.lower():
                print(f"  {Colors.GREEN}┃{Colors.RESET} {line}")
            else:
                print(f"  {Colors.DARK_GRAY}┃{Colors.RESET} {line}")
        
        if len(lines) > max_lines:
            print(f"  {Colors.DARK_GRAY}┃ ⋯ ({len(lines) - max_lines} more lines){Colors.RESET}")

    @staticmethod
    def phase(phase_name, phase_num=0):
        """Print current phase with modern card design."""
        phases = {
            "recon": ("🔍", "RECONNAISSANCE", Colors.TEAL, "Discovering target surface..."),
            "scan": ("🔎", "VULNERABILITY SCANNING", Colors.YELLOW, "Probing for weaknesses..."),
            "exploit": ("💥", "EXPLOITATION", Colors.RED, "Testing attack vectors..."),
            "post_exploit": ("🏴", "POST-EXPLOITATION", Colors.MAGENTA, "Deepening access..."),
            "report": ("📋", "REPORTING", Colors.GREEN, "Compiling findings..."),
        }
        emoji, label, color, desc = phases.get(phase_name.lower(), ("⚙️", phase_name.upper(), Colors.CYAN, "Processing..."))
        
        print()
        Display._box([
            f"{emoji}  {color}{Colors.BOLD}PHASE: {label}{Colors.RESET}",
            f"   {Colors.DIM}{Colors.ITALIC}{desc}{Colors.RESET}",
        ], color=color, style="heavy")
        print()

    @staticmethod
    def vulnerability(title, severity, description=""):
        """Print a discovered vulnerability with modern badge."""
        sev_badges = {
            "CRITICAL": (Colors.BG_RED, Colors.WHITE, "🔴"),
            "HIGH": (Colors.NEON_RED, Colors.RED, "🟠"),
            "MEDIUM": (Colors.ORANGE, Colors.YELLOW, "🟡"),
            "LOW": (Colors.STEEL_BLUE, Colors.BLUE, "🔵"),
            "INFO": (Colors.TEAL, Colors.CYAN, "⚪"),
        }
        badge_color, text_color, dot = sev_badges.get(severity.upper(), (Colors.WHITE, Colors.WHITE, "○"))
        
        sev_upper = severity.upper()
        if sev_upper == "CRITICAL":
            print(f"  {Colors.BG_RED}{Colors.WHITE}{Colors.BOLD} {sev_upper} {Colors.RESET} {Colors.BOLD}{title}{Colors.RESET}")
        else:
            print(f"  {dot} {text_color}{Colors.BOLD}[{sev_upper}]{Colors.RESET} {Colors.BOLD}{title}{Colors.RESET}")
        
        if description:
            print(f"    {Colors.GRAY}↳ {description[:100]}{Colors.RESET}")

    @staticmethod
    def stats(ai_stats, exec_stats, vuln_counts, elapsed):
        """Print modern live dashboard with visual indicators."""
        total_cmd = exec_stats.get('total_commands', 0)
        failed_cmd = exec_stats.get('failed_commands', 0)
        success_rate_str = exec_stats.get('success_rate', '0.0%')
        avg_duration = exec_stats.get('avg_duration', 0)
        cache_hits = exec_stats.get('cache_hits', 0)
        ai_calls = ai_stats.get('total_calls', 0)
        
        # Parse success rate for progress bar
        try:
            success_pct = float(success_rate_str.replace('%', ''))
        except (ValueError, AttributeError):
            success_pct = 0
        
        # Dynamic color for success rate
        if success_pct >= 80:
            rate_color = Colors.NEON_GREEN
        elif success_pct >= 50:
            rate_color = Colors.YELLOW
        else:
            rate_color = Colors.RED
        
        # Build vuln summary string
        vuln_parts = []
        total_vulns = 0
        for sev, color, icon in [("CRITICAL", Colors.NEON_RED, "●"), ("HIGH", Colors.RED, "●"), ("MEDIUM", Colors.YELLOW, "●"), ("LOW", Colors.BLUE, "●"), ("INFO", Colors.TEAL, "○")]:
            count = vuln_counts.get(sev, 0)
            total_vulns += count
            if count > 0:
                vuln_parts.append(f"{color}{icon}{count}{Colors.RESET}")
        vuln_str = " ".join(vuln_parts) if vuln_parts else f"{Colors.DIM}none{Colors.RESET}"
        
        # Build the dashboard
        w = min(_term_width() - 4, 72)
        
        print()
        lines = [
            f"{Colors.BOLD}📊 LIVE DASHBOARD{Colors.RESET}                         {Colors.GRAY}⏱ {elapsed}{Colors.RESET}",
            f"",
            f"{Colors.PURPLE}🧠{Colors.RESET} AI Calls  {Colors.BOLD}{ai_calls}{Colors.RESET}    "
            f"{Colors.GREEN}💻{Colors.RESET} Commands  {Colors.BOLD}{total_cmd}{Colors.RESET}    "
            f"{Colors.RED}❌{Colors.RESET} Failed  {Colors.BOLD}{failed_cmd}{Colors.RESET}    "
            f"{Colors.TEAL}⚡{Colors.RESET} Cache  {Colors.BOLD}{cache_hits}{Colors.RESET}",
            f"",
            f"  Success {Display._progress_bar(success_pct, 100, width=25, filled_color=rate_color)}  "
            f"{Colors.GRAY}avg {avg_duration}s{Colors.RESET}",
            f"  Vulns   {vuln_str}  {Colors.GRAY}total: {total_vulns}{Colors.RESET}",
        ]
        Display._box(lines, color=Colors.STEEL_BLUE, style="rounded", title="─── ZENITH ───")

    @staticmethod
    def iteration_card(iteration, max_iter, reasoning, expected="", script_info=""):
        """Print a modern iteration info card (optional, called from scanner if desired)."""
        pbar = Display._progress_bar(iteration, max_iter, width=20)
        lines = [
            f"{Colors.BOLD}Iteration {iteration}/{max_iter}{Colors.RESET}  {pbar}",
            f"",
            f"{Colors.PURPLE}🧠{Colors.RESET} {Colors.DIM}{reasoning[:90]}{Colors.RESET}",
        ]
        if expected:
            lines.append(f"{Colors.TEAL}🎯{Colors.RESET} {Colors.DIM}{expected[:80]}{Colors.RESET}")
        if script_info:
            lines.append(f"{Colors.GREEN}📝{Colors.RESET} {Colors.DIM}{script_info}{Colors.RESET}")
        
        Display._box(lines, color=Colors.PURPLE, style="rounded")

    @staticmethod
    def final_report(report_data, report_file):
        """Print final report summary with modern card design."""
        if isinstance(report_data, dict):
            summary = report_data.get("executive_summary", "No summary available")
            risk = report_data.get("risk_rating", "UNKNOWN")
            
            risk_styles = {
                "CRITICAL": (Colors.BG_RED, Colors.NEON_RED, "🔴"),
                "HIGH": (Colors.RED, Colors.RED, "🟠"),
                "MEDIUM": (Colors.YELLOW, Colors.YELLOW, "🟡"),
                "LOW": (Colors.BLUE, Colors.BLUE, "🔵"),
            }
            bg, fg, icon = risk_styles.get(risk, (Colors.WHITE, Colors.WHITE, "⚪"))
            
            # Risk badge
            if risk == "CRITICAL":
                risk_badge = f"{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD} {risk} {Colors.RESET}"
            else:
                risk_badge = f"{fg}{Colors.BOLD}{icon} {risk}{Colors.RESET}"
            
            lines = [
                f"{Colors.BOLD}📋 ZENITH AI - SECURITY REPORT{Colors.RESET}",
                f"",
                f"  Risk Rating:  {risk_badge}",
                f"",
            ]
            
            # Word-wrap summary
            words = summary.split()
            line_buf = "  "
            for word in words:
                if len(line_buf) + len(word) + 1 > 66:
                    lines.append(f"{Colors.DIM}{line_buf}{Colors.RESET}")
                    line_buf = "  " + word
                else:
                    line_buf += " " + word if line_buf.strip() else "  " + word
            if line_buf.strip():
                lines.append(f"{Colors.DIM}{line_buf}{Colors.RESET}")
            
            # Findings
            findings = report_data.get("critical_findings", report_data.get("all_findings", []))
            if findings:
                lines.append(f"")
                lines.append(f"  {Colors.BOLD}Key Findings:{Colors.RESET}")
                for i, f in enumerate(findings[:8], 1):
                    if isinstance(f, dict):
                        sev = f.get("severity", "INFO")
                        title = f.get("title", "Unknown")[:50]
                        sev_colors_map = {"CRITICAL": Colors.NEON_RED, "HIGH": Colors.RED, "MEDIUM": Colors.YELLOW, "LOW": Colors.BLUE}
                        sc = sev_colors_map.get(sev, Colors.GRAY)
                        lines.append(f"  {sc}▪{Colors.RESET} {sc}[{sev}]{Colors.RESET} {title}")
            
            lines.append(f"")
            lines.append(f"  {Colors.GREEN}✔ Report saved: {report_file}{Colors.RESET}")
            
            Display._box(lines, color=Colors.CYAN, style="double")
        else:
            print(f"\n  {Colors.GREEN}✔ Report saved: {report_file}{Colors.RESET}")
        print()

    @staticmethod
    def progress(current, description=""):
        """Print progress indicator with modern spinner."""
        spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        idx = current % len(spinner)
        print(f"\r  {Colors.CYAN}{spinner[idx]}{Colors.RESET} {description}", end="", flush=True)

    @staticmethod
    def scan_complete_banner(duration, vulns_found, commands_run):
        """Print a scan-complete banner."""
        lines = [
            f"{Colors.NEON_GREEN}{Colors.BOLD}✔ SCAN COMPLETE{Colors.RESET}",
            f"",
            f"  ⏱ Duration      {Colors.BOLD}{duration}{Colors.RESET}",
            f"  🔓 Vulns Found   {Colors.BOLD}{vulns_found}{Colors.RESET}",
            f"  💻 Commands      {Colors.BOLD}{commands_run}{Colors.RESET}",
        ]
        Display._box(lines, color=Colors.GREEN, style="double")
