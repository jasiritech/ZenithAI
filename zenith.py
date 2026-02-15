#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║               ZENITH AI SECURITY SCANNER v2.0             ║
║         Autonomous AI-Powered Vulnerability Scanner        ║
║                                                           ║
║  Usage:                                                   ║
║    python3 zenith.py                    (interactive)     ║
║    python3 zenith.py --target URL       (direct)          ║
║    python3 zenith.py --resume SESSION   (resume scan)     ║
║    python3 zenith.py --sessions         (list sessions)   ║
║    python3 zenith.py --tor -t URL       (scan via Tor)    ║
║    python3 zenith.py --config config.json                 ║
╚═══════════════════════════════════════════════════════════╝
"""

import argparse
import json
import os
import sys
import re

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from zenith.core.scanner import ZenithScanner
from zenith.core.session import SessionManager
from zenith.core.profiles import PROFILES, get_profile, get_profile_goal, list_profiles
from zenith.utils.display import Display, Colors


# ═══════════════════════════════════════════════════════════
# TARGET VALIDATION - Prevents shell commands as targets
# ═══════════════════════════════════════════════════════════

# Shell commands that users might accidentally type as target
SHELL_COMMANDS = [
    'cd ', 'ls', 'rm ', 'git ', 'cat ', 'echo ', 'mkdir ', 'mv ', 'cp ',
    'chmod ', 'sudo ', 'apt ', 'pip ', 'python', 'nano ', 'vi ', 'vim ',
    'wget ', 'curl ', 'ssh ', 'scp ', 'tar ', 'unzip ', 'grep ', 'find ',
    'kill ', 'ps ', 'top', 'htop', 'ifconfig', 'ip ', 'ping ', 'traceroute ',
    'systemctl ', 'service ', 'docker ', 'npm ', 'node ', 'go ', 'make',
    'bash', 'sh ', 'export ', 'source ', './', 'pwd', 'whoami', 'uname',
]


def validate_target(target):
    """
    Validate that a target is a real hostname/IP/URL/CIDR, not a shell command.
    
    Args:
        target: The user-provided target string
        
    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    """
    if not target or not target.strip():
        return False, "Target cannot be empty."

    target = target.strip()

    # Block shell commands
    target_lower = target.lower()
    for cmd in SHELL_COMMANDS:
        if target_lower.startswith(cmd) or target_lower == cmd.strip():
            return False, (
                f"'{target}' looks like a shell command, not a target!\n"
                f"    Enter a URL, IP address, or domain name instead.\n"
                f"    Examples: https://example.com, 192.168.1.1, example.com"
            )

    # Block paths
    if target.startswith('/') or target.startswith('~') or target.startswith('..'):
        if not re.match(r'^\d', target):  # Not starting with digit (not a CIDR)
            return False, (
                f"'{target}' looks like a file path, not a target!\n"
                f"    Enter a URL, IP address, or domain name."
            )

    # Block targets with spaces (except query params in URLs)
    if ' ' in target and not target.startswith('http'):
        return False, (
            f"Target cannot contain spaces.\n"
            f"    Enter a single URL, IP address, or domain name.\n"
            f"    Examples: https://example.com, 192.168.1.1, example.com"
        )

    # Validate against known patterns
    valid_patterns = [
        r'^https?://\S+',                                    # URL
        r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$',  # IP or CIDR
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}',  # Domain
        r'^[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}',                   # Short domain
    ]

    for pattern in valid_patterns:
        if re.match(pattern, target):
            return True, None

    return False, (
        f"'{target}' doesn't look like a valid target.\n"
        f"    Accepted formats:\n"
        f"      • URL:    https://example.com or http://192.168.1.1:8080\n"
        f"      • IP:     192.168.1.1\n"
        f"      • CIDR:   10.0.0.0/24\n"
        f"      • Domain: example.com or sub.example.com"
    )


def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def show_sessions():
    """Show all saved scan sessions."""
    mgr = SessionManager()
    sessions = mgr.get_resumable_sessions()

    print(f"\n  {Colors.CYAN}{Colors.BOLD}📋 Saved Sessions{Colors.RESET}")
    print(f"  {Colors.CYAN}{'━' * 60}{Colors.RESET}")

    if not sessions:
        print(f"  {Colors.DIM}  No sessions found.{Colors.RESET}\n")
        return

    for s in sessions:
        status_icon = "🟡" if s.get("status") == "interrupted" else "🔴" if s.get("status") == "failed" else "🟢"
        target = s.get("target", "?")
        sid = s.get("session_id", "?")
        iteration = s.get("current_iteration", 0)
        phase = s.get("current_phase", "?")
        print(f"  {status_icon} {Colors.BOLD}{sid}{Colors.RESET}")
        print(f"     Target: {target}  │  Phase: {phase}  │  Iteration: {iteration}")
        print(f"     {Colors.DIM}Resume: python3 zenith.py --resume {sid}{Colors.RESET}")
        print()

    print(f"  {Colors.CYAN}{'━' * 60}{Colors.RESET}\n")


def interactive_setup():
    """
    Full interactive setup with target validation, scan profiles,
    proxy support, and session resume.
    
    Returns:
        tuple: (api_key, target, goal, model, max_iterations, 
                profile_name, proxy_config, notify_config, sudo_password, resume_session)
    """
    clear_screen()

    # ═══════════════════════════════════════
    # BANNER
    # ═══════════════════════════════════════
    print(f"""
{Colors.CYAN}{Colors.BOLD}
 ███████╗███████╗███╗   ██╗██╗████████╗██╗  ██╗     █████╗ ██╗
 ╚══███╔╝██╔════╝████╗  ██║██║╚══██╔══╝██║  ██║    ██╔══██╗██║
   ███╔╝ █████╗  ██╔██╗ ██║██║   ██║   ███████║    ███████║██║
  ███╔╝  ██╔══╝  ██║╚██╗██║██║   ██║   ██╔══██║    ██╔══██║██║
 ███████╗███████╗██║ ╚████║██║   ██║   ██║  ██║    ██║  ██║██║
 ╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝   ╚═╝   ╚═╝  ╚═╝    ╚═╝  ╚═╝
{Colors.RESET}
{Colors.YELLOW}  ⚡ Autonomous AI-Powered Security Scanner v2.0{Colors.RESET}
{Colors.DIM}  ─────────────────────────────────────────────────────{Colors.RESET}
{Colors.CYAN}  Model: Gemini 2.5 Pro/Flash  │  Engine: Autonomous AI Agent{Colors.RESET}
{Colors.DIM}  ─────────────────────────────────────────────────────{Colors.RESET}
""")

    # ═══════════════════════════════════════
    # CHECK FOR RESUMABLE SESSIONS
    # ═══════════════════════════════════════
    session_mgr = SessionManager()
    resumable = session_mgr.get_resumable_sessions()
    resume_session = None

    if resumable:
        print(f"  {Colors.YELLOW}{'━' * 52}{Colors.RESET}")
        print(f"  {Colors.YELLOW}{Colors.BOLD}  📂  RESUMABLE SESSIONS FOUND{Colors.RESET}")
        print(f"  {Colors.YELLOW}{'━' * 52}{Colors.RESET}")
        for i, s in enumerate(resumable[:5], 1):
            target_disp = s.get("target", "?")[:30]
            phase = s.get("current_phase", "?")
            itr = s.get("current_iteration", 0)
            print(f"  {Colors.GREEN}  [{i}]{Colors.RESET} {target_disp} {Colors.DIM}(phase: {phase}, iter: {itr}){Colors.RESET}")
        print(f"  {Colors.DIM}  [0] Start a new scan{Colors.RESET}")
        print()

        resume_choice = input(f"  {Colors.YELLOW}  Resume a session? [0]: {Colors.RESET}").strip()
        if resume_choice and resume_choice != '0':
            try:
                idx = int(resume_choice) - 1
                if 0 <= idx < len(resumable):
                    session = resumable[idx]
                    resume_session = session.get("session_id")
                    # For resume, we still need the API key
                    print(f"\n  {Colors.GREEN}  [✓] Will resume: {resume_session}{Colors.RESET}")
            except (ValueError, IndexError):
                pass
        print()

    # ═══════════════════════════════════════
    # STEP 1: API KEY
    # ═══════════════════════════════════════
    print(f"  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}  🔑  GEMINI API KEY{Colors.RESET}")
    print(f"  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.DIM}  Get yours free: https://aistudio.google.com/apikey{Colors.RESET}")
    print()

    api_key = os.environ.get("GEMINI_API_KEY", "")
    if api_key:
        masked = api_key[:8] + "..." + api_key[-4:]
        print(f"  {Colors.GREEN}  [✓] Found API key: {masked}{Colors.RESET}")
        use_env = input(f"\n  {Colors.YELLOW}  Use this key? [Y/n]: {Colors.RESET}").strip().lower()
        if use_env == 'n':
            api_key = ""

    if not api_key:
        api_key = input(f"\n  {Colors.YELLOW}  Enter API Key: {Colors.RESET}").strip()

    if not api_key:
        print(f"\n  {Colors.RED}  [✗] API key is required!{Colors.RESET}")
        sys.exit(1)

    # If resuming, load session data and skip target/goal/profile
    if resume_session:
        session_data = session_mgr.load_session(resume_session)
        if session_data:
            target = session_data.get("target", "")
            goal = session_data.get("goal", "")
            model = session_data.get("model", "flash")
            max_iter = session_data.get("max_iterations", 100)
            return api_key, target, goal, model, max_iter, None, None, None, None, resume_session
        else:
            print(f"  {Colors.RED}  [✗] Failed to load session. Starting new scan.{Colors.RESET}")
            resume_session = None

    # ═══════════════════════════════════════
    # STEP 2: TARGET (with validation!)
    # ═══════════════════════════════════════
    print(f"\n  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}  🎯  TARGET{Colors.RESET}")
    print(f"  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.DIM}  URL:    https://example.com{Colors.RESET}")
    print(f"  {Colors.DIM}  IP:     192.168.1.1{Colors.RESET}")
    print(f"  {Colors.DIM}  Domain: example.com{Colors.RESET}")
    print(f"  {Colors.DIM}  CIDR:   10.0.0.0/24{Colors.RESET}")
    print()

    while True:
        target = input(f"  {Colors.YELLOW}  Enter target: {Colors.RESET}").strip()

        if not target:
            print(f"  {Colors.RED}  [✗] Target is required!{Colors.RESET}")
            continue

        is_valid, error_msg = validate_target(target)
        if is_valid:
            break
        else:
            print(f"  {Colors.RED}  [✗] {error_msg}{Colors.RESET}\n")

    # ═══════════════════════════════════════
    # STEP 3: SCAN PROFILE
    # ═══════════════════════════════════════
    print(f"\n  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}  📋  SCAN PROFILE{Colors.RESET}")
    print(f"  {Colors.CYAN}{'━' * 52}{Colors.RESET}")

    profile_list = list_profiles()
    profile_keys = [k for k, _, _ in profile_list]
    for i, (key, name, desc) in enumerate(profile_list, 1):
        print(f"  {Colors.GREEN}  [{i}]{Colors.RESET} {name} {Colors.DIM}- {desc}{Colors.RESET}")
    print(f"  {Colors.DIM}  [0] Custom goal (type your own){Colors.RESET}")
    print()

    profile_choice = input(f"  {Colors.YELLOW}  Choose profile [0]: {Colors.RESET}").strip()
    profile_name = None
    goal = None
    max_iterations = 100

    if profile_choice and profile_choice != '0':
        try:
            idx = int(profile_choice) - 1
            if 0 <= idx < len(profile_keys):
                profile_name = profile_keys[idx]
                profile = get_profile(profile_name)
                goal = get_profile_goal(profile_name, target)
                max_iterations = profile["max_iterations"]
                print(f"  {Colors.GREEN}  [✓] Profile: {profile['name']}{Colors.RESET}")
                print(f"  {Colors.DIM}  Max iterations: {max_iterations}{Colors.RESET}")
        except (ValueError, IndexError):
            pass

    # ═══════════════════════════════════════
    # STEP 4: GOAL (if no profile selected)
    # ═══════════════════════════════════════
    if not goal:
        print(f"\n  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
        print(f"  {Colors.CYAN}{Colors.BOLD}  🎯  GOAL {Colors.DIM}(press Enter for full scan){Colors.RESET}")
        print(f"  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
        print(f"  {Colors.DIM}  Example: Find SQL injection, Check for XSS, etc.{Colors.RESET}")
        print()

        goal = input(f"  {Colors.YELLOW}  Goal [full scan]: {Colors.RESET}").strip()

        if not goal:
            goal = (
                f"Perform a comprehensive security assessment on {target}. "
                f"Find all vulnerabilities including web vulnerabilities, misconfigurations, "
                f"exposed sensitive data, and any security weaknesses. Be thorough and systematic."
            )

    # ═══════════════════════════════════════
    # STEP 5: AI MODEL
    # ═══════════════════════════════════════
    print(f"\n  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}  🧠  AI MODEL{Colors.RESET}")
    print(f"  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.GREEN}  [1]{Colors.RESET} Gemini 2.5 Flash  {Colors.DIM}(fast, recommended){Colors.RESET}")
    print(f"  {Colors.MAGENTA}  [2]{Colors.RESET} Gemini 2.5 Pro    {Colors.DIM}(deep thinking, slower){Colors.RESET}")
    print()

    model_choice = input(f"  {Colors.YELLOW}  Choose [1]: {Colors.RESET}").strip()
    model = "pro" if model_choice == "2" else "flash"

    # ═══════════════════════════════════════
    # STEP 6: PROXY / TOR (optional)
    # ═══════════════════════════════════════
    proxy_config = None
    print(f"\n  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}  🔒  PROXY / TOR {Colors.DIM}(optional){Colors.RESET}")
    print(f"  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.GREEN}  [0]{Colors.RESET} No proxy {Colors.DIM}(direct connection){Colors.RESET}")
    print(f"  {Colors.GREEN}  [1]{Colors.RESET} Tor {Colors.DIM}(route through Tor network){Colors.RESET}")
    print(f"  {Colors.GREEN}  [2]{Colors.RESET} Proxychains {Colors.DIM}(use proxychains config){Colors.RESET}")
    print(f"  {Colors.GREEN}  [3]{Colors.RESET} Custom proxy {Colors.DIM}(HTTP/SOCKS5){Colors.RESET}")
    print()

    proxy_choice = input(f"  {Colors.YELLOW}  Choose [0]: {Colors.RESET}").strip()

    if proxy_choice == "1":
        proxy_config = {"type": "tor"}
        print(f"  {Colors.GREEN}  [✓] Tor proxy enabled{Colors.RESET}")
    elif proxy_choice == "2":
        proxy_config = {"type": "proxychains"}
        print(f"  {Colors.GREEN}  [✓] Proxychains enabled{Colors.RESET}")
    elif proxy_choice == "3":
        proxy_url = input(f"  {Colors.YELLOW}  Proxy URL (e.g. socks5://127.0.0.1:1080): {Colors.RESET}").strip()
        if proxy_url:
            if "socks5" in proxy_url:
                proxy_config = {"type": "socks5", "host": proxy_url}
            elif "socks4" in proxy_url:
                proxy_config = {"type": "socks4", "host": proxy_url}
            else:
                proxy_config = {"type": "http", "host": proxy_url}
            print(f"  {Colors.GREEN}  [✓] Custom proxy: {proxy_url}{Colors.RESET}")

    # ═══════════════════════════════════════
    # STEP 7: SUDO PASSWORD (optional)
    # ═══════════════════════════════════════
    sudo_password = None
    print(f"\n  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}  🔓  SUDO PASSWORD {Colors.DIM}(optional - press Enter to skip){Colors.RESET}")
    print(f"  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.DIM}  Needed for: apt install, service restart, etc.{Colors.RESET}")
    print(f"  {Colors.DIM}  Skip if your user has passwordless sudo.{Colors.RESET}")
    print()

    import getpass
    sudo_input = getpass.getpass(f"  {Colors.YELLOW}  Sudo password (hidden): {Colors.RESET}").strip()
    if sudo_input:
        sudo_password = sudo_input
        print(f"  {Colors.GREEN}  [✓] Sudo password saved (will auto-pipe to sudo commands){Colors.RESET}")
    else:
        print(f"  {Colors.DIM}  [ℹ] Skipped - sudo commands may fail if password required{Colors.RESET}")

    # ═══════════════════════════════════════
    # STEP 8: NOTIFICATIONS (optional)
    # ═══════════════════════════════════════
    notify_config = None
    telegram_token = os.environ.get("ZENITH_TELEGRAM_TOKEN", "")
    telegram_chat = os.environ.get("ZENITH_TELEGRAM_CHAT_ID", "")

    if telegram_token and telegram_chat:
        print(f"\n  {Colors.GREEN}  [✓] Telegram notifications detected from env{Colors.RESET}")
        notify_config = {
            "telegram": {"token": telegram_token, "chat_id": telegram_chat}
        }

    # ═══════════════════════════════════════
    # CONFIRM & LAUNCH
    # ═══════════════════════════════════════
    model_display = f"{Colors.MAGENTA}Gemini 2.5 Pro{Colors.RESET}" if model == "pro" else f"{Colors.GREEN}Gemini 2.5 Flash{Colors.RESET}"
    profile_display = profile_name or "custom"
    proxy_display = proxy_config["type"] if proxy_config else "none"

    print(f"\n  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}  🚀  READY TO LAUNCH{Colors.RESET}")
    print(f"  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.BOLD}    Target:{Colors.RESET}  {target}")
    print(f"  {Colors.BOLD}    Model:{Colors.RESET}   {model_display}")
    print(f"  {Colors.BOLD}    Profile:{Colors.RESET} {profile_display}")
    print(f"  {Colors.BOLD}    Proxy:{Colors.RESET}   {proxy_display}")
    print(f"  {Colors.BOLD}    Goal:{Colors.RESET}    {goal[:60]}...")
    print(f"  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print()

    confirm = input(f"  {Colors.YELLOW}{Colors.BOLD}    Launch scan? [Y/n]: {Colors.RESET}").strip().lower()

    if confirm == 'n':
        print(f"\n  {Colors.RED}  Scan cancelled.{Colors.RESET}")
        sys.exit(0)

    return api_key, target, goal, model, max_iterations, profile_name, proxy_config, notify_config, sudo_password, None


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Zenith AI Security Scanner - Autonomous AI-Powered Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 zenith.py                                     # Interactive mode
  python3 zenith.py -t https://example.com              # Quick scan
  python3 zenith.py -t 192.168.1.1 -m pro              # Use Gemini Pro
  python3 zenith.py -t example.com -p web               # Web app profile
  python3 zenith.py -t example.com --tor                # Scan via Tor
  python3 zenith.py --resume zenith_123456_example      # Resume session
  python3 zenith.py --sessions                          # List sessions
  python3 zenith.py -t https://example.com -g "Find SQL injection vulnerabilities"
  python3 zenith.py --config scan_config.json           # Use config file

Profiles: quick, full, stealth, web, network, api, recon-only
        """
    )

    parser.add_argument('-t', '--target', help='Target URL, IP address, or domain')
    parser.add_argument('-k', '--api-key', help='Gemini API key (or set GEMINI_API_KEY env var)')
    parser.add_argument('-m', '--model', choices=['pro', 'flash'], default='flash',
                       help='AI model: pro (deep thinking) or flash (fast)')
    parser.add_argument('-g', '--goal', help='Scanning goal description')
    parser.add_argument('-p', '--profile',
                       choices=['quick', 'full', 'stealth', 'web', 'network', 'api', 'recon-only'],
                       help='Scan profile (overrides --goal)')
    parser.add_argument('-i', '--max-iterations', type=int, default=100,
                       help='Maximum AI iterations (default: 100)')
    parser.add_argument('-o', '--output-dir', help='Output directory for reports')
    parser.add_argument('--config', help='Path to JSON config file')
    parser.add_argument('--tor', action='store_true', help='Route scan traffic through Tor')
    parser.add_argument('--proxy', help='Proxy URL (e.g. socks5://127.0.0.1:1080)')
    parser.add_argument('--resume', metavar='SESSION_ID', help='Resume an interrupted scan session')
    parser.add_argument('--sessions', action='store_true', help='List all saved scan sessions')
    parser.add_argument('--sudo', action='store_true', help='Prompt for sudo password (for apt install, etc.)')

    return parser.parse_args()


def load_config(config_path):
    """Load configuration from JSON file."""
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"  {Colors.RED}[!] Failed to load config: {e}{Colors.RESET}")
        sys.exit(1)


def build_proxy_config(args):
    """Build proxy config from CLI args."""
    if args.tor:
        return {"type": "tor"}
    if args.proxy:
        url = args.proxy
        if "socks5" in url:
            return {"type": "socks5", "host": url}
        elif "socks4" in url:
            return {"type": "socks4", "host": url}
        else:
            return {"type": "http", "host": url}
    return None


def get_sudo_password(args):
    """Prompt for sudo password if --sudo flag is set."""
    if hasattr(args, 'sudo') and args.sudo:
        import getpass
        pwd = getpass.getpass(f"  {Colors.YELLOW}Enter sudo password: {Colors.RESET}").strip()
        if pwd:
            print(f"  {Colors.GREEN}[✓] Sudo password configured{Colors.RESET}")
            return pwd
    return None


def main():
    """Main entry point."""
    args = parse_args()

    # ═══════════════════════════════════════
    # LIST SESSIONS MODE
    # ═══════════════════════════════════════
    if args.sessions:
        show_sessions()
        sys.exit(0)

    # ═══════════════════════════════════════
    # RESUME MODE
    # ═══════════════════════════════════════
    if args.resume:
        api_key = args.api_key or os.environ.get('GEMINI_API_KEY', '')
        if not api_key:
            api_key = input("  Enter Gemini API Key: ").strip()
        if not api_key:
            print(f"  {Colors.RED}[!] API key required to resume!{Colors.RESET}")
            sys.exit(1)

        mgr = SessionManager()
        session_data = mgr.load_session(args.resume)
        if not session_data:
            print(f"  {Colors.RED}[!] Session '{args.resume}' not found!{Colors.RESET}")
            show_sessions()
            sys.exit(1)

        sudo_password = get_sudo_password(args)

        try:
            scanner = ZenithScanner(
                api_key=api_key,
                target=session_data.get("target", ""),
                goal=session_data.get("goal", ""),
                model=session_data.get("model", "flash"),
                max_iterations=session_data.get("max_iterations", 100),
                resume_session=args.resume,
                proxy_config=build_proxy_config(args),
                sudo_password=sudo_password,
            )
            scanner.run()
        except KeyboardInterrupt:
            print(f"\n  {Colors.YELLOW}[!] Scan interrupted by user.{Colors.RESET}")
        except Exception as e:
            print(f"\n  {Colors.RED}[!] Fatal error: {e}{Colors.RESET}")
            import traceback
            traceback.print_exc()
        sys.exit(0)

    # ═══════════════════════════════════════
    # CONFIG FILE MODE
    # ═══════════════════════════════════════
    if args.config:
        config = load_config(args.config)
        api_key = config.get('api_key', os.environ.get('GEMINI_API_KEY', ''))
        target = config.get('target', '')
        goal = config.get('goal', '')
        model = config.get('model', 'flash')
        max_iterations = config.get('max_iterations', 100)
        output_dir = config.get('output_dir', None)
        profile_name = config.get('profile', None)
        proxy_config = config.get('proxy', None)
        notify_config = config.get('notifications', None)

    # ═══════════════════════════════════════
    # CLI MODE
    # ═══════════════════════════════════════
    elif args.target:
        api_key = args.api_key or os.environ.get('GEMINI_API_KEY', '')
        if not api_key:
            api_key = input("  Enter Gemini API Key: ").strip()
        target = args.target
        model = args.model
        max_iterations = min(args.max_iterations, 200)
        output_dir = args.output_dir
        proxy_config = build_proxy_config(args)
        notify_config = None
        profile_name = args.profile
        sudo_password = get_sudo_password(args)

        # Use profile goal or custom goal
        if profile_name:
            goal = get_profile_goal(profile_name, target)
            profile_data = get_profile(profile_name)
            if profile_data:
                max_iterations = profile_data["max_iterations"]
        else:
            goal = args.goal or f"Perform a comprehensive security assessment on {target}"

        # Validate target
        is_valid, error_msg = validate_target(target)
        if not is_valid:
            print(f"  {Colors.RED}[!] Invalid target: {error_msg}{Colors.RESET}")
            sys.exit(1)

    # ═══════════════════════════════════════
    # INTERACTIVE MODE
    # ═══════════════════════════════════════
    else:
        result = interactive_setup()
        api_key, target, goal, model, max_iterations = result[:5]
        profile_name = result[5]
        proxy_config = result[6]
        notify_config = result[7]
        sudo_password = result[8]
        resume_session = result[9]
        output_dir = None

        # Handle resume from interactive mode
        if resume_session:
            try:
                scanner = ZenithScanner(
                    api_key=api_key, target=target, goal=goal,
                    model=model, max_iterations=max_iterations,
                    resume_session=resume_session, proxy_config=proxy_config,
                    notify_config=notify_config, sudo_password=sudo_password,
                )
                scanner.run()
            except KeyboardInterrupt:
                print(f"\n  {Colors.YELLOW}[!] Scan interrupted by user.{Colors.RESET}")
            except Exception as e:
                print(f"\n  {Colors.RED}[!] Fatal error: {e}{Colors.RESET}")
                import traceback
                traceback.print_exc()
            sys.exit(0)

    # ═══════════════════════════════════════
    # VALIDATE
    # ═══════════════════════════════════════
    if not api_key:
        print(f"  {Colors.RED}[!] Gemini API key is required!{Colors.RESET}")
        print(f"  {Colors.DIM}Set GEMINI_API_KEY environment variable or use -k flag{Colors.RESET}")
        sys.exit(1)

    if not target:
        print(f"  {Colors.RED}[!] Target is required!{Colors.RESET}")
        sys.exit(1)

    # ═══════════════════════════════════════
    # CREATE AND RUN SCANNER
    # ═══════════════════════════════════════
    # Get sudo_password if not set by interactive/CLI mode
    try:
        sudo_password
    except NameError:
        sudo_password = None

    try:
        scanner = ZenithScanner(
            api_key=api_key,
            target=target,
            goal=goal,
            model=model,
            max_iterations=max_iterations,
            working_dir=output_dir,
            profile=profile_name,
            proxy_config=proxy_config,
            notify_config=notify_config,
            sudo_password=sudo_password,
        )
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n  {Colors.YELLOW}[!] Scan interrupted by user.{Colors.RESET}")
    except Exception as e:
        print(f"\n  {Colors.RED}[!] Fatal error: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
