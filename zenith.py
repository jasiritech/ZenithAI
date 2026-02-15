#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║               ZENITH AI SECURITY SCANNER                  ║
║         Autonomous AI-Powered Vulnerability Scanner        ║
║                                                           ║
║  Usage:                                                   ║
║    python3 zenith.py                    (interactive)     ║
║    python3 zenith.py --target URL       (direct)          ║
║    python3 zenith.py --config config.json                 ║
╚═══════════════════════════════════════════════════════════╝
"""

import argparse
import json
import os
import sys
import getpass

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from zenith.core.scanner import ZenithScanner
from zenith.utils.display import Display, Colors


def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def interactive_setup():
    """Simple interactive setup - API key, target, and go."""
    
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
{Colors.CYAN}  Powered by Gemini 2.5 Pro/Flash  │  Fully Autonomous{Colors.RESET}
{Colors.DIM}  ─────────────────────────────────────────────────────{Colors.RESET}
""")

    # ═══════════════════════════════════════
    # STEP 1: API KEY
    # ═══════════════════════════════════════
    print(f"  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}  🔑  GEMINI API KEY{Colors.RESET}")
    print(f"  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.DIM}  Get yours free: https://aistudio.google.com/apikey{Colors.RESET}")
    print()

    # Check environment variable first
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

    # ═══════════════════════════════════════
    # STEP 2: TARGET
    # ═══════════════════════════════════════
    print(f"\n  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}  🎯  TARGET{Colors.RESET}")
    print(f"  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.DIM}  Example: https://example.com or 192.168.1.1{Colors.RESET}")
    print()
    
    target = input(f"  {Colors.YELLOW}  Enter target: {Colors.RESET}").strip()
    
    if not target:
        print(f"\n  {Colors.RED}  [✗] Target is required!{Colors.RESET}")
        sys.exit(1)

    # ═══════════════════════════════════════
    # STEP 3: GOAL (optional, with default)
    # ═══════════════════════════════════════
    print(f"\n  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}  📋  GOAL {Colors.DIM}(optional - press Enter to skip){Colors.RESET}")
    print(f"  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.DIM}  Example: Find SQL injection, Check for XSS, etc.{Colors.RESET}")
    print()
    
    goal = input(f"  {Colors.YELLOW}  Goal [full scan]: {Colors.RESET}").strip()
    
    if not goal:
        goal = f"Perform a comprehensive security assessment on {target}. Find all vulnerabilities including web vulnerabilities, misconfigurations, exposed sensitive data, and any security weaknesses. Be thorough and systematic."

    # ═══════════════════════════════════════
    # STEP 4: MODEL SELECTION
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
    # CONFIRM & LAUNCH
    # ═══════════════════════════════════════
    model_display = f"{Colors.MAGENTA}Gemini 2.5 Pro{Colors.RESET}" if model == "pro" else f"{Colors.GREEN}Gemini 2.5 Flash{Colors.RESET}"
    
    print(f"\n  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.CYAN}{Colors.BOLD}  🚀  READY TO LAUNCH{Colors.RESET}")
    print(f"  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print(f"  {Colors.BOLD}  Target:{Colors.RESET}  {target}")
    print(f"  {Colors.BOLD}  Model:{Colors.RESET}   {model_display}")
    print(f"  {Colors.BOLD}  Goal:{Colors.RESET}    {goal[:50]}...")
    print(f"  {Colors.CYAN}{'━' * 52}{Colors.RESET}")
    print()
    
    confirm = input(f"  {Colors.YELLOW}{Colors.BOLD}  Launch scan? [Y/n]: {Colors.RESET}").strip().lower()
    
    if confirm == 'n':
        print(f"\n  {Colors.RED}  Scan cancelled.{Colors.RESET}")
        sys.exit(0)

    return api_key, target, goal, model, 100


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Zenith AI Security Scanner - Autonomous AI-Powered Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 zenith.py                                    # Interactive mode
  python3 zenith.py -t https://example.com             # Quick scan
  python3 zenith.py -t 192.168.1.1 -m pro             # Use Gemini Pro
  python3 zenith.py -t https://example.com -g "Find SQL injection vulnerabilities"
  python3 zenith.py --config scan_config.json          # Use config file
        """
    )
    
    parser.add_argument('-t', '--target', help='Target URL or IP address')
    parser.add_argument('-k', '--api-key', help='Gemini API key (or set GEMINI_API_KEY env var)')
    parser.add_argument('-m', '--model', choices=['pro', 'flash'], default='flash',
                       help='AI model: pro (deep thinking) or flash (fast)')
    parser.add_argument('-g', '--goal', help='Scanning goal description')
    parser.add_argument('-i', '--max-iterations', type=int, default=100,
                       help='Maximum AI iterations (default: 100)')
    parser.add_argument('-o', '--output-dir', help='Output directory for reports')
    parser.add_argument('--config', help='Path to JSON config file')
    
    return parser.parse_args()


def load_config(config_path):
    """Load configuration from JSON file."""
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"  {Colors.RED}[!] Failed to load config: {e}{Colors.RESET}")
        sys.exit(1)


def main():
    """Main entry point."""
    args = parse_args()

    # Config file mode
    if args.config:
        config = load_config(args.config)
        api_key = config.get('api_key', os.environ.get('GEMINI_API_KEY', ''))
        target = config.get('target', '')
        goal = config.get('goal', '')
        model = config.get('model', 'flash')
        max_iterations = config.get('max_iterations', 100)
        output_dir = config.get('output_dir', None)
    
    # Direct CLI mode
    elif args.target:
        api_key = args.api_key or os.environ.get('GEMINI_API_KEY', '')
        if not api_key:
            api_key = input("Enter Gemini API Key: ").strip()
        target = args.target
        goal = args.goal or f"Perform a comprehensive security assessment on {target}"
        model = args.model
        max_iterations = min(args.max_iterations, 200)
        output_dir = args.output_dir
    
    # Interactive mode
    else:
        api_key, target, goal, model, max_iterations = interactive_setup()
        output_dir = None

    # Validate
    if not api_key:
        print(f"  {Colors.RED}[!] Gemini API key is required!{Colors.RESET}")
        print(f"  {Colors.DIM}Set GEMINI_API_KEY environment variable or use -k flag{Colors.RESET}")
        sys.exit(1)
    
    if not target:
        print(f"  {Colors.RED}[!] Target is required!{Colors.RESET}")
        sys.exit(1)

    # Create and run scanner
    try:
        scanner = ZenithScanner(
            api_key=api_key,
            target=target,
            goal=goal,
            model=model,
            max_iterations=max_iterations,
            working_dir=output_dir
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
