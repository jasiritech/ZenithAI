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


def interactive_setup():
    """Interactive setup - asks the user questions and starts the scan."""
    
    Display.banner()
    Display.section("INTERACTIVE SETUP")

    # ─── API KEY ───
    print(f"  {Colors.CYAN}[1/4] Gemini API Key{Colors.RESET}")
    print(f"  {Colors.DIM}Get your API key here: https://aistudio.google.com/apikey{Colors.RESET}")
    
    # Check environment variable first
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if api_key:
        print(f"  {Colors.GREEN}[✓] API key found in environment variable GEMINI_API_KEY{Colors.RESET}")
        use_env = input(f"  {Colors.YELLOW}Use this key? (y/n): {Colors.RESET}").strip().lower()
        if use_env != 'y':
            api_key = ""
    
    if not api_key:
        api_key = getpass.getpass(f"  {Colors.YELLOW}Enter Gemini API Key: {Colors.RESET}")
    
    if not api_key:
        print(f"  {Colors.RED}[!] API key is required!{Colors.RESET}")
        sys.exit(1)

    # ─── MODEL ───
    print(f"\n  {Colors.CYAN}[2/4] Choose AI Model{Colors.RESET}")
    print(f"  {Colors.DIM}  1. Gemini 2.5 Flash (fast, recommended){Colors.RESET}")
    print(f"  {Colors.DIM}  2. Gemini 2.5 Pro (deep thinking, slower){Colors.RESET}")
    
    model_choice = input(f"  {Colors.YELLOW}Choose (1/2) [default: 1]: {Colors.RESET}").strip()
    model = "pro" if model_choice == "2" else "flash"

    # ─── TARGET ───
    print(f"\n  {Colors.CYAN}[3/4] Target{Colors.RESET}")
    target = input(f"  {Colors.YELLOW}Enter target (URL or IP): {Colors.RESET}").strip()
    
    if not target:
        print(f"  {Colors.RED}[!] Target is required!{Colors.RESET}")
        sys.exit(1)

    # ─── GOAL ───
    print(f"\n  {Colors.CYAN}[4/4] Goal (Optional){Colors.RESET}")
    print(f"  {Colors.DIM}Example: 'Find all web vulnerabilities', 'Check for SQL injection'{Colors.RESET}")
    print(f"  {Colors.DIM}Press Enter for default (full vulnerability scan){Colors.RESET}")
    
    goal = input(f"  {Colors.YELLOW}Goal: {Colors.RESET}").strip()
    
    if not goal:
        goal = f"Perform a comprehensive security assessment on {target}. Find all vulnerabilities including web vulnerabilities, misconfigurations, exposed sensitive data, and any security weaknesses. Be thorough and systematic."

    # ─── MAX ITERATIONS ───
    print(f"\n  {Colors.DIM}Advanced: Max iterations (default: 100, max: 200){Colors.RESET}")
    max_iter_input = input(f"  {Colors.YELLOW}Max iterations [100]: {Colors.RESET}").strip()
    try:
        max_iterations = min(int(max_iter_input), 200) if max_iter_input else 100
    except ValueError:
        max_iterations = 100

    # ─── CONFIRM ───
    print(f"\n  {Colors.CYAN}{'─' * 50}{Colors.RESET}")
    print(f"  {Colors.BOLD}Configuration Summary:{Colors.RESET}")
    print(f"  {Colors.DIM}Target:{Colors.RESET}     {target}")
    print(f"  {Colors.DIM}Model:{Colors.RESET}      Gemini 2.5 {'Pro' if model == 'pro' else 'Flash'}")
    print(f"  {Colors.DIM}Goal:{Colors.RESET}       {goal[:60]}...")
    print(f"  {Colors.DIM}Max Iter:{Colors.RESET}   {max_iterations}")
    print(f"  {Colors.CYAN}{'─' * 50}{Colors.RESET}")
    
    confirm = input(f"\n  {Colors.YELLOW}Start scan? (y/n): {Colors.RESET}").strip().lower()
    
    if confirm != 'y':
        print(f"  {Colors.RED}Scan cancelled.{Colors.RESET}")
        sys.exit(0)

    return api_key, target, goal, model, max_iterations


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
            api_key = getpass.getpass("Enter Gemini API Key: ")
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
