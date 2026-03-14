"""
Zenith Bot Runner - Start and manage Telegram/WhatsApp bots.

This module integrates the scanner with messaging bots for remote control.

Usage:
    # Start Telegram bot
    python -m zenith.bot.runner --telegram
    
    # Start WhatsApp bot
    python -m zenith.bot.runner --whatsapp
    
    # Start both
    python -m zenith.bot.runner --both

Configuration:
    Set these in config.json or environment:
    
    For Telegram:
        TELEGRAM_BOT_TOKEN - Your bot token from @BotFather
        TELEGRAM_ALLOWED_USERS - Comma-separated user IDs (optional)
        TELEGRAM_ADMIN_USERS - Comma-separated admin user IDs (optional)
    
    For WhatsApp:
        Just run and scan QR code!
"""

import asyncio
import argparse
import json
import os
import sys
import logging
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from zenith.bot import TelegramBot, WhatsAppBot
from zenith.core.ai_brain import AIBrain


# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("zenith.bot.runner")


class BotIntegratedScanner:
    """
    Scanner wrapper that integrates with bots for callbacks.
    
    Provides log_callback and progress_callback for real-time updates.
    """

    def __init__(self, bot):
        """
        Initialize with a bot instance.
        
        Args:
            bot: TelegramBot or WhatsAppBot instance
        """
        self.bot = bot
        self._stop_flag = False

    def stop(self):
        """Signal scan to stop."""
        self._stop_flag = True

    def scan(self, target: str, profile: str = "quick", 
             log_callback=None, progress_callback=None):
        """
        Run a scan with callbacks for the bot.
        
        Args:
            target: Target URL/IP
            profile: Scan profile name
            log_callback: Function to call with log messages
            progress_callback: Function to call with (phase, progress)
        """
        from zenith.core.scanner import ZenithScanner
        
        # Get API key from environment or config
        api_key = self._get_api_key()
        if not api_key:
            if log_callback:
                log_callback("ERROR: No API key configured!", "error")
            return

        self._stop_flag = False

        try:
            # Create scanner with bot callbacks
            scanner = ZenithScanner(
                api_key=api_key,
                target=target,
                profile=profile
            )

            # Hook into scanner for progress updates
            original_run = scanner.run
            
            def wrapped_run():
                """Run scanner with progress callbacks."""
                phases = ["recon", "scan", "exploit", "report"]
                phase_progress = {
                    "recon": (0, 25),
                    "scan": (25, 60),
                    "exploit": (60, 85),
                    "report": (85, 100)
                }

                # Initial callback
                if progress_callback:
                    progress_callback("🔍 Reconnaissance", 0)
                if log_callback:
                    log_callback(f"Starting {profile} scan on {target}")

                # Track phase changes
                last_phase = "recon"
                
                # Override the phase display
                original_phase = scanner.current_phase
                
                while scanner.running and scanner.iteration < scanner.max_iterations:
                    # Check stop flag
                    if self._stop_flag:
                        scanner.running = False
                        if log_callback:
                            log_callback("Scan stopped by user", "warning")
                        break

                    # Update progress on phase change
                    if scanner.current_phase != last_phase:
                        last_phase = scanner.current_phase
                        phase_emoji = {
                            "recon": "🔍",
                            "scan": "🔬",
                            "exploit": "💥",
                            "report": "📊"
                        }.get(last_phase, "⚙️")
                        
                        if progress_callback:
                            start, _ = phase_progress.get(last_phase, (0, 100))
                            progress_callback(f"{phase_emoji} {last_phase.title()}", start)
                        
                        if log_callback:
                            log_callback(f"Phase: {last_phase.upper()}")

                    # Run single iteration
                    try:
                        scanner._run_iteration()
                    except Exception as e:
                        if log_callback:
                            log_callback(f"Error: {str(e)[:50]}", "error")

                    # Calculate progress within phase
                    if progress_callback:
                        phase_start, phase_end = phase_progress.get(last_phase, (0, 100))
                        phase_progress_pct = min(
                            scanner.phase_iteration * 5,  # 5% per iteration
                            phase_end - phase_start
                        )
                        total_progress = phase_start + phase_progress_pct
                        progress_callback(
                            f"{last_phase.title()}: Iteration {scanner.phase_iteration}",
                            int(total_progress)
                        )

                # Completion
                if progress_callback:
                    progress_callback("✅ Complete", 100)
                if log_callback:
                    vuln_count = sum(scanner.kb.get_vulnerability_count().values())
                    log_callback(f"Scan complete! Found {vuln_count} vulnerabilities")

            # Run the wrapped scanner
            wrapped_run()

        except Exception as e:
            if log_callback:
                log_callback(f"Scanner error: {str(e)}", "error")
            raise

    def generate_report(self, session_id: str) -> str:
        """Generate report for a session (placeholder)."""
        # TODO: Integrate with actual report generation
        return None

    def _get_api_key(self) -> str:
        """Get API key from config or environment."""
        # Try environment
        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GROQ_API_KEY")
        if api_key:
            return api_key

        # Try config file
        config_paths = [
            Path("config.json"),
            Path.home() / ".zenith" / "config.json"
        ]
        
        for path in config_paths:
            if path.exists():
                try:
                    config = json.loads(path.read_text())
                    return config.get("gemini_api_key") or config.get("groq_api_key")
                except Exception:
                    pass

        return None


def load_config() -> dict:
    """Load configuration from file or environment."""
    config = {}

    # Try config file
    config_paths = [
        Path("config.json"),
        Path.home() / ".zenith" / "config.json"
    ]
    
    for path in config_paths:
        if path.exists():
            try:
                config = json.loads(path.read_text())
                break
            except Exception:
                pass

    # Override with environment
    if os.environ.get("TELEGRAM_BOT_TOKEN"):
        config["telegram_token"] = os.environ["TELEGRAM_BOT_TOKEN"]
    
    if os.environ.get("TELEGRAM_ALLOWED_USERS"):
        config["telegram_allowed_users"] = [
            int(x.strip()) for x in os.environ["TELEGRAM_ALLOWED_USERS"].split(",")
        ]

    if os.environ.get("TELEGRAM_ADMIN_USERS"):
        config["telegram_admin_users"] = [
            int(x.strip()) for x in os.environ["TELEGRAM_ADMIN_USERS"].split(",")
        ]

    return config


async def run_telegram_bot(config: dict):
    """Run Telegram bot."""
    token = config.get("telegram_token")
    if not token:
        logger.error("TELEGRAM_BOT_TOKEN not set!")
        logger.info("Get a token from @BotFather on Telegram")
        return

    # Initialize AI brain for command parsing
    ai = None
    api_key = config.get("gemini_api_key") or os.environ.get("GEMINI_API_KEY")
    if api_key:
        ai = AIBrain(api_key)

    # Create bot
    bot = TelegramBot(
        token=token,
        ai_brain=ai,
        allowed_users=config.get("telegram_allowed_users"),
        admin_users=config.get("telegram_admin_users")
    )

    # Create integrated scanner
    scanner = BotIntegratedScanner(bot)
    bot.scanner = scanner

    logger.info("🚀 Starting Telegram bot...")
    await bot.start()

    # Keep running
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass
    finally:
        await bot.stop()


async def run_whatsapp_bot(config: dict):
    """Run WhatsApp bot."""
    # Initialize AI brain for command parsing
    ai = None
    api_key = config.get("gemini_api_key") or os.environ.get("GEMINI_API_KEY")
    if api_key:
        ai = AIBrain(api_key)

    # Create bot
    bot = WhatsAppBot(
        ai_brain=ai,
        allowed_numbers=config.get("whatsapp_allowed_numbers"),
        admin_numbers=config.get("whatsapp_admin_numbers")
    )

    # Create integrated scanner
    scanner = BotIntegratedScanner(bot)
    bot.scanner = scanner

    logger.info("📱 Starting WhatsApp bot...")
    logger.info("   A QR code will appear - scan it with WhatsApp")
    
    await bot.start()

    # Keep running
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass
    finally:
        await bot.stop()


async def run_both(config: dict):
    """Run both Telegram and WhatsApp bots."""
    logger.info("🤖 Starting both Telegram and WhatsApp bots...")
    
    tasks = [
        asyncio.create_task(run_telegram_bot(config)),
        asyncio.create_task(run_whatsapp_bot(config))
    ]
    
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        for task in tasks:
            task.cancel()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="ZenithAI Bot Runner - Remote control via Telegram/WhatsApp",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Start Telegram bot
    python -m zenith.bot.runner --telegram
    
    # Start WhatsApp bot  
    python -m zenith.bot.runner --whatsapp
    
    # Start both
    python -m zenith.bot.runner --both

Environment Variables:
    TELEGRAM_BOT_TOKEN      Your Telegram bot token
    TELEGRAM_ALLOWED_USERS  Comma-separated user IDs
    GEMINI_API_KEY          API key for AI features
"""
    )
    
    parser.add_argument(
        "--telegram", "-t",
        action="store_true",
        help="Start Telegram bot"
    )
    parser.add_argument(
        "--whatsapp", "-w",
        action="store_true",
        help="Start WhatsApp bot"
    )
    parser.add_argument(
        "--both", "-b",
        action="store_true",
        help="Start both bots"
    )
    parser.add_argument(
        "--config", "-c",
        type=str,
        default=None,
        help="Path to config file"
    )

    args = parser.parse_args()

    # Load config
    if args.config:
        config = json.loads(Path(args.config).read_text())
    else:
        config = load_config()

    # Run appropriate bot(s)
    if args.both:
        asyncio.run(run_both(config))
    elif args.whatsapp:
        asyncio.run(run_whatsapp_bot(config))
    elif args.telegram:
        asyncio.run(run_telegram_bot(config))
    else:
        # Default to Telegram if no option specified
        print("Usage: python -m zenith.bot.runner --telegram | --whatsapp | --both")
        print()
        print("Start the ZenithAI remote control bot.")
        print("Use --telegram for Telegram, --whatsapp for WhatsApp, or --both.")
        sys.exit(1)


if __name__ == "__main__":
    main()
