"""
Zenith Telegram Bot - Remote control and live monitoring via Telegram.

Features:
    - Natural language command parsing
    - Live log streaming (real-time updates)
    - Progress tracking with visual bars
    - Report delivery
    - Multi-session support

Usage:
    1. Set TELEGRAM_BOT_TOKEN in config.json or environment
    2. Start the bot: bot.start()
    3. Send commands via Telegram
"""

import asyncio
import logging
import html
import time
from datetime import datetime
from typing import Optional, Dict, Any, Callable, List
from dataclasses import dataclass, field

try:
    from telegram import Update, Bot, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import (
        Application, CommandHandler, MessageHandler, 
        CallbackQueryHandler, ContextTypes, filters
    )
    from telegram.constants import ParseMode, ChatAction
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False

from zenith.bot.command_parser import CommandParser


@dataclass
class ScanSession:
    """Represents an active scan session."""
    session_id: str
    target: str
    profile: str
    chat_id: int
    message_id: Optional[int] = None  # Message to update with live logs
    status: str = "pending"  # pending, running, paused, completed, failed
    started_at: float = field(default_factory=time.time)
    logs: List[str] = field(default_factory=list)
    progress: int = 0
    phase: str = "Initializing"


class TelegramBot:
    """
    Telegram Bot for remote ZenithAI control.
    
    Provides:
        - Command parsing (natural language)
        - Live log streaming
        - Progress updates
        - Report delivery
    """

    def __init__(
        self, 
        token: str, 
        scanner=None,
        ai_brain=None,
        allowed_users: Optional[List[int]] = None,
        admin_users: Optional[List[int]] = None
    ):
        """
        Initialize Telegram bot.
        
        Args:
            token: Telegram Bot API token
            scanner: ZenithScanner instance
            ai_brain: AIBrain instance for command parsing
            allowed_users: List of allowed user IDs (None = all)
            admin_users: List of admin user IDs
        """
        if not TELEGRAM_AVAILABLE:
            raise ImportError(
                "python-telegram-bot not installed. "
                "Install with: pip install python-telegram-bot"
            )

        self.token = token
        self.scanner = scanner
        self.parser = CommandParser(ai_brain)
        self.allowed_users = set(allowed_users) if allowed_users else None
        self.admin_users = set(admin_users) if admin_users else set()
        
        # Session tracking
        self.sessions: Dict[str, ScanSession] = {}
        self.active_session: Optional[str] = None
        
        # Log streaming
        self.log_buffer: List[str] = []
        self.last_update: float = 0
        self.update_interval: float = 2.0  # Seconds between message updates
        
        # Application
        self.app: Optional[Application] = None
        self._running = False

        # Logger
        self.logger = logging.getLogger("zenith.telegram")

    async def start(self):
        """Start the Telegram bot."""
        self.app = Application.builder().token(self.token).build()
        
        # Register handlers
        self.app.add_handler(CommandHandler("start", self._cmd_start))
        self.app.add_handler(CommandHandler("help", self._cmd_help))
        self.app.add_handler(CommandHandler("scan", self._cmd_scan))
        self.app.add_handler(CommandHandler("status", self._cmd_status))
        self.app.add_handler(CommandHandler("stop", self._cmd_stop))
        self.app.add_handler(CommandHandler("pause", self._cmd_pause))
        self.app.add_handler(CommandHandler("resume", self._cmd_resume))
        self.app.add_handler(CommandHandler("report", self._cmd_report))
        self.app.add_handler(CommandHandler("sessions", self._cmd_sessions))
        
        # Natural language handler (for messages without /)
        self.app.add_handler(MessageHandler(
            filters.TEXT & ~filters.COMMAND, 
            self._handle_message
        ))
        
        # Callback query handler for buttons
        self.app.add_handler(CallbackQueryHandler(self._handle_callback))
        
        # Error handler
        self.app.add_error_handler(self._handle_error)
        
        self._running = True
        self.logger.info("🤖 Telegram bot started")
        
        # Start polling
        await self.app.initialize()
        await self.app.start()
        await self.app.updater.start_polling(drop_pending_updates=True)

    async def stop(self):
        """Stop the Telegram bot."""
        self._running = False
        if self.app:
            await self.app.updater.stop()
            await self.app.stop()
            await self.app.shutdown()
        self.logger.info("🤖 Telegram bot stopped")

    def is_authorized(self, user_id: int) -> bool:
        """Check if user is authorized."""
        if self.allowed_users is None:
            return True
        return user_id in self.allowed_users or user_id in self.admin_users

    def is_admin(self, user_id: int) -> bool:
        """Check if user is admin."""
        return user_id in self.admin_users

    # ========== Command Handlers ==========

    async def _cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command."""
        user = update.effective_user
        
        if not self.is_authorized(user.id):
            await update.message.reply_text("⛔ Unauthorized. Contact admin.")
            return

        welcome = f"""
🚀 *Welcome to ZenithAI, {html.escape(user.first_name)}!*

I'm your AI-powered security scanner. I can:

• 🔍 Scan targets for vulnerabilities
• 📊 Stream live progress updates
• 📝 Generate detailed reports
• 🤖 Understand natural language commands

*Quick Start:*
Just send me a URL and I'll scan it!

Or use commands like:
• `/scan https://target.com`
• `/status` - Check progress
• `/help` - All commands

_Let's hunt some bugs!_ 🎯
"""
        await update.message.reply_text(
            welcome, 
            parse_mode=ParseMode.MARKDOWN
        )

    async def _cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command."""
        if not self.is_authorized(update.effective_user.id):
            return
        
        await update.message.reply_text(
            self.parser.get_help_text(),
            parse_mode=ParseMode.MARKDOWN
        )

    async def _cmd_scan(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /scan command."""
        user = update.effective_user
        if not self.is_authorized(user.id):
            await update.message.reply_text("⛔ Unauthorized")
            return

        # Get target from args
        if not context.args:
            await update.message.reply_text(
                "❓ Please provide a target.\n"
                "Example: `/scan https://example.com`",
                parse_mode=ParseMode.MARKDOWN
            )
            return

        target = context.args[0]
        profile = context.args[1] if len(context.args) > 1 else "quick"
        
        await self._start_scan(update, target, profile)

    async def _cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /status command."""
        if not self.is_authorized(update.effective_user.id):
            return

        if not self.active_session or self.active_session not in self.sessions:
            await update.message.reply_text("ℹ️ No active scan.")
            return

        session = self.sessions[self.active_session]
        await update.message.reply_text(
            self._format_status(session),
            parse_mode=ParseMode.MARKDOWN
        )

    async def _cmd_stop(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /stop command."""
        if not self.is_authorized(update.effective_user.id):
            return

        if not self.active_session:
            await update.message.reply_text("ℹ️ No active scan to stop.")
            return

        session = self.sessions[self.active_session]
        session.status = "stopped"
        
        # Signal scanner to stop
        if self.scanner:
            self.scanner.stop()

        await update.message.reply_text(
            f"🛑 Stopped scan: `{session.target}`",
            parse_mode=ParseMode.MARKDOWN
        )
        
        self.active_session = None

    async def _cmd_pause(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /pause command."""
        if not self.is_authorized(update.effective_user.id):
            return

        if not self.active_session:
            await update.message.reply_text("ℹ️ No active scan to pause.")
            return

        session = self.sessions[self.active_session]
        session.status = "paused"
        
        await update.message.reply_text(
            f"⏸️ Paused scan: `{session.target}`\nUse /resume to continue.",
            parse_mode=ParseMode.MARKDOWN
        )

    async def _cmd_resume(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /resume command."""
        if not self.is_authorized(update.effective_user.id):
            return

        if not self.active_session:
            await update.message.reply_text("ℹ️ No paused scan to resume.")
            return

        session = self.sessions[self.active_session]
        if session.status != "paused":
            await update.message.reply_text("ℹ️ Scan is not paused.")
            return

        session.status = "running"
        await update.message.reply_text(
            f"▶️ Resumed scan: `{session.target}`",
            parse_mode=ParseMode.MARKDOWN
        )

    async def _cmd_report(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /report command."""
        if not self.is_authorized(update.effective_user.id):
            return

        # Get session
        session_id = context.args[0] if context.args else self.active_session
        
        if not session_id or session_id not in self.sessions:
            await update.message.reply_text("ℹ️ No session found for report.")
            return

        session = self.sessions[session_id]
        
        # Send typing action
        await update.message.chat.send_action(ChatAction.UPLOAD_DOCUMENT)
        
        # Generate report (if scanner available)
        if self.scanner:
            report_path = self.scanner.generate_report(session_id)
            if report_path:
                await update.message.reply_document(
                    document=open(report_path, 'rb'),
                    caption=f"📊 Report: {session.target}"
                )
                return

        # Fallback: text summary
        summary = self._generate_text_report(session)
        await update.message.reply_text(summary, parse_mode=ParseMode.MARKDOWN)

    async def _cmd_sessions(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /sessions command."""
        if not self.is_authorized(update.effective_user.id):
            return

        if not self.sessions:
            await update.message.reply_text("ℹ️ No sessions yet.")
            return

        lines = ["📋 *Scan Sessions:*\n"]
        for sid, session in list(self.sessions.items())[-10:]:  # Last 10
            status_emoji = {
                "running": "🟢",
                "paused": "⏸️",
                "completed": "✅",
                "failed": "❌",
                "stopped": "🛑"
            }.get(session.status, "⚪")
            
            lines.append(
                f"{status_emoji} `{sid[:8]}` - {session.target} ({session.status})"
            )

        await update.message.reply_text(
            "\n".join(lines),
            parse_mode=ParseMode.MARKDOWN
        )

    # ========== Message Handlers ==========

    async def _handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle natural language messages."""
        user = update.effective_user
        if not self.is_authorized(user.id):
            return

        text = update.message.text
        
        # Parse command
        parsed = self.parser.parse(text)
        
        if parsed.get("error"):
            await update.message.reply_text(
                f"❓ {parsed['error']}\n\nType /help for commands.",
                parse_mode=ParseMode.MARKDOWN
            )
            return

        action = parsed.get("action")
        
        if action == "scan":
            await self._start_scan(
                update, 
                parsed["target"], 
                parsed.get("profile", "quick")
            )
        elif action == "status":
            await self._cmd_status(update, context)
        elif action == "stop":
            await self._cmd_stop(update, context)
        elif action == "pause":
            await self._cmd_pause(update, context)
        elif action == "resume":
            await self._cmd_resume(update, context)
        elif action == "report":
            await self._cmd_report(update, context)
        elif action == "help":
            await self._cmd_help(update, context)
        elif action == "sessions":
            await self._cmd_sessions(update, context)
        else:
            await update.message.reply_text(
                "🤔 I didn't understand that. Try /help",
                parse_mode=ParseMode.MARKDOWN
            )

    async def _handle_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle inline button callbacks."""
        query = update.callback_query
        await query.answer()
        
        data = query.data
        
        if data.startswith("scan:"):
            # Quick action button
            _, target, profile = data.split(":", 2)
            await self._start_scan(update, target, profile, query.message)
        elif data == "stop":
            await self._cmd_stop(update, context)
        elif data == "status":
            await self._cmd_status(update, context)

    async def _handle_error(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle errors."""
        self.logger.error(f"Telegram error: {context.error}")
        
        if update and update.effective_message:
            await update.effective_message.reply_text(
                "⚠️ An error occurred. Please try again."
            )

    # ========== Scan Operations ==========

    async def _start_scan(
        self, 
        update: Update, 
        target: str, 
        profile: str,
        reply_to: Optional[Any] = None
    ):
        """Start a new scan."""
        chat_id = update.effective_chat.id
        
        # Check for active scan
        if self.active_session:
            session = self.sessions.get(self.active_session)
            if session and session.status == "running":
                await (reply_to or update.message).reply_text(
                    f"⚠️ Scan already running: `{session.target}`\n"
                    "Use /stop to cancel first.",
                    parse_mode=ParseMode.MARKDOWN
                )
                return

        # Create session
        session_id = f"{int(time.time())}_{hash(target) % 10000:04d}"
        session = ScanSession(
            session_id=session_id,
            target=target,
            profile=profile,
            chat_id=chat_id,
            status="running"
        )
        
        self.sessions[session_id] = session
        self.active_session = session_id

        # Send initial message
        msg = await (reply_to or update.message).reply_text(
            self._format_live_status(session),
            parse_mode=ParseMode.MARKDOWN
        )
        session.message_id = msg.message_id

        # Start scan in background
        asyncio.create_task(self._run_scan(session))

    async def _run_scan(self, session: ScanSession):
        """Run the scan and stream updates."""
        try:
            session.phase = "🔍 Reconnaissance"
            await self._update_live_message(session)

            if self.scanner:
                # Real scan with callbacks
                await self._run_real_scan(session)
            else:
                # Demo mode
                await self._run_demo_scan(session)

            session.status = "completed"
            session.phase = "✅ Complete"
            session.progress = 100
            await self._send_completion_message(session)

        except Exception as e:
            session.status = "failed"
            session.phase = f"❌ Failed: {str(e)}"
            await self._update_live_message(session)
            self.logger.error(f"Scan failed: {e}")

    async def _run_real_scan(self, session: ScanSession):
        """Run actual scan with scanner."""
        # This connects to the ZenithScanner
        # The scanner should call self.log() which we hook into
        
        def log_callback(msg: str, level: str = "info"):
            session.logs.append(f"[{level.upper()}] {msg}")
            asyncio.create_task(self._update_live_message(session))

        def progress_callback(phase: str, progress: int):
            session.phase = phase
            session.progress = progress
            asyncio.create_task(self._update_live_message(session))

        # Run scanner with callbacks
        await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self.scanner.scan(
                target=session.target,
                profile=session.profile,
                log_callback=log_callback,
                progress_callback=progress_callback
            )
        )

    async def _run_demo_scan(self, session: ScanSession):
        """Demo scan for testing without scanner."""
        phases = [
            ("🔍 Reconnaissance", 20, [
                "Starting reconnaissance...",
                "Resolving DNS for target...",
                "Found 3 subdomains",
            ]),
            ("🌐 Port Scanning", 40, [
                "Scanning common ports...",
                "Port 80/tcp open - HTTP",
                "Port 443/tcp open - HTTPS",
                "Port 22/tcp open - SSH",
            ]),
            ("🔬 Vulnerability Scan", 70, [
                "Running Nuclei scanner...",
                "Checking for common CVEs...",
                "[HIGH] SQL Injection found in /api/users",
                "[MEDIUM] Missing security headers",
            ]),
            ("📊 Finalizing", 90, [
                "Generating report...",
                "Saving results...",
            ]),
        ]

        for phase, progress, logs in phases:
            if session.status == "stopped":
                return
            
            while session.status == "paused":
                await asyncio.sleep(1)

            session.phase = phase
            session.progress = progress
            
            for log in logs:
                session.logs.append(log)
                await self._update_live_message(session)
                await asyncio.sleep(1.5)

    # ========== Live Updates ==========

    async def _update_live_message(self, session: ScanSession):
        """Update the live status message."""
        now = time.time()
        
        # Rate limit updates
        if now - self.last_update < self.update_interval:
            return
        self.last_update = now

        if not session.message_id:
            return

        try:
            bot = self.app.bot
            await bot.edit_message_text(
                chat_id=session.chat_id,
                message_id=session.message_id,
                text=self._format_live_status(session),
                parse_mode=ParseMode.MARKDOWN
            )
        except Exception as e:
            # Message unchanged or other error
            pass

    def _format_live_status(self, session: ScanSession) -> str:
        """Format live status message."""
        # Progress bar
        filled = int(session.progress / 5)
        bar = "█" * filled + "░" * (20 - filled)
        
        # Recent logs (last 8)
        logs = session.logs[-8:] if session.logs else ["Initializing..."]
        log_text = "\n".join(f"• {log}" for log in logs)
        
        # Status emoji
        status_emoji = {
            "running": "🟢",
            "paused": "⏸️",
            "completed": "✅",
            "failed": "❌",
            "stopped": "🛑"
        }.get(session.status, "⚪")

        return f"""
{status_emoji} *Scanning:* `{session.target}`
*Profile:* {session.profile.upper()}
*Phase:* {session.phase}

`[{bar}] {session.progress}%`

*Live Logs:*
```
{log_text}
```

_Updated: {datetime.now().strftime("%H:%M:%S")}_
"""

    def _format_status(self, session: ScanSession) -> str:
        """Format detailed status."""
        elapsed = int(time.time() - session.started_at)
        mins, secs = divmod(elapsed, 60)
        
        return f"""
📊 *Scan Status*

*Target:* `{session.target}`
*Profile:* {session.profile}
*Status:* {session.status.upper()}
*Phase:* {session.phase}
*Progress:* {session.progress}%
*Elapsed:* {mins}m {secs}s
*Logs:* {len(session.logs)} entries
"""

    async def _send_completion_message(self, session: ScanSession):
        """Send completion notification."""
        bot = self.app.bot
        
        # Keyboard with actions
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("📊 View Report", callback_data="report"),
                InlineKeyboardButton("🔄 Scan Again", callback_data=f"scan:{session.target}:{session.profile}")
            ]
        ])
        
        await bot.send_message(
            chat_id=session.chat_id,
            text=f"""
✅ *Scan Complete!*

*Target:* `{session.target}`
*Duration:* {int(time.time() - session.started_at)}s
*Findings:* Check report for details

Use /report to get the full report.
""",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=keyboard
        )

    def _generate_text_report(self, session: ScanSession) -> str:
        """Generate text-based report summary."""
        return f"""
📊 *Scan Report*

*Target:* `{session.target}`
*Profile:* {session.profile}
*Status:* {session.status}
*Duration:* {int(time.time() - session.started_at)}s

*Log Summary:*
{chr(10).join(session.logs[-15:])}

_Full report available via scanner._
"""

    # ========== Log Streaming API ==========

    def log(self, message: str, level: str = "info"):
        """
        Log a message (can be called from scanner).
        
        This enables real-time log streaming to Telegram.
        """
        if self.active_session and self.active_session in self.sessions:
            session = self.sessions[self.active_session]
            session.logs.append(f"[{level.upper()}] {message}")
            
            # Schedule update
            if self._running and self.app:
                asyncio.create_task(self._update_live_message(session))

    def set_progress(self, phase: str, progress: int):
        """
        Set scan progress (can be called from scanner).
        """
        if self.active_session and self.active_session in self.sessions:
            session = self.sessions[self.active_session]
            session.phase = phase
            session.progress = progress
            
            if self._running and self.app:
                asyncio.create_task(self._update_live_message(session))
