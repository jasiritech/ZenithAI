"""
Zenith WhatsApp Bot - Remote control and live monitoring via WhatsApp.

Uses WhatsApp Web.js / Baileys approach via a bridge script.

Features:
    - Natural language command parsing
    - Live log streaming
    - Progress tracking
    - Report delivery via WhatsApp
    - QR code authentication

Architecture:
    Python <---> Node.js Bridge (Baileys/whatsapp-web.js) <---> WhatsApp

Usage:
    1. Install Node.js dependencies: npm install whatsapp-web.js qrcode-terminal
    2. Run the bridge: node whatsapp_bridge.js
    3. Scan QR code with WhatsApp
    4. Start sending commands!
"""

import asyncio
import json
import logging
import subprocess
import threading
import time
import os
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, field


from zenith.bot.command_parser import CommandParser


@dataclass
class WhatsAppSession:
    """Represents an active scan session."""
    session_id: str
    target: str
    profile: str
    chat_id: str  # WhatsApp chat/phone number
    status: str = "pending"
    started_at: float = field(default_factory=time.time)
    logs: List[str] = field(default_factory=list)
    progress: int = 0
    phase: str = "Initializing"


class WhatsAppBot:
    """
    WhatsApp Bot for remote ZenithAI control.
    
    Uses a Node.js bridge (Baileys or whatsapp-web.js) for WhatsApp communication.
    Python handles the logic, Node.js handles WhatsApp protocol.
    """

    BRIDGE_SCRIPT = """
// WhatsApp Bridge Script for ZenithAI
// Save as whatsapp_bridge.js and run with: node whatsapp_bridge.js

const { Client, LocalAuth, MessageMedia } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
const readline = require('readline');

// Create client
const client = new Client({
    authStrategy: new LocalAuth({ dataPath: '.zenith_whatsapp' }),
    puppeteer: {
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    }
});

// QR Code display
client.on('qr', (qr) => {
    console.log('ZENITH_QR_START');
    qrcode.generate(qr, { small: true });
    console.log('ZENITH_QR_END');
    console.log('Scan the QR code above with WhatsApp');
});

// Ready
client.on('ready', () => {
    console.log('ZENITH_READY');
    console.log('WhatsApp bot is ready!');
});

// Authenticated
client.on('authenticated', () => {
    console.log('ZENITH_AUTHENTICATED');
});

// Disconnected
client.on('disconnected', (reason) => {
    console.log('ZENITH_DISCONNECTED:' + reason);
});

// Message handler
client.on('message', async (message) => {
    // Only process direct messages (not groups unless specified)
    const chat = await message.getChat();
    
    // Output message for Python to process
    const data = {
        type: 'message',
        from: message.from,
        body: message.body,
        timestamp: message.timestamp,
        isGroup: chat.isGroup,
        chatName: chat.name
    };
    console.log('ZENITH_MSG:' + JSON.stringify(data));
});

// Send message function
function sendMessage(to, text) {
    client.sendMessage(to, text).then(() => {
        console.log('ZENITH_SENT:' + to);
    }).catch(err => {
        console.log('ZENITH_ERROR:' + err.message);
    });
}

// Send media function  
function sendMedia(to, filePath, caption) {
    const media = MessageMedia.fromFilePath(filePath);
    client.sendMessage(to, media, { caption }).then(() => {
        console.log('ZENITH_MEDIA_SENT:' + to);
    }).catch(err => {
        console.log('ZENITH_ERROR:' + err.message);
    });
}

// Read commands from stdin
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false
});

rl.on('line', (line) => {
    try {
        const cmd = JSON.parse(line);
        if (cmd.action === 'send') {
            sendMessage(cmd.to, cmd.text);
        } else if (cmd.action === 'media') {
            sendMedia(cmd.to, cmd.path, cmd.caption || '');
        } else if (cmd.action === 'stop') {
            client.destroy();
            process.exit(0);
        }
    } catch (e) {
        console.log('ZENITH_ERROR:Invalid command');
    }
});

// Initialize
console.log('ZENITH_INIT');
client.initialize();
"""

    def __init__(
        self,
        scanner=None,
        ai_brain=None,
        allowed_numbers: Optional[List[str]] = None,
        admin_numbers: Optional[List[str]] = None,
        bridge_path: Optional[str] = None
    ):
        """
        Initialize WhatsApp bot.
        
        Args:
            scanner: ZenithScanner instance
            ai_brain: AIBrain instance
            allowed_numbers: List of allowed phone numbers (None = all)
            admin_numbers: List of admin phone numbers
            bridge_path: Path to Node.js bridge script
        """
        self.scanner = scanner
        self.parser = CommandParser(ai_brain)
        self.allowed_numbers = set(allowed_numbers) if allowed_numbers else None
        self.admin_numbers = set(admin_numbers) if admin_numbers else set()
        self.bridge_path = bridge_path or self._setup_bridge()

        # Session tracking
        self.sessions: Dict[str, WhatsAppSession] = {}
        self.active_session: Optional[str] = None

        # Bridge process
        self.bridge_process: Optional[subprocess.Popen] = None
        self._running = False
        self._reader_thread: Optional[threading.Thread] = None

        # Message queue
        self._message_queue: asyncio.Queue = asyncio.Queue()
        
        # Logger
        self.logger = logging.getLogger("zenith.whatsapp")

    def _setup_bridge(self) -> str:
        """Create the bridge script if needed."""
        bridge_dir = Path.home() / ".zenith" / "whatsapp"
        bridge_dir.mkdir(parents=True, exist_ok=True)
        
        bridge_path = bridge_dir / "whatsapp_bridge.js"
        
        # Write bridge script
        bridge_path.write_text(self.BRIDGE_SCRIPT)
        
        # Create package.json if needed
        package_json = bridge_dir / "package.json"
        if not package_json.exists():
            package_json.write_text(json.dumps({
                "name": "zenith-whatsapp-bridge",
                "version": "1.0.0",
                "dependencies": {
                    "whatsapp-web.js": "^1.23.0",
                    "qrcode-terminal": "^0.12.0"
                }
            }, indent=2))

        return str(bridge_path)

    async def start(self):
        """Start the WhatsApp bot."""
        self.logger.info("📱 Starting WhatsApp bot...")
        
        # Check Node.js
        try:
            result = subprocess.run(
                ["node", "--version"], 
                capture_output=True, 
                text=True
            )
            self.logger.info(f"Node.js version: {result.stdout.strip()}")
        except FileNotFoundError:
            raise RuntimeError(
                "Node.js not found. Install from https://nodejs.org/"
            )

        # Install dependencies if needed
        bridge_dir = Path(self.bridge_path).parent
        if not (bridge_dir / "node_modules").exists():
            self.logger.info("Installing WhatsApp bridge dependencies...")
            subprocess.run(
                ["npm", "install"],
                cwd=str(bridge_dir),
                capture_output=True
            )

        # Start bridge process
        self.bridge_process = subprocess.Popen(
            ["node", self.bridge_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(bridge_dir)
        )

        self._running = True
        
        # Start reader thread
        self._reader_thread = threading.Thread(
            target=self._read_bridge_output,
            daemon=True
        )
        self._reader_thread.start()

        # Start message handler
        asyncio.create_task(self._message_handler())
        
        self.logger.info("📱 WhatsApp bot started. Waiting for QR code...")

    async def stop(self):
        """Stop the WhatsApp bot."""
        self._running = False
        
        if self.bridge_process:
            self._send_command({"action": "stop"})
            self.bridge_process.terminate()
            self.bridge_process.wait()
            self.bridge_process = None

        self.logger.info("📱 WhatsApp bot stopped")

    def _send_command(self, cmd: Dict):
        """Send command to bridge."""
        if self.bridge_process and self.bridge_process.stdin:
            try:
                self.bridge_process.stdin.write(json.dumps(cmd) + "\n")
                self.bridge_process.stdin.flush()
            except Exception as e:
                self.logger.error(f"Failed to send command: {e}")

    def send_message(self, to: str, text: str):
        """Send a message via WhatsApp."""
        self._send_command({
            "action": "send",
            "to": to,
            "text": text
        })

    def send_media(self, to: str, file_path: str, caption: str = ""):
        """Send a file via WhatsApp."""
        self._send_command({
            "action": "media",
            "to": to,
            "path": file_path,
            "caption": caption
        })

    def _read_bridge_output(self):
        """Read output from bridge process (runs in thread)."""
        if not self.bridge_process:
            return

        for line in self.bridge_process.stdout:
            line = line.strip()
            
            if line.startswith("ZENITH_"):
                asyncio.run_coroutine_threadsafe(
                    self._handle_bridge_event(line),
                    asyncio.get_event_loop()
                )
            else:
                # Regular output (QR code, etc.)
                print(line)

    async def _handle_bridge_event(self, event: str):
        """Handle events from bridge."""
        if event == "ZENITH_READY":
            self.logger.info("✅ WhatsApp connected and ready!")
            
        elif event == "ZENITH_AUTHENTICATED":
            self.logger.info("🔐 WhatsApp authenticated")
            
        elif event.startswith("ZENITH_DISCONNECTED:"):
            reason = event.split(":", 1)[1]
            self.logger.warning(f"⚠️ WhatsApp disconnected: {reason}")
            
        elif event.startswith("ZENITH_MSG:"):
            # New message
            data = json.loads(event[11:])
            await self._message_queue.put(data)
            
        elif event.startswith("ZENITH_ERROR:"):
            error = event[13:]
            self.logger.error(f"Bridge error: {error}")

    async def _message_handler(self):
        """Process incoming messages."""
        while self._running:
            try:
                msg = await asyncio.wait_for(
                    self._message_queue.get(),
                    timeout=1.0
                )
                await self._process_message(msg)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Message handler error: {e}")

    async def _process_message(self, msg: Dict):
        """Process a single message."""
        sender = msg["from"]
        body = msg["body"]
        is_group = msg.get("isGroup", False)

        # Skip groups (unless you want to handle them)
        if is_group:
            return

        # Authorization check
        phone = sender.replace("@c.us", "")
        if not self._is_authorized(phone):
            self.send_message(sender, "⛔ Unauthorized. Contact admin.")
            return

        # Parse command
        parsed = self.parser.parse(body)

        if parsed.get("error"):
            self.send_message(
                sender,
                f"❓ {parsed['error']}\n\nType 'help' for commands."
            )
            return

        # Handle action
        action = parsed.get("action")

        if action == "scan":
            await self._start_scan(sender, parsed["target"], parsed.get("profile", "quick"))
        elif action == "status":
            self._send_status(sender)
        elif action == "stop":
            self._stop_scan(sender)
        elif action == "help":
            self.send_message(sender, self.parser.get_help_text().replace("*", ""))
        elif action == "report":
            self._send_report(sender)
        else:
            self.send_message(sender, "🤔 I didn't understand. Type 'help' for commands.")

    def _is_authorized(self, phone: str) -> bool:
        """Check if phone number is authorized."""
        # Normalize phone number
        phone = phone.lstrip("+").replace(" ", "").replace("-", "")
        
        if self.allowed_numbers is None:
            return True
        
        # Check with and without country code
        return any(
            phone.endswith(allowed.lstrip("+").replace(" ", "").replace("-", ""))
            for allowed in self.allowed_numbers
        ) or any(
            phone.endswith(admin.lstrip("+").replace(" ", "").replace("-", ""))
            for admin in self.admin_numbers
        )

    async def _start_scan(self, chat_id: str, target: str, profile: str):
        """Start a new scan."""
        if self.active_session:
            session = self.sessions.get(self.active_session)
            if session and session.status == "running":
                self.send_message(
                    chat_id,
                    f"⚠️ Scan already running: {session.target}\nSend 'stop' to cancel."
                )
                return

        # Create session
        session_id = f"{int(time.time())}_{hash(target) % 10000:04d}"
        session = WhatsAppSession(
            session_id=session_id,
            target=target,
            profile=profile,
            chat_id=chat_id,
            status="running"
        )
        
        self.sessions[session_id] = session
        self.active_session = session_id

        self.send_message(
            chat_id,
            f"🚀 Starting {profile.upper()} scan on:\n{target}\n\nYou'll receive live updates..."
        )

        # Run scan
        asyncio.create_task(self._run_scan(session))

    async def _run_scan(self, session: WhatsAppSession):
        """Run the scan with live updates."""
        try:
            if self.scanner:
                await self._run_real_scan(session)
            else:
                await self._run_demo_scan(session)

            session.status = "completed"
            self.send_message(
                session.chat_id,
                f"✅ *Scan Complete!*\n\nTarget: {session.target}\nSend 'report' for details."
            )

        except Exception as e:
            session.status = "failed"
            self.send_message(
                session.chat_id,
                f"❌ Scan failed: {str(e)}"
            )

    async def _run_real_scan(self, session: WhatsAppSession):
        """Run actual scan."""
        last_update = time.time()
        update_interval = 5  # WhatsApp rate limits

        def log_callback(msg: str, level: str = "info"):
            nonlocal last_update
            session.logs.append(msg)
            
            # Rate-limited updates
            if time.time() - last_update >= update_interval:
                last_update = time.time()
                progress_bar = "█" * (session.progress // 5) + "░" * (20 - session.progress // 5)
                self.send_message(
                    session.chat_id,
                    f"📡 {session.phase}\n[{progress_bar}] {session.progress}%\n\n• {msg}"
                )

        def progress_callback(phase: str, progress: int):
            session.phase = phase
            session.progress = progress

        await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self.scanner.scan(
                target=session.target,
                profile=session.profile,
                log_callback=log_callback,
                progress_callback=progress_callback
            )
        )

    async def _run_demo_scan(self, session: WhatsAppSession):
        """Demo scan for testing."""
        phases = [
            ("🔍 Reconnaissance", 25, "Found 3 subdomains"),
            ("🌐 Port Scanning", 50, "Open: 80, 443, 22"),
            ("🔬 Vulnerability Scan", 75, "[HIGH] SQL Injection found"),
            ("📊 Finalizing", 95, "Generating report..."),
        ]

        for phase, progress, log in phases:
            if session.status == "stopped":
                return

            session.phase = phase
            session.progress = progress
            session.logs.append(log)

            bar = "█" * (progress // 5) + "░" * (20 - progress // 5)
            self.send_message(
                session.chat_id,
                f"📡 {phase}\n[{bar}] {progress}%\n\n• {log}"
            )
            
            await asyncio.sleep(3)

    def _send_status(self, chat_id: str):
        """Send current status."""
        if not self.active_session or self.active_session not in self.sessions:
            self.send_message(chat_id, "ℹ️ No active scan.")
            return

        session = self.sessions[self.active_session]
        elapsed = int(time.time() - session.started_at)
        mins, secs = divmod(elapsed, 60)
        bar = "█" * (session.progress // 5) + "░" * (20 - session.progress // 5)

        self.send_message(
            chat_id,
            f"""📊 *Status*

Target: {session.target}
Profile: {session.profile}
Status: {session.status.upper()}
Phase: {session.phase}

[{bar}] {session.progress}%

Time: {mins}m {secs}s"""
        )

    def _stop_scan(self, chat_id: str):
        """Stop current scan."""
        if not self.active_session:
            self.send_message(chat_id, "ℹ️ No active scan.")
            return

        session = self.sessions[self.active_session]
        session.status = "stopped"
        
        if self.scanner:
            self.scanner.stop()

        self.send_message(chat_id, f"🛑 Stopped scan: {session.target}")
        self.active_session = None

    def _send_report(self, chat_id: str):
        """Send scan report."""
        session_id = self.active_session
        
        if not session_id or session_id not in self.sessions:
            self.send_message(chat_id, "ℹ️ No scan results available.")
            return

        session = self.sessions[session_id]

        # Try to send file report
        if self.scanner:
            report_path = self.scanner.generate_report(session_id)
            if report_path and Path(report_path).exists():
                self.send_media(
                    chat_id,
                    report_path,
                    f"📊 Scan Report: {session.target}"
                )
                return

        # Text summary
        summary = f"""📊 *Scan Report*

Target: {session.target}
Profile: {session.profile}
Status: {session.status}
Duration: {int(time.time() - session.started_at)}s

*Recent Findings:*
{chr(10).join('• ' + log for log in session.logs[-10:])}
"""
        self.send_message(chat_id, summary)

    # ========== Log Streaming API ==========

    def log(self, message: str, level: str = "info"):
        """Log a message (called from scanner)."""
        if self.active_session and self.active_session in self.sessions:
            session = self.sessions[self.active_session]
            session.logs.append(message)

    def set_progress(self, phase: str, progress: int):
        """Set scan progress (called from scanner)."""
        if self.active_session and self.active_session in self.sessions:
            session = self.sessions[self.active_session]
            session.phase = phase
            session.progress = progress
