"""
Zenith Notifier - Send alerts via Telegram, Discord, and Slack.
Get real-time notifications when vulnerabilities are discovered.
"""

import json
import threading
import os

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class Notifier:
    """
    Multi-channel notification system.
    Supports Telegram, Discord webhooks, and Slack webhooks.
    """

    def __init__(self, config=None):
        """
        Initialize notifier with configuration.
        
        Args:
            config: Dict with notification settings. Example:
                {
                    "telegram": {"bot_token": "...", "chat_id": "..."},
                    "discord": {"webhook_url": "..."},
                    "slack": {"webhook_url": "..."},
                    "notify_on": ["critical", "high", "scan_start", "scan_end"]
                }
        """
        self.config = config or {}
        self.enabled = bool(config)
        self.notify_on = [s.upper() for s in self.config.get("notify_on", ["CRITICAL", "HIGH", "SCAN_START", "SCAN_END"])]
        
        # Track sent notifications to avoid spam
        self._sent = set()
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls):
        """
        Create notifier from environment variables.
        
        Env vars:
            ZENITH_TELEGRAM_TOKEN - Telegram bot token
            ZENITH_TELEGRAM_CHAT_ID - Telegram chat ID
            ZENITH_DISCORD_WEBHOOK - Discord webhook URL
            ZENITH_SLACK_WEBHOOK - Slack webhook URL
        """
        config = {}
        
        tg_token = os.environ.get("ZENITH_TELEGRAM_TOKEN")
        tg_chat = os.environ.get("ZENITH_TELEGRAM_CHAT_ID")
        if tg_token and tg_chat:
            config["telegram"] = {"bot_token": tg_token, "chat_id": tg_chat}
        
        discord_url = os.environ.get("ZENITH_DISCORD_WEBHOOK")
        if discord_url:
            config["discord"] = {"webhook_url": discord_url}
        
        slack_url = os.environ.get("ZENITH_SLACK_WEBHOOK")
        if slack_url:
            config["slack"] = {"webhook_url": slack_url}
        
        return cls(config if config else None)

    def notify_scan_start(self, target, model, profile="custom"):
        """Send scan started notification."""
        if not self._should_notify("SCAN_START"):
            return
        
        message = (
            f"🚀 **ZenithAI Scan Started**\n"
            f"🎯 Target: `{target}`\n"
            f"🧠 Model: {model}\n"
            f"📋 Profile: {profile}\n"
            f"⏰ Started at: {self._timestamp()}"
        )
        self._send_all(message)

    def notify_scan_end(self, target, duration, vuln_counts, risk_rating="UNKNOWN"):
        """Send scan completed notification."""
        if not self._should_notify("SCAN_END"):
            return
        
        total = sum(vuln_counts.values())
        
        risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(risk_rating, "⚪")
        
        message = (
            f"✅ **ZenithAI Scan Complete**\n"
            f"🎯 Target: `{target}`\n"
            f"⏱️ Duration: {duration}\n"
            f"{risk_emoji} Risk: **{risk_rating}**\n"
            f"🔓 Vulnerabilities: **{total}**\n"
        )
        
        if vuln_counts.get("CRITICAL", 0):
            message += f"  🔴 Critical: {vuln_counts['CRITICAL']}\n"
        if vuln_counts.get("HIGH", 0):
            message += f"  🟠 High: {vuln_counts['HIGH']}\n"
        if vuln_counts.get("MEDIUM", 0):
            message += f"  🟡 Medium: {vuln_counts['MEDIUM']}\n"
        if vuln_counts.get("LOW", 0):
            message += f"  🔵 Low: {vuln_counts['LOW']}\n"
        if vuln_counts.get("INFO", 0):
            message += f"  ⚪ Info: {vuln_counts['INFO']}\n"
        
        self._send_all(message)

    def notify_vulnerability(self, title, severity, description="", target=""):
        """Send vulnerability discovered notification."""
        sev_upper = severity.upper()
        if not self._should_notify(sev_upper):
            return
        
        # Deduplicate
        dedup_key = f"vuln:{title}:{sev_upper}"
        with self._lock:
            if dedup_key in self._sent:
                return
            self._sent.add(dedup_key)
        
        sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️"}.get(sev_upper, "⚪")
        
        message = (
            f"{sev_emoji} **[{sev_upper}] Vulnerability Found!**\n"
            f"🎯 Target: `{target}`\n"
            f"📌 {title}\n"
        )
        if description:
            message += f"📝 {description[:200]}\n"
        
        self._send_all(message)

    def notify_error(self, error_message, target=""):
        """Send error notification."""
        if not self._should_notify("ERROR"):
            return
        
        message = (
            f"❌ **ZenithAI Error**\n"
            f"🎯 Target: `{target}`\n"
            f"⚠️ {error_message[:300]}"
        )
        self._send_all(message)

    def _should_notify(self, event_type):
        """Check if we should send this notification type."""
        if not self.enabled or not HAS_REQUESTS:
            return False
        return event_type.upper() in self.notify_on or "ALL" in self.notify_on

    def _send_all(self, message):
        """Send message to all configured channels (async)."""
        thread = threading.Thread(target=self._send_all_sync, args=(message,), daemon=True)
        thread.start()

    def _send_all_sync(self, message):
        """Send to all channels synchronously."""
        if "telegram" in self.config:
            self._send_telegram(message)
        if "discord" in self.config:
            self._send_discord(message)
        if "slack" in self.config:
            self._send_slack(message)

    def _send_telegram(self, message):
        """Send message via Telegram Bot API."""
        try:
            cfg = self.config["telegram"]
            token = cfg["bot_token"]
            chat_id = cfg["chat_id"]
            
            # Convert markdown to Telegram format
            text = message.replace("**", "*")
            
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            payload = {
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "Markdown",
                "disable_web_page_preview": True,
            }
            
            requests.post(url, json=payload, timeout=10)
        except Exception as e:
            pass  # Silent fail - don't break scanning

    def _send_discord(self, message):
        """Send message via Discord webhook."""
        try:
            url = self.config["discord"]["webhook_url"]
            
            # Convert to Discord format
            text = message.replace("`", "``")
            
            payload = {"content": text}
            requests.post(url, json=payload, timeout=10)
        except Exception:
            pass

    def _send_slack(self, message):
        """Send message via Slack webhook."""
        try:
            url = self.config["slack"]["webhook_url"]
            
            # Convert markdown to Slack mrkdwn
            text = message.replace("**", "*")
            
            payload = {"text": text}
            requests.post(url, json=payload, timeout=10)
        except Exception:
            pass

    @staticmethod
    def _timestamp():
        """Get current timestamp string."""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
