"""Zenith Bot - Remote control via Telegram and WhatsApp."""
"""
Zenith Bot Integration - Remote control via Telegram and WhatsApp.

This module provides:
    - TelegramBot: Control ZenithAI via Telegram with live log streaming
    - WhatsAppBot: Control ZenithAI via WhatsApp with live updates
    - CommandParser: AI-powered natural language command parsing

Example Usage:
    from zenith.bot import TelegramBot, WhatsAppBot
    
    # Telegram
    bot = TelegramBot(
        token="YOUR_TELEGRAM_BOT_TOKEN",
        scanner=scanner,
        ai_brain=ai
    )
    await bot.start()
    
    # WhatsApp
    wa_bot = WhatsAppBot(
        scanner=scanner,
        ai_brain=ai
    )
    await wa_bot.start()  # Scan QR code

Supported Commands:
    - scan <target> - Start vulnerability scan
    - deep <target> - Deep comprehensive scan
    - stealth <target> - Stealth/quiet scan
    - status - Current scan progress
    - stop - Stop running scan
    - report - Get scan report
    - help - List all commands
    
Natural Language:
    You can also send natural language like:
    - "check example.com for vulnerabilities"
    - "hack test.com" (friendly alias for scan)
    - "stop the scan"
    - "show me the results"
"""

from zenith.bot.telegram_bot import TelegramBot
from zenith.bot.whatsapp_bot import WhatsAppBot
from zenith.bot.command_parser import CommandParser

__all__ = ["TelegramBot", "WhatsAppBot", "CommandParser"]
