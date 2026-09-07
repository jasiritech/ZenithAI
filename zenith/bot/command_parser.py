"""
Zenith Command Parser - AI-powered natural language command parser.

Converts natural language messages into structured scan commands.

Examples:
    "scan example.com"                → {"action": "scan", "target": "example.com", "profile": "quick"}
    "deep scan https://target.com"    → {"action": "scan", "target": "https://target.com", "profile": "deep"}
    "status"                          → {"action": "status"}
    "stop"                            → {"action": "stop"}
    "report"                          → {"action": "report"}
"""

import re
import json
from typing import Dict, Optional, Any


class CommandParser:
    """
    Parses natural language commands from Telegram/WhatsApp messages.
    
    Supports both pattern-based and AI-assisted parsing.
    """

    # Supported commands and patterns
    COMMANDS = {
        "scan": {
            "aliases": ["scan", "hack", "test", "check", "piga", "angalia", "chunguza"],
            "requires_target": True,
        },
        "quick_scan": {
            "aliases": ["quick", "haraka", "fast"],
            "requires_target": True,
        },
        "deep_scan": {
            "aliases": ["deep", "full", "kina", "yote"],
            "requires_target": True,
        },
        "stealth_scan": {
            "aliases": ["stealth", "quiet", "kimya", "ninja"],
            "requires_target": True,
        },
        "status": {
            "aliases": ["status", "hali", "progress", "maendeleo", "?"],
            "requires_target": False,
        },
        "stop": {
            "aliases": ["stop", "simama", "acha", "cancel", "abort"],
            "requires_target": False,
        },
        "pause": {
            "aliases": ["pause", "pumzika", "wait", "subiri"],
            "requires_target": False,
        },
        "resume": {
            "aliases": ["resume", "endelea", "continue"],
            "requires_target": False,
        },
        "report": {
            "aliases": ["report", "ripoti", "results", "matokeo"],
            "requires_target": False,
        },
        "help": {
            "aliases": ["help", "msaada", "?", "commands", "amri"],
            "requires_target": False,
        },
        "sessions": {
            "aliases": ["sessions", "vikao", "list", "orodha"],
            "requires_target": False,
        },
    }

    # Profile mapping
    PROFILES = {
        "quick":   ["quick", "haraka", "fast", "⚡"],
        "deep":    ["deep", "kina", "full", "thorough", "🧠"],
        "stealth": ["stealth", "ninja", "quiet", "kimya", "🥷"],
        "web":     ["web", "website", "tovuti", "🌐"],
        "api":     ["api", "rest", "graphql"],
        "turbo":   ["turbo", "speed", "🚀"],
    }

    # Target extraction patterns
    TARGET_PATTERNS = [
        re.compile(r'https?://[^\s]+'),           # Full URL
        re.compile(r'(\d{1,3}\.){3}\d{1,3}'),     # IP address
        re.compile(r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}[^\s]*'),  # Domain
    ]

    def __init__(self, ai_brain=None):
        """
        Initialize parser.
        
        Args:
            ai_brain: Optional AIBrain for complex command parsing
        """
        self.ai = ai_brain

    def parse(self, message: str) -> Dict[str, Any]:
        """
        Parse a natural language message into a command dict.

        Args:
            message: Raw message from Telegram/WhatsApp

        Returns:
            {
                "action": "scan" | "status" | "stop" | ...,
                "target": "https://..." | None,
                "profile": "quick" | "deep" | ...,
                "options": {...},
                "raw_message": "...",
                "confidence": 0.0-1.0,
            }
        """
        if not message:
            return self._error("Empty message")

        message = message.strip()
        lower   = message.lower()

        # Check for direct commands first
        result = self._parse_patterns(lower, message)
        if result.get("action"):
            result["raw_message"] = message
            result["confidence"]  = result.get("confidence", 0.9)
            return result

        # Try AI parsing for complex messages
        if self.ai:
            result = self._ai_parse(message)
            if result.get("action"):
                result["raw_message"] = message
                result["confidence"]  = result.get("confidence", 0.7)
                return result

        # Fallback: try to extract a target anyway
        target = self._extract_target(message)
        if target:
            return {
                "action":      "scan",
                "target":      target,
                "profile":     "quick",
                "options":     {},
                "raw_message": message,
                "confidence":  0.5,
            }

        return self._error("Could not parse command. Try: scan <target>")

    def _parse_patterns(self, lower: str, original: str) -> Dict:
        """Pattern-based command parsing."""
        result = {
            "action":  None,
            "target":  None,
            "profile": "quick",
            "options": {},
        }

        # Detect action
        for action, config in self.COMMANDS.items():
            for alias in config["aliases"]:
                if alias in lower.split() or lower.startswith(alias):
                    result["action"] = action.replace("_scan", "")
                    if result["action"] in ("quick", "deep", "stealth"):
                        result["profile"] = result["action"]
                        result["action"]  = "scan"
                    break
            if result["action"]:
                break

        # Extract target if required
        if result["action"] and self.COMMANDS.get(f"{result['action']}_scan", self.COMMANDS.get(result["action"], {})).get("requires_target", False):
            result["target"] = self._extract_target(original)
            if not result["target"]:
                return self._error(f"Command '{result['action']}' requires a target. Example: scan https://example.com")

        # Override scan action to just "scan" with profile
        if result["action"] == "scan":
            # Check for profile hints in message
            for profile, keywords in self.PROFILES.items():
                for kw in keywords:
                    if kw in lower:
                        result["profile"] = profile
                        break

        return result

    def _extract_target(self, text: str) -> Optional[str]:
        """Extract target URL/IP/domain from text."""
        for pattern in self.TARGET_PATTERNS:
            match = pattern.search(text)
            if match:
                target = match.group()
                # Ensure URL has protocol
                if not target.startswith("http"):
                    # Check if it looks like a domain
                    if "." in target and not target[0].isdigit():
                        target = f"https://{target}"
                    elif re.match(r'(\d{1,3}\.){3}\d{1,3}', target):
                        pass  # Keep IP as-is
                return target
        return None

    def _ai_parse(self, message: str) -> Dict:
        """Use AI to parse complex/ambiguous commands."""
        prompt = f"""Parse this security scan command and return JSON:

Message: "{message}"

Return JSON with:
{{
  "action": "scan" | "status" | "stop" | "pause" | "resume" | "report" | "help" | "sessions" | null,
  "target": "extracted URL/IP/domain or null",
  "profile": "quick" | "deep" | "stealth" | "web" | "api" | "turbo",
  "options": {{}},
  "confidence": 0.0-1.0
}}

If you can't determine the action, set action to null.
ONLY return valid JSON, no explanation."""

        try:
            response = self.ai.think(prompt)
            # Extract JSON from response
            match = re.search(r'\{[\s\S]*\}', response)
            if match:
                return json.loads(match.group())
        except Exception:
            pass

        return {}

    def _error(self, msg: str) -> Dict:
        """Return an error result."""
        return {
            "action":      None,
            "target":      None,
            "profile":     None,
            "options":     {},
            "error":       msg,
            "confidence":  0.0,
        }

    def get_help_text(self) -> str:
        """Return help text for available commands."""
        return """🤖 *ZenithAI Commands*

*Scanning:*
• `scan <target>` - Quick scan
• `deep <target>` - Deep comprehensive scan
• `stealth <target>` - Stealth/quiet scan
• `turbo <target>` - Fast high-signal scan

*Control:*
• `status` - Current scan progress
• `stop` - Stop running scan
• `pause` - Pause scan
• `resume` - Resume paused scan

*Results:*
• `report` - Get scan report
• `sessions` - List saved sessions

*Examples:*
• `scan https://example.com`
• `deep scan example.com`
• `status`

💡 You can also just send a URL and I'll scan it!"""
