"""
Zenith Base Plugin - Foundation for third-party modules.

Plugin types:
  - scanner:  New vulnerability scanners
  - exploit:  New exploitation modules
  - recon:    New reconnaissance tools
  - parser:   New output parsers
  - reporter: New report formats
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class PluginInfo:
    """Metadata about a plugin."""
    name:        str
    version:     str
    author:      str
    description: str
    plugin_type: str   # "scanner" | "exploit" | "recon" | "parser" | "reporter"
    tags:        List[str] = None

    def to_dict(self) -> Dict:
        return {
            "name":        self.name,
            "version":     self.version,
            "author":      self.author,
            "description": self.description,
            "type":        self.plugin_type,
            "tags":        self.tags or [],
        }


class BasePlugin(ABC):
    """
    Abstract base class for all ZenithAI plugins.

    To create a plugin:
    1. Subclass BasePlugin
    2. Set INFO with PluginInfo
    3. Implement run() method
    4. Place the .py file in zenith/plugins/custom/

    Example:
        class MyScanner(BasePlugin):
            INFO = PluginInfo(
                name="My Custom Scanner",
                version="1.0.0",
                author="Your Name",
                description="Scans for custom vulnerabilities",
                plugin_type="scanner",
                tags=["web", "custom"],
            )

            def run(self, target: str, **kwargs) -> Dict:
                # Your scanning logic here
                return {"findings": [...]}
    """

    INFO: PluginInfo = None

    def __init__(self, executor=None, memory=None, ai_brain=None):
        """
        Initialize plugin with optional ZenithAI components.

        Args:
            executor: TerminalExecutor for running commands
            memory:   SharedMemory for reading/writing findings
            ai_brain: AIBrain for AI-powered analysis
        """
        self.executor = executor
        self.memory   = memory
        self.ai       = ai_brain

    @abstractmethod
    def run(self, target: str, **kwargs) -> Dict:
        """
        Execute the plugin.

        Args:
            target: Target URL/IP
            **kwargs: Plugin-specific arguments

        Returns:
            Dict with results (format depends on plugin_type):
            - scanner/exploit: {"findings": [...], "data": {...}}
            - recon:           {"subdomains": [...], "ports": [...], ...}
            - parser:          {"parsed": {...}}
            - reporter:        {"report_path": "...", "format": "..."}
        """
        ...

    def _run_cmd(self, command: str, timeout: int = 120) -> str:
        """Run a shell command and return output."""
        if self.executor:
            result = self.executor.run(command, timeout=timeout)
            return result.get("output", "")
        return ""

    def _emit(self, event: str, data: Any = None) -> None:
        """Emit an event to shared memory bus."""
        if self.memory:
            self.memory.emit(event, data, source=self.INFO.name if self.INFO else "plugin")

    def _ai_analyze(self, prompt: str) -> str:
        """Send a prompt to the AI brain."""
        if self.ai:
            return self.ai.think(prompt)
        return ""

    @classmethod
    def get_info(cls) -> Optional[PluginInfo]:
        """Return plugin metadata."""
        return cls.INFO

    def validate(self) -> bool:
        """Validate plugin is properly configured."""
        if not self.INFO:
            return False
        if not self.INFO.name or not self.INFO.plugin_type:
            return False
        return True
