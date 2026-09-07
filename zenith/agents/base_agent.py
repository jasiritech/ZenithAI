"""
Zenith Base Agent - Abstract foundation for all ZenithAI agents.

Every agent shares:
  - access to the executor (run shell commands)
  - access to the AI brain (generate reasoning)
  - access to shared memory (read/write findings)
  - a standard AgentResult return type
  - timing utilities
  - display helpers
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from zenith.memory.shared_memory import SharedMemory


# ──────────────────────────────────────────────────────────────
# Standard result type
# ──────────────────────────────────────────────────────────────

@dataclass
class AgentResult:
    """
    Standardised result returned by every agent's run() method.

    Fields:
        agent_name  – agent that produced the result
        status      – "success" | "partial" | "failed" | "skipped"
        findings    – list of finding dicts  [{"title", "severity", ...}]
        data        – free-form structured output (agent-specific)
        errors      – list of error strings
        duration    – wall-clock time in seconds
        message     – short human-readable summary
    """
    agent_name: str
    status:     str
    findings:   List[Dict] = field(default_factory=list)
    data:       Dict       = field(default_factory=dict)
    errors:     List[str]  = field(default_factory=list)
    duration:   float      = 0.0
    message:    str        = ""

    def to_dict(self) -> Dict:
        return {
            "agent":    self.agent_name,
            "status":   self.status,
            "findings": self.findings,
            "data":     self.data,
            "errors":   self.errors,
            "duration": round(self.duration, 2),
            "message":  self.message,
        }

    @property
    def success(self) -> bool:
        return self.status in ("success", "partial")


# ──────────────────────────────────────────────────────────────
# Base agent
# ──────────────────────────────────────────────────────────────

class BaseAgent(ABC):
    """
    Abstract base class for all ZenithAI agents.

    Subclasses must implement:
        NAME        (str)         – unique agent identifier, e.g. "recon"
        DESCRIPTION (str)         – one-line description shown in UI
        run(target, **kwargs)     – main entry point, returns AgentResult

    Optional class attributes:
        REQUIRES (List[str])      – names of agents that must finish first
        PROVIDES (List[str])      – context keys this agent writes
    """

    NAME:        str       = "base"
    DESCRIPTION: str       = ""
    REQUIRES:    List[str] = []  # agent names that must complete before this one
    PROVIDES:    List[str] = []  # shared-context keys this agent populates

    def __init__(
        self,
        executor,
        ai_brain,
        shared_memory: SharedMemory,
        attack_graph=None,
        display=None,
    ):
        self.executor = executor
        self.ai       = ai_brain
        self.memory   = shared_memory
        self.graph    = attack_graph   # AttackGraph (may be None)
        self.display  = display
        self._t0: Optional[float] = None

    # ──────────────────────────────────────────────
    # Abstract interface
    # ──────────────────────────────────────────────

    @abstractmethod
    def run(self, target: str, **kwargs) -> AgentResult:
        """Execute this agent. Must be overridden."""
        ...

    # ──────────────────────────────────────────────
    # Timing
    # ──────────────────────────────────────────────

    def _start(self) -> None:
        """Start the wall-clock timer."""
        self._t0 = time.monotonic()

    def _elapsed(self) -> float:
        """Return seconds since _start() was called."""
        if self._t0 is None:
            return 0.0
        return time.monotonic() - self._t0

    # ──────────────────────────────────────────────
    # Command execution helpers
    # ──────────────────────────────────────────────

    def _run(self, command: str, timeout: int = 120) -> Dict:
        """Run a shell command and return the executor result dict."""
        return self.executor.run(command, timeout=timeout)

    def _output(self, command: str, timeout: int = 120) -> str:
        """Run a command and return stdout as a string."""
        result = self._run(command, timeout=timeout)
        return result.get("output", "") or ""

    # ──────────────────────────────────────────────
    # Display helpers
    # ──────────────────────────────────────────────

    def _log(self, msg: str, level: str = "info") -> None:
        tag = f"[{self.NAME.upper()}]"
        if not self.display:
            return
        {
            "info":    self.display.info,
            "success": self.display.success,
            "warning": self.display.warning,
            "error":   self.display.error,
        }.get(level, self.display.info)(f"{tag} {msg}")

    # ──────────────────────────────────────────────
    # Memory helpers
    # ──────────────────────────────────────────────

    def _write(self, key: str, value: Any) -> None:
        """Write to this agent's namespace."""
        self.memory.write(self.NAME, key, value)

    def _read(self, namespace: str, key: str, default: Any = None) -> Any:
        """Read from any namespace."""
        return self.memory.read(namespace, key, default)

    def _ctx(self, key: str) -> Any:
        """Read from global shared context."""
        return self.memory.get_context(key)

    def _update(self, key: str, value: Any) -> None:
        """Write to global shared context."""
        self.memory.update_context(key, value)

    def _emit(self, event: str, data: Any = None) -> None:
        """Emit an event to the shared bus."""
        self.memory.emit(event, data, source=self.NAME)

    # ──────────────────────────────────────────────
    # Graph helpers  (no-op if graph is None)
    # ──────────────────────────────────────────────

    def _graph_add_vuln(
        self,
        title: str,
        severity: str,
        description: str = "",
        cve: str = None,
        evidence: str = "",
        parent_service: str = None,
        url: str = None,
    ) -> Optional[str]:
        if self.graph:
            return self.graph.add_vulnerability(
                title, severity, description, cve, evidence, parent_service, url
            )
        return None

    def _graph_add_service(
        self, port: int, service: str, version: str = "", parent_ip: str = None
    ) -> Optional[str]:
        if self.graph:
            return self.graph.add_service(port, service, version, parent_ip)
        return None
