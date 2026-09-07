"""
Zenith Shared Memory - Central communication bus for all agents.

Thread-safe event store, message passing, and agent coordination.
All agents read/write here to share findings and coordinate execution.
"""

import threading
import time
from datetime import datetime
from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional


class SharedMemory:
    """
    Thread-safe shared memory store and event bus for multi-agent coordination.

    Agents:
    - Write findings to namespaced stores (memory.write("recon", "subdomains", [...]))
    - Subscribe to events from other agents (memory.subscribe("vuln_found", callback))
    - Read global context (memory.get_context("open_ports"))
    - Publish events (memory.emit("new_subdomain", "admin.target.com"))
    """

    def __init__(self, target: str):
        self._lock = threading.RLock()
        self.target = target
        self.created_at = datetime.now()

        # Per-agent namespaced data stores
        self._stores: Dict[str, Dict] = {
            "planner":      {},
            "recon":        {},
            "web":          {},
            "exploit":      {},
            "intelligence": {},
            "reporter":     {},
            "shared":       {},
        }

        # Event bus: event_name → list of callbacks
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)

        # Full event log (append-only)
        self._events: List[Dict] = []

        # Agent lifecycle tracking
        self._agent_status: Dict[str, str] = {}   # "idle" | "running" | "done" | "failed" | "skipped"
        self._agent_results: Dict[str, Any] = {}

        # Global shared context — merged by all agents
        self._context: Dict[str, Any] = {
            "target": target,
            "subdomains":       [],   # ["sub.target.com", ...]
            "open_ports":       [],   # [{"port": 80, "service": "http", "version": "..."}]
            "technologies":     [],   # ["WordPress 6.1", "Apache 2.4", ...]
            "vulnerabilities":  [],   # [{"title": "...", "severity": "HIGH", ...}]
            "credentials":      [],   # [{"user": "admin", "pass": "123", "service": "ftp"}]
            "directories":      [],   # ["/admin", "/backup", ...]
            "api_endpoints":    [],   # ["GET /api/v1/users", ...]
            "forms":            [],   # [{"url": "...", "method": "POST", "params": [...]}]
            "cve_matches":      [],   # [{"cve": "CVE-2023-...", "tech": "Apache 2.4.50"}]
            "attack_paths":     [],   # Graph-derived attack paths
            "waf_detected":     False,
            "waf_type":         None,
            "rate_limited":     False,
            "scan_speed":       "normal",   # "slow" | "normal" | "fast"
            "stealth_mode":     False,
            "active_proxies":   [],
            "screenshot_paths": [],   # [{"url": "...", "path": "/tmp/shot.png"}]
        }

    # ──────────────────────────────────────────────
    # Namespaced store operations
    # ──────────────────────────────────────────────

    def write(self, namespace: str, key: str, value: Any) -> None:
        """Write data to an agent namespace."""
        with self._lock:
            if namespace not in self._stores:
                self._stores[namespace] = {}
            self._stores[namespace][key] = value

    def read(self, namespace: str, key: str, default: Any = None) -> Any:
        """Read data from an agent namespace."""
        with self._lock:
            return self._stores.get(namespace, {}).get(key, default)

    def get_store(self, namespace: str) -> Dict:
        """Return a snapshot of an entire agent namespace."""
        with self._lock:
            return dict(self._stores.get(namespace, {}))

    # ──────────────────────────────────────────────
    # Global context operations
    # ──────────────────────────────────────────────

    def update_context(self, key: str, value: Any) -> None:
        """
        Update a key in the global shared context.

        - If the existing value is a list and the new value is also a list,
          the items are merged (deduped).
        - If the existing value is a list and the new value is a single item,
          the item is appended (if not already present).
        - Otherwise the value is replaced outright.
        """
        with self._lock:
            existing = self._context.get(key)
            if isinstance(existing, list):
                if isinstance(value, list):
                    for item in value:
                        if item not in existing:
                            existing.append(item)
                else:
                    if value not in existing:
                        existing.append(value)
            else:
                self._context[key] = value

    def get_context(self, key: str = None) -> Any:
        """Return the full context dict, or a single key."""
        with self._lock:
            if key is not None:
                return self._context.get(key)
            return dict(self._context)

    # ──────────────────────────────────────────────
    # Event bus
    # ──────────────────────────────────────────────

    def emit(self, event: str, data: Any = None, source: str = "system") -> None:
        """
        Emit a named event.  Synchronously calls all registered callbacks
        (outside the lock to prevent deadlocks).
        """
        with self._lock:
            event_obj = {
                "event":     event,
                "data":      data,
                "source":    source,
                "timestamp": datetime.now().isoformat(),
            }
            self._events.append(event_obj)
            callbacks = list(self._subscribers.get(event, []))

        for cb in callbacks:
            try:
                cb(data, source)
            except Exception:
                pass  # never crash the bus

    def subscribe(self, event: str, callback: Callable) -> None:
        """Subscribe a callable to a named event."""
        with self._lock:
            self._subscribers[event].append(callback)

    def get_all_events(self, event_type: str = None) -> List[Dict]:
        """Return all logged events, optionally filtered by type."""
        with self._lock:
            if event_type:
                return [e for e in self._events if e["event"] == event_type]
            return list(self._events)

    # ──────────────────────────────────────────────
    # Agent lifecycle
    # ──────────────────────────────────────────────

    def set_agent_status(self, agent: str, status: str) -> None:
        """Update an agent's lifecycle status."""
        with self._lock:
            self._agent_status[agent] = status
            self._events.append({
                "event":     "agent_status_changed",
                "data":      {"agent": agent, "status": status},
                "timestamp": datetime.now().isoformat(),
            })

    def get_agent_status(self, agent: str = None) -> Any:
        """Return the status of one agent, or a dict of all agents."""
        with self._lock:
            if agent:
                return self._agent_status.get(agent, "idle")
            return dict(self._agent_status)

    def store_agent_result(self, agent: str, result: Any) -> None:
        """Persist an agent's final AgentResult."""
        with self._lock:
            self._agent_results[agent] = result

    def get_agent_result(self, agent: str) -> Optional[Any]:
        """Retrieve an agent's final AgentResult."""
        with self._lock:
            return self._agent_results.get(agent)

    # ──────────────────────────────────────────────
    # Summary helpers
    # ──────────────────────────────────────────────

    def get_summary(self) -> Dict:
        """
        Return a compact summary of current knowledge.
        Used by the Planner and AI prompts.
        """
        ctx = self.get_context()
        with self._lock:
            statuses = dict(self._agent_status)
        return {
            "target":               ctx["target"],
            "subdomains_found":     len(ctx["subdomains"]),
            "subdomains":           ctx["subdomains"][:10],
            "open_ports":           ctx["open_ports"][:20],
            "technologies":         ctx["technologies"][:10],
            "vulnerabilities_found":len(ctx["vulnerabilities"]),
            "top_vulns":            ctx["vulnerabilities"][:5],
            "credentials_found":    len(ctx["credentials"]),
            "directories_found":    len(ctx["directories"]),
            "api_endpoints_found":  len(ctx["api_endpoints"]),
            "cve_matches":          ctx["cve_matches"][:5],
            "waf_detected":         ctx["waf_detected"],
            "waf_type":             ctx["waf_type"],
            "scan_speed":           ctx["scan_speed"],
            "agents_done":          [a for a, s in statuses.items() if s == "done"],
            "agents_running":       [a for a, s in statuses.items() if s == "running"],
            "agents_failed":        [a for a, s in statuses.items() if s == "failed"],
        }

    def get_ai_context_string(self, max_chars: int = 1500) -> str:
        """
        Build a compact string context suitable for injection into AI prompts.
        """
        s = self.get_summary()
        lines = [
            f"Target: {s['target']}",
            f"Subdomains: {s['subdomains_found']} found → {s['subdomains'][:5]}",
            f"Open ports: {s['open_ports'][:10]}",
            f"Technologies: {s['technologies'][:8]}",
            f"Vulnerabilities: {s['vulnerabilities_found']} found",
        ]
        if s["top_vulns"]:
            for v in s["top_vulns"]:
                lines.append(f"  [{v.get('severity','?')}] {v.get('title','?')[:60]}")
        if s["cve_matches"]:
            lines.append(f"CVE matches: {[c.get('cve') for c in s['cve_matches'][:5]]}")
        if s["waf_detected"]:
            lines.append(f"WAF detected: {s['waf_type']} — stealth mode active")
        if s["credentials_found"]:
            lines.append(f"Credentials found: {s['credentials_found']}")
        result = "\n".join(lines)
        return result[:max_chars]
