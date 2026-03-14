"""
Zenith Attack Graph - Represents discovered assets and vulnerabilities as a directed graph.

Graph structure:
    Target
     ├── Domain
     │   └── Subdomain
     │       └── IP
     │           └── Service (port)
     │               └── Vulnerability
     │                   └── Exploit Path
     └── Network Service

Nodes are deterministically IDed by (type, label) so the same asset
added twice just merges data rather than duplicating.
"""

import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional


# ──────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────

class Node:
    """A single vertex in the attack graph."""

    TYPES = frozenset([
        "target", "domain", "subdomain", "ip",
        "service", "vulnerability", "exploit_path", "credential",
    ])

    TYPE_ICONS = {
        "target":         "🎯",
        "domain":         "🌍",
        "subdomain":      "🌐",
        "ip":             "🔗",
        "service":        "⚙",
        "vulnerability":  "🔴",
        "exploit_path":   "💥",
        "credential":     "🔑",
    }

    SEV_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}

    def __init__(self, node_id: str, node_type: str, label: str, data: Dict = None):
        self.id         = node_id
        self.type       = node_type
        self.label      = label
        self.data       = data or {}
        self.created_at = datetime.now().isoformat()

    @property
    def icon(self) -> str:
        if self.type == "vulnerability":
            sev = self.data.get("severity", "INFO").upper()
            return self.SEV_ICONS.get(sev, "🔴")
        return self.TYPE_ICONS.get(self.type, "○")

    def to_dict(self) -> Dict:
        return {
            "id":         self.id,
            "type":       self.type,
            "label":      self.label,
            "data":       self.data,
            "created_at": self.created_at,
        }


class Edge:
    """A directed relationship between two nodes."""

    RELATIONS = frozenset([
        "has_subdomain", "resolves_to", "runs_service",
        "has_vulnerability", "leads_to", "exploits",
        "has_credential", "has_domain",
    ])

    def __init__(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        weight: float = 1.0,
        data: Dict = None,
    ):
        self.source   = source_id
        self.target   = target_id
        self.relation = relation
        self.weight   = weight
        self.data     = data or {}

    def to_dict(self) -> Dict:
        return {
            "source":   self.source,
            "target":   self.target,
            "relation": self.relation,
            "weight":   self.weight,
            "data":     self.data,
        }


# ──────────────────────────────────────────────────────────────
# Main graph class
# ──────────────────────────────────────────────────────────────

class AttackGraph:
    """
    In-memory directed graph for tracking targets, assets, and attack paths.

    All add_* methods are idempotent: calling them twice with the same inputs
    merges data rather than creating duplicate nodes/edges.

    Usage:
        graph = AttackGraph("https://example.com")
        graph.add_subdomain("admin.example.com")
        graph.add_service(80, "http", "Apache 2.4.50", parent_ip="1.2.3.4")
        graph.add_vulnerability("SQLi in /login", "CRITICAL", parent_service="http:80")
        print(graph.to_ascii())
    """

    _SEV_WEIGHTS = {"CRITICAL": 1.0, "HIGH": 0.85, "MEDIUM": 0.6, "LOW": 0.3, "INFO": 0.1}

    def __init__(self, target: str):
        self.target  = target
        self._nodes: Dict[str, Node]   = {}
        self._edges: List[Edge]        = []
        self._adj:   Dict[str, List[str]] = {}  # adjacency list (outgoing)
        self._radj:  Dict[str, List[str]] = {}  # reverse adjacency (incoming)

        # Insert root node
        root_id = self._uid("target", target)
        self._insert_node(root_id, "target", target)
        self.root_id = root_id

    # ──────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────

    def _uid(self, node_type: str, label: str) -> str:
        """Generate a stable 12-char hex ID from (type, label)."""
        raw = f"{node_type}:{label.lower().strip()}"
        return hashlib.md5(raw.encode()).hexdigest()[:12]

    def _insert_node(self, node_id: str, node_type: str, label: str, data: Dict = None) -> str:
        """Insert a node, or merge data into an existing one."""
        if node_id not in self._nodes:
            self._nodes[node_id] = Node(node_id, node_type, label, data or {})
            self._adj[node_id]  = []
            self._radj[node_id] = []
        elif data:
            self._nodes[node_id].data.update(data)
        return node_id

    def _insert_edge(
        self,
        src: str,
        dst: str,
        relation: str,
        weight: float = 1.0,
        data: Dict = None,
    ) -> None:
        """Insert a directed edge; silently ignores duplicates."""
        for e in self._edges:
            if e.source == src and e.target == dst and e.relation == relation:
                return
        self._edges.append(Edge(src, dst, relation, weight, data))
        if src in self._adj and dst not in self._adj[src]:
            self._adj[src].append(dst)
        if dst in self._radj and src not in self._radj[dst]:
            self._radj[dst].append(src)

    def _resolve_parent(self, label: Optional[str], node_type: str) -> str:
        """Return parent node ID if it exists, else root."""
        if label:
            candidate = self._uid(node_type, label)
            if candidate in self._nodes:
                return candidate
        return self.root_id

    # ──────────────────────────────────────────────
    # Public add_* API
    # ──────────────────────────────────────────────

    def add_domain(self, domain: str) -> str:
        nid = self._insert_node(self._uid("domain", domain), "domain", domain)
        self._insert_edge(self.root_id, nid, "has_domain")
        return nid

    def add_subdomain(self, subdomain: str, parent_domain: str = None) -> str:
        nid = self._insert_node(self._uid("subdomain", subdomain), "subdomain", subdomain)
        parent = self._resolve_parent(parent_domain, "domain")
        self._insert_edge(parent, nid, "has_subdomain")
        return nid

    def add_ip(self, ip: str, parent_subdomain: str = None) -> str:
        nid = self._insert_node(self._uid("ip", ip), "ip", ip)
        parent = self._resolve_parent(parent_subdomain, "subdomain")
        self._insert_edge(parent, nid, "resolves_to")
        return nid

    def add_service(
        self,
        port: int,
        service: str,
        version: str = "",
        parent_ip: str = None,
    ) -> str:
        label = f"{service}:{port}"
        nid = self._insert_node(
            self._uid("service", label),
            "service",
            label,
            {"port": port, "service": service, "version": version},
        )
        parent = self._resolve_parent(parent_ip, "ip")
        self._insert_edge(parent, nid, "runs_service", weight=0.8)
        return nid

    def add_vulnerability(
        self,
        title: str,
        severity: str,
        description: str = "",
        cve: str = None,
        evidence: str = "",
        parent_service: str = None,
        url: str = None,
    ) -> str:
        weight = self._SEV_WEIGHTS.get(severity.upper(), 0.5)
        nid = self._insert_node(
            self._uid("vulnerability", title),
            "vulnerability",
            title,
            {
                "severity":    severity,
                "description": description,
                "cve":         cve,
                "evidence":    evidence[:500] if evidence else "",
                "url":         url,
            },
        )
        parent = self._resolve_parent(parent_service, "service")
        self._insert_edge(parent, nid, "has_vulnerability", weight=weight)
        return nid

    def add_exploit_path(
        self,
        title: str,
        vuln_title: str,
        steps: List[str] = None,
        tool: str = None,
    ) -> str:
        nid = self._insert_node(
            self._uid("exploit_path", title),
            "exploit_path",
            title,
            {"steps": steps or [], "tool": tool},
        )
        vuln_id = self._uid("vulnerability", vuln_title)
        if vuln_id in self._nodes:
            self._insert_edge(vuln_id, nid, "leads_to", weight=1.0)
        else:
            self._insert_edge(self.root_id, nid, "leads_to", weight=1.0)
        return nid

    def add_credential(
        self,
        username: str,
        password: str,
        service: str = "",
        url: str = "",
    ) -> str:
        label = f"{username}@{service}"
        nid = self._insert_node(
            self._uid("credential", label),
            "credential",
            label,
            {"username": username, "password": password, "service": service, "url": url},
        )
        parent = self._resolve_parent(service, "service") if service else self.root_id
        self._insert_edge(parent, nid, "has_credential", weight=1.0)
        return nid

    # ──────────────────────────────────────────────
    # Query API
    # ──────────────────────────────────────────────

    def get_nodes_by_type(self, node_type: str) -> List[Node]:
        return [n for n in self._nodes.values() if n.type == node_type]

    def get_vulnerabilities(self, min_severity: str = None) -> List[Node]:
        """Return all vulnerability nodes, optionally filtered by minimum severity."""
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        vulns = self.get_nodes_by_type("vulnerability")
        if min_severity:
            idx = order.index(min_severity.upper()) if min_severity.upper() in order else 4
            vulns = [v for v in vulns if order.index(v.data.get("severity", "INFO").upper()) <= idx]
        return sorted(vulns, key=lambda v: order.index(v.data.get("severity", "INFO").upper()))

    def get_high_value_targets(self) -> List[Dict]:
        """Return CRITICAL + HIGH vulnerabilities sorted by severity."""
        results = []
        for v in self.get_vulnerabilities(min_severity="HIGH"):
            results.append({
                "id":          v.id,
                "label":       v.label,
                "severity":    v.data.get("severity", "?"),
                "description": v.data.get("description", "")[:100],
                "cve":         v.data.get("cve"),
                "evidence":    v.data.get("evidence", "")[:80],
            })
        return results

    def get_attack_paths(self, max_depth: int = 8) -> List[List[str]]:
        """DFS: collect all root→leaf paths up to max_depth."""
        paths: List[List[str]] = []

        def dfs(nid: str, path: List[str], depth: int):
            if depth > max_depth:
                return
            path = path + [nid]
            neighbors = self._adj.get(nid, [])
            node = self._nodes.get(nid)
            if not neighbors or (node and node.type == "exploit_path"):
                paths.append(path)
                return
            for neighbor in neighbors:
                dfs(neighbor, path, depth + 1)

        dfs(self.root_id, [], 0)
        return paths

    def get_critical_path(self) -> Optional[List[Node]]:
        """
        Return the highest-weight path from target to an exploit_path node.
        Uses a greedy max-weight walk.
        """
        path: List[str] = []
        visited = set()

        def walk(nid: str) -> float:
            if nid in visited:
                return 0.0
            visited.add(nid)
            path.append(nid)
            node = self._nodes.get(nid)
            if not node:
                return 0.0
            if node.type == "exploit_path":
                return 1.0

            # Pick highest-weight outgoing edge
            best_weight, best_nid = 0.0, None
            for e in self._edges:
                if e.source == nid and e.target not in visited:
                    if e.weight > best_weight:
                        best_weight, best_nid = e.weight, e.target

            if best_nid:
                return best_weight + walk(best_nid)
            return 0.0

        walk(self.root_id)
        return [self._nodes[nid] for nid in path if nid in self._nodes]

    # ──────────────────────────────────────────────
    # Summaries
    # ──────────────────────────────────────────────

    def get_graph_summary(self) -> Dict:
        """Return a statistics summary of the graph."""
        type_counts: Dict[str, int] = {}
        for node in self._nodes.values():
            type_counts[node.type] = type_counts.get(node.type, 0) + 1
        return {
            "total_nodes":       len(self._nodes),
            "total_edges":       len(self._edges),
            "node_types":        type_counts,
            "attack_paths":      len(self.get_attack_paths()),
            "high_value_targets":len(self.get_high_value_targets()),
        }

    def to_dict(self) -> Dict:
        """Serialize the full graph to a JSON-compatible dict."""
        return {
            "target":  self.target,
            "nodes":   [n.to_dict() for n in self._nodes.values()],
            "edges":   [e.to_dict() for e in self._edges],
            "summary": self.get_graph_summary(),
        }

    def to_ascii(self, max_depth: int = 5) -> str:
        """Render the graph as an indented ASCII tree."""
        lines = [f"{Node.TYPE_ICONS['target']} [TARGET] {self.target}"]

        def render(nid: str, depth: int, prefix: str):
            if depth > max_depth:
                return
            neighbors = self._adj.get(nid, [])
            for i, child_id in enumerate(neighbors):
                node = self._nodes.get(child_id)
                if not node:
                    continue
                is_last   = (i == len(neighbors) - 1)
                connector = "└── " if is_last else "├── "
                extra     = ""
                if node.type == "service":
                    extra = f"  ver={node.data.get('version', '?')[:30]}"
                elif node.type == "vulnerability":
                    extra = f"  [{node.data.get('severity','?')}] {node.data.get('cve') or ''}"
                elif node.type == "credential":
                    extra = f"  user={node.data.get('username','?')}"
                lines.append(f"{prefix}{connector}{node.icon} [{node.type.upper()}] {node.label}{extra}")
                child_prefix = prefix + ("    " if is_last else "│   ")
                render(child_id, depth + 1, child_prefix)

        render(self.root_id, 0, "")
        return "\n".join(lines)
