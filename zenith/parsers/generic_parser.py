"""
Generic Parser - AI-assisted output parser for any security tool.

When tool-specific parsers aren't available, this uses pattern matching +
optional AI interpretation to extract structured data from raw output.
"""

import re
from typing import Any, Dict, List, Optional


class GenericParser:
    """
    Extracts structured security findings from arbitrary tool output.

    Can run standalone (pattern-only) or with an AI brain for deeper extraction.
    """

    # Severity keywords for heuristic classification
    _CRITICAL_KEYS = [
        "critical", "rce", "remote code execution", "command injection",
        "unauthenticated", "arbitrary code", "sql injection confirmed",
        "authentication bypass",
    ]
    _HIGH_KEYS = [
        "high", "xss", "sql injection", "directory traversal", "lfi", "rfi",
        "ssrf", "xxe", "idor", "open redirect", "csrf", "insecure deserialization",
        "exposed credentials", "default password",
    ]
    _MEDIUM_KEYS = [
        "medium", "information disclosure", "misconfiguration", "outdated",
        "missing header", "sensitive data", "weak cipher", "self-signed",
    ]
    _LOW_KEYS = [
        "low", "verbose", "banner", "fingerprint", "cors misconfiguration",
    ]

    # Common finding patterns (regex → dict key)
    _PATTERNS = {
        "ip": re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b'),
        "url": re.compile(r'https?://[^\s\'"<>]+'),
        "cve": re.compile(r'CVE-\d{4}-\d+', re.I),
        "port_open": re.compile(r'\b(\d{1,5})/tcp\s+open\s+(\S+)'),
        "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        "hash_md5": re.compile(r'\b[0-9a-f]{32}\b', re.I),
        "hash_sha": re.compile(r'\b[0-9a-f]{40,64}\b', re.I),
        "base64_jwt": re.compile(r'eyJ[A-Za-z0-9+/=]{20,}\.[A-Za-z0-9+/=]{20,}'),
    }

    def __init__(self, ai_brain=None):
        self.ai = ai_brain

    def parse(self, output: str, tool_hint: str = "", context: str = "") -> Dict:
        """
        Parse arbitrary tool output into a structured dict.

        Args:
            output:    Raw stdout/stderr from the tool
            tool_hint: Name of the tool (e.g. "dirsearch", "whatweb") for heuristics
            context:   Additional context (e.g. target URL) for AI parsing

        Returns:
            {
                "findings": [...],   # vulnerability-like dicts
                "ips": [...],
                "urls": [...],
                "cves": [...],
                "ports": [...],
                "emails": [...],
                "raw_summary": "...",
            }
        """
        result: Dict[str, Any] = {
            "findings":    [],
            "ips":         [],
            "urls":        [],
            "cves":        [],
            "ports":       [],
            "emails":      [],
            "raw_summary": "",
        }

        if not output or not output.strip():
            return result

        # Extract known patterns
        result["ips"]    = list({m.group(1) for m in self._PATTERNS["ip"].finditer(output)})[:20]
        result["urls"]   = list({m.group() for m in self._PATTERNS["url"].finditer(output)})[:30]
        result["cves"]   = list({m.group().upper() for m in self._PATTERNS["cve"].finditer(output)})[:10]
        result["emails"] = list({m.group() for m in self._PATTERNS["email"].finditer(output)})[:10]

        for m in self._PATTERNS["port_open"].finditer(output):
            result["ports"].append({"port": int(m.group(1)), "service": m.group(2), "state": "open"})

        # Extract finding lines
        findings = self._extract_findings(output, tool_hint)
        result["findings"] = findings

        # CVE findings
        for cve in result["cves"]:
            result["findings"].append({
                "title":    cve,
                "severity": "HIGH",
                "description": f"CVE reference found in {tool_hint or 'tool'} output",
                "cve":       cve,
                "evidence":  cve,
            })

        # Raw summary (first meaningful 300 chars)
        lines = [l.strip() for l in output.splitlines() if l.strip()]
        result["raw_summary"] = " | ".join(lines[:8])[:300]

        return result

    def _extract_findings(self, output: str, tool_hint: str) -> List[Dict]:
        """Heuristic line-by-line extraction of vulnerability-like findings."""
        findings = []
        seen     = set()

        for line in output.splitlines():
            ll = line.lower()

            # Skip empty / purely decorative lines
            if not line.strip() or all(c in "=-#*. \t" for c in line.strip()):
                continue

            sev = self._classify_line(ll)
            if not sev:
                continue

            title = self._clean_title(line)
            if not title or title in seen:
                continue
            seen.add(title)

            cve_m = self._PATTERNS["cve"].search(line)
            cve   = cve_m.group().upper() if cve_m else None

            url_m = self._PATTERNS["url"].search(line)
            url   = url_m.group() if url_m else None

            findings.append({
                "title":       title[:120],
                "severity":    sev,
                "description": line.strip()[:200],
                "cve":         cve,
                "evidence":    url or line.strip()[:100],
                "tool":        tool_hint or "generic",
            })

        return findings[:30]

    def _classify_line(self, line_lower: str) -> Optional[str]:
        for kw in self._CRITICAL_KEYS:
            if kw in line_lower:
                return "CRITICAL"
        for kw in self._HIGH_KEYS:
            if kw in line_lower:
                return "HIGH"
        for kw in self._MEDIUM_KEYS:
            if kw in line_lower:
                return "MEDIUM"
        for kw in self._LOW_KEYS:
            if kw in line_lower:
                return "LOW"
        return None

    @staticmethod
    def _clean_title(line: str) -> str:
        """Strip ANSI codes, leading symbols, and whitespace from a line."""
        ansi_esc = re.compile(r'\x1b\[[0-9;]*m')
        clean    = ansi_esc.sub('', line).strip()
        clean    = re.sub(r'^[\s\[\]+\-*#>|=]+', '', clean).strip()
        return clean[:120]

    # ──────────────────────────────────────────────
    # Specific tool helpers
    # ──────────────────────────────────────────────

    @staticmethod
    def parse_dirsearch(output: str) -> List[str]:
        """Extract discovered paths from dirsearch output."""
        paths = []
        for line in output.splitlines():
            m = re.search(r'((?:https?://\S+)|(?:/[^\s]+))\s+\[(\d{3})\]', line)
            if m and m.group(2) not in ("404", "400"):
                paths.append(m.group(1))
        return paths

    @staticmethod
    def parse_whatweb(output: str) -> List[str]:
        """Extract technology tags from whatweb output."""
        techs = []
        for item in re.findall(r'\[([^\[\]]+)\]', output):
            for tech in item.split(','):
                t = tech.strip()
                if t and len(t) > 2 and not re.match(r'^\d+\.\d+', t):
                    techs.append(t)
        return list(dict.fromkeys(techs))[:20]   # dedup while preserving order

    @staticmethod
    def parse_subdomains(output: str, base_domain: str) -> List[str]:
        """Extract subdomain lines from subfinder/amass/assetfinder output."""
        results = []
        for line in output.splitlines():
            s = line.strip().lower()
            if s and base_domain in s and re.match(r'^[a-z0-9.\-]+$', s):
                results.append(s)
        return list(set(results))

    @staticmethod
    def parse_httpx(output: str) -> List[Dict]:
        """Parse httpx output: URL, status code, content-length."""
        results = []
        for line in output.splitlines():
            parts = line.split()
            if not parts:
                continue
            url   = parts[0]
            code  = parts[1] if len(parts) > 1 else ""
            title = " ".join(parts[2:]) if len(parts) > 2 else ""
            if url.startswith("http"):
                results.append({"url": url, "status": code, "title": title})
        return results
