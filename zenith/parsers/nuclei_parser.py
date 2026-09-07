"""
Nuclei Parser - Converts nuclei JSON-lines output into structured vulnerability dicts.

Nuclei output format (-jsonl flag):
  {"template-id":"...", "info":{"name":"...","severity":"high",...}, "matched-at":"..."}
"""

import json
import re
from typing import Dict, List, Optional


class NucleiParser:
    """Parse nuclei -jsonl output into normalized vulnerability objects."""

    # Severity normalisation map
    SEV_MAP = {
        "critical": "CRITICAL",
        "high":     "HIGH",
        "medium":   "MEDIUM",
        "low":      "LOW",
        "info":     "INFO",
        "unknown":  "INFO",
    }

    @staticmethod
    def parse(output: str) -> List[Dict]:
        """
        Parse nuclei -jsonl output.

        Returns:
            List of vulnerability dicts:
            [{"title": "...", "severity": "HIGH", "cve": "CVE-...",
              "description": "...", "matched_at": "...", "template_id": "...",
              "tags": [...], "references": [...], "evidence": "..."}]
        """
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            finding = NucleiParser._parse_one(obj)
            if finding:
                findings.append(finding)

        return findings

    @staticmethod
    def _parse_one(obj: Dict) -> Optional[Dict]:
        """Parse a single nuclei JSON line into a finding dict."""
        info        = obj.get("info", {})
        sev_raw     = info.get("severity", "info").lower()
        severity    = NucleiParser.SEV_MAP.get(sev_raw, "INFO")

        name        = info.get("name", "")
        desc        = info.get("description", "")
        template_id = obj.get("template-id", "")
        matched_at  = obj.get("matched-at", "")
        extracted   = obj.get("extracted-results", [])
        curl_cmd    = obj.get("curl-command", "")

        # Extract CVE
        cve = None
        for ref in info.get("reference", []):
            m = re.search(r'CVE-\d{4}-\d+', str(ref), re.I)
            if m:
                cve = m.group().upper()
                break
        if not cve:
            m = re.search(r'CVE-\d{4}-\d+', template_id, re.I)
            if m:
                cve = m.group().upper()

        if not name:
            return None

        return {
            "title":       name,
            "severity":    severity,
            "description": desc[:300] if desc else "",
            "cve":         cve,
            "template_id": template_id,
            "matched_at":  matched_at,
            "tags":        info.get("tags", []),
            "references":  info.get("reference", [])[:3],
            "evidence":    matched_at or (str(extracted[:2]) if extracted else ""),
            "curl":        curl_cmd[:200] if curl_cmd else "",
            "tool":        "nuclei",
        }

    @staticmethod
    def parse_plain(output: str) -> List[Dict]:
        """
        Parse nuclei plain-text output (without -jsonl flag).

        Example line:
          [critical] [cve/CVE-2023-1234] [http] https://example.com/path [CVE-2023-1234]
        """
        findings = []
        pattern  = re.compile(
            r'\[(\w+)\]\s+\[([^\]]+)\]\s+\[(\w+)\]\s+(\S+)(?:\s+\[([^\]]+)\])?'
        )
        for line in output.splitlines():
            m = pattern.search(line)
            if not m:
                continue
            sev_raw     = m.group(1).lower()
            template_id = m.group(2)
            proto       = m.group(3)
            url         = m.group(4)
            extras      = m.group(5) or ""

            cve_m = re.search(r'CVE-\d{4}-\d+', template_id + extras, re.I)
            cve   = cve_m.group().upper() if cve_m else None

            findings.append({
                "title":       template_id,
                "severity":    NucleiParser.SEV_MAP.get(sev_raw, "INFO"),
                "description": "",
                "cve":         cve,
                "template_id": template_id,
                "matched_at":  url,
                "tags":        [proto],
                "references":  [],
                "evidence":    url,
                "tool":        "nuclei",
            })

        return findings
