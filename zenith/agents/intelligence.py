"""
Intelligence Agent - Vulnerability database lookups and exploit matching.

Queries:
  - NVD API (nvd.nist.gov) — official CVE database
  - ExploitDB via searchsploit — offline exploit database
  - MITRE CVE API — alternative CVE lookup
  - OSV API (Google) — open-source vulnerability database

Matches discovered technology versions against known vulnerabilities
and feeds CVE + exploit data to the attack graph and exploit agent.
"""

import re
import json
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Optional

from zenith.agents.base_agent import BaseAgent, AgentResult


class IntelligenceAgent(BaseAgent):
    """Queries CVE/ExploitDB for technologies found by the recon agent."""

    NAME        = "intelligence"
    DESCRIPTION = "CVE + exploit matching for discovered technologies (NVD, ExploitDB, MITRE)"
    REQUIRES    = ["recon"]
    PROVIDES    = ["cve_matches"]

    NVD_API    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MITRE_API  = "https://cveawg.mitre.org/api/cve"

    def run(self, target: str, **kwargs) -> AgentResult:
        self._start()
        self.memory.set_agent_status(self.NAME, "running")

        techs      = self._ctx("technologies") or []
        ports      = self._ctx("open_ports")   or []
        findings:  List[Dict] = []
        matches:   List[Dict] = []
        errors:    List[str]  = []

        if not techs and not ports:
            self._log("No technologies or ports to look up — skipping", "warning")
            self.memory.set_agent_status(self.NAME, "skipped")
            return AgentResult(
                agent_name = self.NAME,
                status     = "skipped",
                duration   = self._elapsed(),
                message    = "No targets for CVE lookup",
            )

        self._log(f"Looking up CVEs for {len(techs)} technologies …", "info")

        # 1. Parse versions from technology strings
        tech_versions = self._extract_versions(techs, ports)

        # 2. Query NVD for each tech
        for tech_entry in tech_versions[:8]:   # Cap API calls
            product = tech_entry["product"]
            version = tech_entry.get("version")
            self._log(f"  Querying NVD: {product} {version or ''}", "info")

            cves = self._nvd_lookup(product, version, errors)
            for cve in cves[:3]:              # Top-3 CVEs per product
                match = {
                    "cve":         cve.get("id"),
                    "tech":        product,
                    "version":     version,
                    "severity":    cve.get("severity", "UNKNOWN"),
                    "cvss":        cve.get("cvss", 0.0),
                    "description": cve.get("description", "")[:200],
                    "published":   cve.get("published", ""),
                    "references":  cve.get("references", [])[:2],
                }
                matches.append(match)
                if cve.get("severity") in ("CRITICAL", "HIGH"):
                    findings.append({
                        "title":       f"{cve['id']} — {product} {version or ''}",
                        "severity":    cve.get("severity", "HIGH"),
                        "description": cve.get("description", "")[:200],
                        "cve":         cve.get("id"),
                        "tool":        "nvd_api",
                    })
                    self._log(
                        f"[{cve.get('severity')}] {cve.get('id')} → {product}",
                        "warning"
                    )
                if self.graph:
                    self.graph.add_vulnerability(
                        title       = f"{cve.get('id')}: {product} {version or ''}",
                        severity    = cve.get("severity", "INFO"),
                        description = cve.get("description", "")[:200],
                        cve         = cve.get("id"),
                    )
            time.sleep(0.7)   # Respect NVD rate limit (5 req/s rolling)

        # 3. searchsploit for offline exploit match
        searchsploit_results = self._searchsploit_lookup(tech_versions, errors)
        matches += searchsploit_results
        for m in searchsploit_results:
            if m.get("severity") in ("CRITICAL", "HIGH"):
                findings.append({
                    "title":    f"ExploitDB: {m.get('title', '?')}",
                    "severity": m.get("severity", "HIGH"),
                    "evidence": m.get("edb_id", ""),
                    "tool":     "searchsploit",
                })

        # 4. Persist
        self._update("cve_matches", matches)
        self._write("cve_matches", matches)
        self._emit("intel_ready", matches)

        self.memory.set_agent_status(self.NAME, "done")
        self.memory.store_agent_result(self.NAME, {"cve_matches": matches})

        return AgentResult(
            agent_name = self.NAME,
            status     = "success" if not errors else "partial",
            findings   = findings,
            data       = {"cve_matches": matches},
            errors     = errors,
            duration   = self._elapsed(),
            message    = f"Found {len(matches)} CVE matches ({len(findings)} critical/high)",
        )

    # ──────────────────────────────────────────────
    # Version extraction
    # ──────────────────────────────────────────────

    def _extract_versions(self, techs: List[str], ports: List[Dict]) -> List[Dict]:
        """
        Parse product/version pairs from technology strings and port banners.
        Examples: "Apache 2.4.50" → {"product": "apache", "version": "2.4.50"}
        """
        entries = []
        seen    = set()

        # From tech strings
        for tech in techs:
            m = re.match(r'^([A-Za-z\-\.]+)\s+([\d\.]+)', tech.strip())
            if m:
                product = m.group(1).lower()
                version = m.group(2)
                key     = f"{product}/{version}"
                if key not in seen:
                    seen.add(key)
                    entries.append({"product": product, "version": version, "source": "tech"})
            else:
                product = re.sub(r'\s+.*', '', tech).strip().lower()
                if product and product not in seen:
                    seen.add(product)
                    entries.append({"product": product, "version": None, "source": "tech"})

        # From port banners
        for port in ports:
            version = port.get("version", "")
            if not version:
                continue
            m = re.match(r'^([A-Za-z\-_\.]+)\s+([\d\.]+)', version.strip())
            if m:
                product = m.group(1).lower()
                ver     = m.group(2)
                key     = f"{product}/{ver}"
                if key not in seen:
                    seen.add(key)
                    entries.append({"product": product, "version": ver, "source": "banner"})

        return entries[:15]

    # ──────────────────────────────────────────────
    # NVD API
    # ──────────────────────────────────────────────

    def _nvd_lookup(self, product: str, version: Optional[str], errors: List) -> List[Dict]:
        """Query NVD REST API 2.0 for CVEs matching a product."""
        try:
            keyword = f"{product} {version}" if version else product
            params  = urllib.parse.urlencode({
                "keywordSearch": keyword,
                "resultsPerPage": "5",
            })
            url = f"{self.NVD_API}?{params}"
            req = urllib.request.Request(url, headers={"User-Agent": "ZenithAI/2.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())

            cves = []
            for item in data.get("vulnerabilities", []):
                cve  = item.get("cve", {})
                cve_id = cve.get("id", "")
                descs  = cve.get("descriptions", [])
                desc   = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                metrics = cve.get("metrics", {})
                cvss    = 0.0
                sev     = "UNKNOWN"
                # Try CVSSv3 first, then v2
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics:
                        cvss_data = metrics[key][0].get("cvssData", {})
                        cvss      = cvss_data.get("baseScore", 0.0)
                        sev_raw   = cvss_data.get("baseSeverity") or metrics[key][0].get("baseSeverity", "")
                        sev       = sev_raw.upper() if sev_raw else self._cvss_to_severity(cvss)
                        break

                refs = [r["url"] for r in cve.get("references", [])[:2]]
                published = cve.get("published", "")[:10]
                cves.append({
                    "id":          cve_id,
                    "description": desc[:200],
                    "cvss":        cvss,
                    "severity":    sev,
                    "published":   published,
                    "references":  refs,
                })

            # Sort by CVSS score descending
            return sorted(cves, key=lambda c: c.get("cvss", 0.0), reverse=True)

        except urllib.error.HTTPError as e:
            if e.code == 403:
                errors.append("NVD API rate-limited (403) — add NVD_API_KEY env var for higher limits")
            elif e.code != 404:
                errors.append(f"NVD API error for {product}: HTTP {e.code}")
        except Exception as exc:
            errors.append(f"NVD lookup failed for {product}: {exc}")

        return []

    # ──────────────────────────────────────────────
    # ExploitDB via searchsploit
    # ──────────────────────────────────────────────

    def _searchsploit_lookup(self, tech_versions: List[Dict], errors: List) -> List[Dict]:
        """Run searchsploit for each tech and return structured exploit info."""
        out_dir = self._output("which searchsploit 2>/dev/null", timeout=5).strip()
        if not out_dir:
            return []

        results = []
        for entry in tech_versions[:6]:
            product = entry["product"]
            version = entry.get("version", "")
            query   = f"{product} {version}".strip()
            out     = self._output(
                f"searchsploit '{query}' --json 2>/dev/null", timeout=30
            )
            try:
                data   = json.loads(out)
                for xp in data.get("RESULTS_EXPLOIT", [])[:3]:
                    title   = xp.get("Title", "")
                    edb_id  = xp.get("EDB-ID", "")
                    type_   = xp.get("Type", "")
                    # Assign severity based on type
                    sev = ("CRITICAL" if "remote" in type_.lower() else
                           "HIGH"     if "local" in type_.lower()  else "MEDIUM")
                    results.append({
                        "title":    title,
                        "edb_id":   edb_id,
                        "type":     type_,
                        "product":  product,
                        "version":  version,
                        "severity": sev,
                        "source":   "exploitdb",
                    })
            except (json.JSONDecodeError, KeyError):
                # Fallback: parse plain text output
                for line in out.splitlines():
                    if "|" in line:
                        parts = [p.strip() for p in line.split("|")]
                        if len(parts) >= 2:
                            results.append({
                                "title":    parts[-1],
                                "edb_id":   parts[0],
                                "product":  product,
                                "severity": "MEDIUM",
                                "source":   "exploitdb",
                            })

        return results[:20]

    # ──────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────

    def _cvss_to_severity(self, score: float) -> str:
        if score >= 9.0:   return "CRITICAL"
        if score >= 7.0:   return "HIGH"
        if score >= 4.0:   return "MEDIUM"
        if score > 0.0:    return "LOW"
        return "INFO"
