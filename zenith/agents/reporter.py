"""
Reporter Agent - Generates structured HTML, JSON, and Markdown reports.

Pulls all data from SharedMemory and AttackGraph, calls the AI for an
executive summary, then writes three report files to the scan workspace.
"""

import json
import os
import re
import textwrap
from datetime import datetime
from typing import Dict, List, Optional

from zenith.agents.base_agent import BaseAgent, AgentResult


_REPORT_PROMPT = """You are a senior penetration tester writing an executive security report.

Target: {target}
Scan duration: {duration}
Total vulnerabilities: {total_vulns}
Critical/High: {critical_high}

Vulnerability list:
{vuln_list}

Attack graph summary:
{graph_summary}

Write a professional JSON report with:
{{
  "executive_summary": "2-3 paragraph non-technical summary",
  "risk_rating": "CRITICAL | HIGH | MEDIUM | LOW",
  "critical_findings": ["list of top findings"],
  "attack_narrative": "How an attacker would exploit this target step by step",
  "remediation_priority": [
    {{"finding": "...", "remediation": "...", "effort": "low|medium|high", "urgency": "immediate|30days|90days"}}
  ],
  "all_findings": ["full list of all finding titles"],
  "recommendations": ["actionable security recommendations"]
}}

Return ONLY valid JSON."""


class ReporterAgent(BaseAgent):
    """Generates HTML + JSON + Markdown reports from all accumulated findings."""

    NAME        = "reporter"
    DESCRIPTION = "Generates professional HTML, JSON, and Markdown security reports"
    REQUIRES    = ["exploit"]
    PROVIDES    = []

    def run(
        self,
        target:      str,
        working_dir: str  = "/tmp/zenith_workspace",
        duration:    str  = "unknown",
        iterations:  int  = 0,
        model_name:  str  = "ZenithAI",
        **kwargs,
    ) -> AgentResult:
        self._start()
        self.memory.set_agent_status(self.NAME, "running")
        self._log("Generating security reports …", "info")

        ctx   = self.memory.get_context()
        vulns = ctx.get("vulnerabilities", [])
        os.makedirs(working_dir, exist_ok=True)

        # AI executive summary
        ai_report = self._generate_ai_report(target, vulns, duration)

        # Determine output paths
        safe   = re.sub(r'[^a-zA-Z0-9_.-]', '_', target)[:40]
        ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
        prefix = os.path.join(working_dir, f"{safe}_{ts}")

        html_path = prefix + ".html"
        json_path = prefix + ".json"
        md_path   = prefix + ".md"

        # Write all three
        errors: List[str] = []
        try:
            self._write_html(html_path, target, ctx, ai_report, duration, iterations, model_name)
        except Exception as e:
            errors.append(f"HTML report error: {e}")

        try:
            self._write_json(json_path, target, ctx, ai_report, duration, iterations)
        except Exception as e:
            errors.append(f"JSON report error: {e}")

        try:
            self._write_markdown(md_path, target, ctx, ai_report, duration)
        except Exception as e:
            errors.append(f"Markdown report error: {e}")

        self.memory.set_agent_status(self.NAME, "done")
        self.memory.store_agent_result(self.NAME, {
            "html": html_path, "json": json_path, "markdown": md_path,
        })
        self._emit("reports_ready", {
            "html": html_path, "json": json_path, "markdown": md_path,
        })

        self._log(f"HTML  → {html_path}", "success")
        self._log(f"JSON  → {json_path}", "success")
        self._log(f"MD    → {md_path}",   "success")

        return AgentResult(
            agent_name = self.NAME,
            status     = "success" if not errors else "partial",
            data       = {"html": html_path, "json": json_path, "markdown": md_path},
            errors     = errors,
            duration   = self._elapsed(),
            message    = f"Reports written to {working_dir}",
        )

    # ──────────────────────────────────────────────
    # AI summary
    # ──────────────────────────────────────────────

    def _generate_ai_report(self, target: str, vulns: List, duration: str) -> Dict:
        sev_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_v = sorted(vulns, key=lambda v: sev_map.get(v.get("severity", "INFO"), 4))
        critical_high = sum(1 for v in vulns if v.get("severity") in ("CRITICAL", "HIGH"))

        vuln_list = "\n".join(
            f"  [{v.get('severity','?')}] {v.get('title','?')[:60]}"
            for v in sorted_v[:20]
        ) or "  No vulnerabilities found."

        graph_summary = ""
        if self.graph:
            gs = self.graph.get_graph_summary()
            graph_summary = (
                f"Nodes: {gs['total_nodes']} | Edges: {gs['total_edges']} | "
                f"Attack paths: {gs['attack_paths']} | High-value: {gs['high_value_targets']}"
            )

        prompt = _REPORT_PROMPT.format(
            target        = target,
            duration      = duration,
            total_vulns   = len(vulns),
            critical_high = critical_high,
            vuln_list     = vuln_list,
            graph_summary = graph_summary or "N/A",
        )

        try:
            raw   = self.ai.think(prompt)
            match = re.search(r'\{[\s\S]*\}', raw)
            if match:
                return json.loads(match.group())
        except Exception:
            pass

        return {
            "executive_summary": (
                f"Security assessment of {target} completed. "
                f"{len(vulns)} vulnerabilities found "
                f"({critical_high} critical/high severity)."
            ),
            "risk_rating":            "HIGH" if critical_high else "MEDIUM",
            "critical_findings":      [v["title"] for v in sorted_v[:5]],
            "attack_narrative":       "Manual review required.",
            "remediation_priority":   [],
            "all_findings":           [v["title"] for v in vulns],
            "recommendations":        ["Apply latest security patches.",
                                       "Enforce authentication everywhere.",
                                       "Review access controls."],
        }

    # ──────────────────────────────────────────────
    # JSON report
    # ──────────────────────────────────────────────

    def _write_json(
        self, path: str, target: str, ctx: Dict,
        ai_report: Dict, duration: str, iterations: int,
    ) -> None:
        report = {
            "meta": {
                "target":     target,
                "generated":  datetime.now().isoformat(),
                "scanner":    "ZenithAI v2.0",
                "duration":   duration,
                "iterations": iterations,
            },
            "summary": {
                "risk_rating":          ai_report.get("risk_rating"),
                "total_vulnerabilities":len(ctx.get("vulnerabilities", [])),
                "executive_summary":    ai_report.get("executive_summary"),
                "attack_narrative":     ai_report.get("attack_narrative"),
            },
            "vulnerabilities":     ctx.get("vulnerabilities", []),
            "open_ports":          ctx.get("open_ports", []),
            "subdomains":          ctx.get("subdomains", []),
            "technologies":        ctx.get("technologies", []),
            "credentials":         ctx.get("credentials", []),
            "api_endpoints":       ctx.get("api_endpoints", []),
            "cve_matches":         ctx.get("cve_matches", []),
            "recommendations":     ai_report.get("recommendations", []),
            "remediation_priority":ai_report.get("remediation_priority", []),
            "attack_graph":        self.graph.to_dict() if self.graph else {},
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    # ──────────────────────────────────────────────
    # Markdown report
    # ──────────────────────────────────────────────

    def _write_markdown(
        self, path: str, target: str, ctx: Dict, ai_report: Dict, duration: str
    ) -> None:
        vulns   = ctx.get("vulnerabilities", [])
        sev_map = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}

        lines = [
            f"# ZenithAI Security Report",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Target** | `{target}` |",
            f"| **Date** | {datetime.now().strftime('%Y-%m-%d %H:%M')} |",
            f"| **Duration** | {duration} |",
            f"| **Risk Rating** | **{ai_report.get('risk_rating','UNKNOWN')}** |",
            f"| **Total Vulns** | {len(vulns)} |",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            textwrap.fill(ai_report.get("executive_summary", ""), 100),
            f"",
            f"## Attack Narrative",
            f"",
            textwrap.fill(ai_report.get("attack_narrative", ""), 100),
            f"",
            f"## Vulnerabilities",
            f"",
        ]

        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for sev in sev_order:
            sev_vulns = [v for v in vulns if v.get("severity","").upper() == sev]
            if not sev_vulns:
                continue
            lines.append(f"### {sev_map.get(sev,'')} {sev} ({len(sev_vulns)})")
            lines.append("")
            for v in sev_vulns:
                lines.append(f"#### {v.get('title', 'Unknown')}")
                if v.get("cve"):
                    lines.append(f"- **CVE**: [{v['cve']}](https://nvd.nist.gov/vuln/detail/{v['cve']})")
                if v.get("description"):
                    lines.append(f"- **Description**: {v['description'][:200]}")
                if v.get("evidence"):
                    lines.append(f"- **Evidence**: `{v['evidence'][:150]}`")
                if v.get("url"):
                    lines.append(f"- **URL**: `{v['url']}`")
                lines.append("")

        # Recommendations
        if ai_report.get("recommendations"):
            lines += ["## Recommendations", ""]
            for i, rec in enumerate(ai_report["recommendations"], 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        # Remediation priority table
        rp = ai_report.get("remediation_priority", [])
        if rp:
            lines += [
                "## Remediation Priority",
                "",
                "| Finding | Remediation | Effort | Urgency |",
                "|---------|-------------|--------|---------|",
            ]
            for item in rp:
                lines.append(
                    f"| {item.get('finding','')} | {item.get('remediation','')} "
                    f"| {item.get('effort','')} | {item.get('urgency','')} |"
                )
            lines.append("")

        # Attack graph
        if self.graph:
            lines += ["## Attack Graph", "", "```", self.graph.to_ascii(), "```", ""]

        # Open ports
        if ctx.get("open_ports"):
            lines += ["## Open Ports", "", "| Port | Service | Version |", "|------|---------|---------|"]
            for p in ctx["open_ports"][:30]:
                lines.append(f"| {p.get('port')} | {p.get('service')} | {p.get('version','')} |")
            lines.append("")

        # Subdomains
        if ctx.get("subdomains"):
            lines += ["## Subdomains", ""]
            for sd in ctx["subdomains"]:
                lines.append(f"- `{sd}`")
            lines.append("")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    # ──────────────────────────────────────────────
    # HTML report
    # ──────────────────────────────────────────────

    def _write_html(
        self, path: str, target: str, ctx: Dict, ai_report: Dict,
        duration: str, iterations: int, model_name: str,
    ) -> None:
        vulns    = ctx.get("vulnerabilities", [])
        ports    = ctx.get("open_ports", [])
        subs     = ctx.get("subdomains", [])
        techs    = ctx.get("technologies", [])
        risk     = ai_report.get("risk_rating", "UNKNOWN")
        sev_map  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_v = sorted(vulns, key=lambda v: sev_map.get(v.get("severity","INFO"), 4))

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in vulns:
            s = v.get("severity", "INFO").upper()
            counts[s] = counts.get(s, 0) + 1

        risk_colors = {
            "CRITICAL": "#dc2626", "HIGH": "#ea580c",
            "MEDIUM":   "#d97706", "LOW":  "#16a34a", "UNKNOWN": "#6b7280",
        }
        risk_color = risk_colors.get(risk, "#6b7280")

        def _sev_badge(sev: str) -> str:
            colors = {
                "CRITICAL": "background:#dc2626;color:#fff",
                "HIGH":     "background:#ea580c;color:#fff",
                "MEDIUM":   "background:#d97706;color:#fff",
                "LOW":      "background:#16a34a;color:#fff",
                "INFO":     "background:#6b7280;color:#fff",
            }
            style = colors.get(sev.upper(), colors["INFO"])
            return (f'<span style="padding:2px 8px;border-radius:4px;'
                    f'font-size:0.75rem;font-weight:700;{style}">{sev}</span>')

        vuln_rows = ""
        for v in sorted_v:
            sev   = v.get("severity", "INFO").upper()
            cve   = v.get("cve", "")
            cve_h = (f'<a href="https://nvd.nist.gov/vuln/detail/{cve}" '
                     f'target="_blank" style="color:#60a5fa">{cve}</a>') if cve else ""
            vuln_rows += f"""
                <tr>
                  <td>{_sev_badge(sev)}</td>
                  <td><strong>{v.get('title','?')}</strong><br>
                      <small style="color:#9ca3af">{v.get('description','')[:150]}</small></td>
                  <td style="font-size:0.8rem;color:#9ca3af">{cve_h}</td>
                  <td><code style="font-size:0.75rem;color:#86efac">{(v.get('evidence','') or '')[:80]}</code></td>
                </tr>"""

        port_rows = "".join(
            f"<tr><td>{p.get('port')}</td><td>{p.get('service')}</td>"
            f"<td>{p.get('version','')}</td></tr>"
            for p in ports[:30]
        )
        subs_html = "".join(f"<li><code>{s}</code></li>" for s in subs[:30])
        tech_html = "".join(
            f'<span style="background:#1e3a5f;color:#93c5fd;padding:3px 10px;'
            f'border-radius:12px;margin:2px;display:inline-block;font-size:0.8rem">'
            f'{t}</span>' for t in techs[:20]
        )

        recs = "\n".join(
            f'<li style="margin-bottom:6px">{r}</li>'
            for r in ai_report.get("recommendations", [])
        )

        # Attack graph
        graph_html = ""
        if self.graph:
            ascii_tree = self.graph.to_ascii()
            graph_html = f'<pre style="color:#86efac;font-size:0.8rem">{ascii_tree}</pre>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ZenithAI Report — {target}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0f172a;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;line-height:1.6}}
  .container{{max-width:1200px;margin:0 auto;padding:2rem}}
  h1{{font-size:2rem;font-weight:800;background:linear-gradient(135deg,#06b6d4,#6366f1);
      -webkit-background-clip:text;-webkit-text-fill-color:transparent}}
  h2{{font-size:1.25rem;font-weight:700;color:#93c5fd;margin:2rem 0 1rem;
      border-bottom:1px solid #1e3a5f;padding-bottom:.5rem}}
  .meta{{display:flex;gap:1rem;flex-wrap:wrap;margin:1.5rem 0}}
  .badge{{background:#1e293b;border:1px solid #334155;padding:.5rem 1rem;
          border-radius:.5rem;font-size:.85rem}}
  .risk-badge{{background:{risk_color}22;border:1px solid {risk_color};
               color:{risk_color};padding:.5rem 1.5rem;border-radius:.5rem;
               font-weight:800;font-size:1.1rem}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:1rem;margin:1.5rem 0}}
  .stat{{background:#1e293b;border:1px solid #334155;border-radius:.75rem;
         padding:1rem;text-align:center}}
  .stat .num{{font-size:2rem;font-weight:800}}
  .stat .label{{font-size:.75rem;color:#94a3b8}}
  .card{{background:#1e293b;border:1px solid #334155;border-radius:.75rem;
         padding:1.5rem;margin-bottom:1.5rem}}
  table{{width:100%;border-collapse:collapse}}
  th{{text-align:left;padding:.75rem;background:#0f172a;color:#94a3b8;
      font-size:.8rem;text-transform:uppercase;letter-spacing:.05em}}
  td{{padding:.75rem;border-bottom:1px solid #1e3a5f;vertical-align:top}}
  tr:hover td{{background:#0f172a}}
  code{{background:#0f172a;padding:2px 6px;border-radius:4px;font-size:.85rem}}
  .summary{{background:#0f172a;border-left:4px solid #6366f1;padding:1rem 1.5rem;
            border-radius:.25rem;color:#cbd5e1;line-height:1.8}}
  ul{{padding-left:1.5rem}}
  li{{margin-bottom:4px}}
</style>
</head>
<body>
<div class="container">
  <h1>⚡ ZenithAI Security Report</h1>
  <div class="meta">
    <span class="badge">🎯 {target}</span>
    <span class="badge">🕐 {datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
    <span class="badge">⏱ {duration}</span>
    <span class="badge">🤖 {model_name}</span>
    <span class="badge">🔁 {iterations} iterations</span>
    <span class="risk-badge">Risk: {risk}</span>
  </div>

  <div class="stats">
    <div class="stat"><div class="num" style="color:#dc2626">{counts['CRITICAL']}</div><div class="label">Critical</div></div>
    <div class="stat"><div class="num" style="color:#ea580c">{counts['HIGH']}</div><div class="label">High</div></div>
    <div class="stat"><div class="num" style="color:#d97706">{counts['MEDIUM']}</div><div class="label">Medium</div></div>
    <div class="stat"><div class="num" style="color:#16a34a">{counts['LOW']}</div><div class="label">Low</div></div>
    <div class="stat"><div class="num" style="color:#22d3ee">{len(ports)}</div><div class="label">Open Ports</div></div>
    <div class="stat"><div class="num" style="color:#a78bfa">{len(subs)}</div><div class="label">Subdomains</div></div>
  </div>

  <h2>Executive Summary</h2>
  <div class="card">
    <div class="summary">{ai_report.get('executive_summary','').replace(chr(10),'<br>')}</div>
  </div>

  <h2>Vulnerabilities ({len(vulns)})</h2>
  <div class="card" style="padding:0;overflow:hidden">
    <table>
      <tr><th>Severity</th><th>Finding</th><th>CVE</th><th>Evidence</th></tr>
      {vuln_rows or '<tr><td colspan="4" style="color:#6b7280;text-align:center;padding:2rem">No vulnerabilities found</td></tr>'}
    </table>
  </div>

  <h2>Technologies</h2>
  <div class="card">{tech_html or '<span style="color:#6b7280">None detected</span>'}</div>

  <h2>Open Ports</h2>
  <div class="card" style="padding:0;overflow:hidden">
    <table><tr><th>Port</th><th>Service</th><th>Version</th></tr>
    {port_rows or '<tr><td colspan="3" style="color:#6b7280;text-align:center;padding:2rem">No open ports found</td></tr>'}
    </table>
  </div>

  <h2>Subdomains ({len(subs)})</h2>
  <div class="card"><ul>{subs_html or '<li style="color:#6b7280">None found</li>'}</ul></div>

  {'<h2>Attack Graph</h2><div class="card">' + graph_html + '</div>' if graph_html else ''}

  <h2>Recommendations</h2>
  <div class="card"><ul>{recs or '<li>Review all findings manually.</li>'}</ul></div>

  <p style="color:#475569;font-size:.75rem;text-align:center;margin-top:2rem">
    Generated by <strong>ZenithAI v2.0</strong> — Autonomous AI Security Scanner
  </p>
</div>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
