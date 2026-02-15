"""
Zenith HTML Report Generator - Beautiful professional security reports.
Generates standalone HTML reports with charts, severity breakdowns, and detailed findings.
"""

import json
import os
from datetime import datetime


class HTMLReportGenerator:
    """
    Generates beautiful standalone HTML security reports.
    No external dependencies - everything is inline CSS/JS.
    """

    def generate(self, report_data, kb_data, scan_info, output_file=None):
        """
        Generate a full HTML security report.
        
        Args:
            report_data: AI analysis report dict
            kb_data: Full knowledge base data dict
            scan_info: Dict with target, model, duration, iterations, etc.
            output_file: Output file path (auto-generated if None)
            
        Returns:
            str: Path to generated HTML report
        """
        if not output_file:
            safe_target = "".join(c if c.isalnum() or c in "-_." else "_" for c in scan_info.get("target", "unknown"))
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(
                scan_info.get("working_dir", "/tmp"),
                f"{safe_target}_report_{timestamp}.html"
            )

        # Gather data
        target = scan_info.get("target", "Unknown")
        model = scan_info.get("model", "Unknown")
        duration = scan_info.get("duration", "Unknown")
        iterations = scan_info.get("iterations", 0)
        commands = scan_info.get("commands_executed", 0)
        
        vulns = kb_data.get("vulnerabilities", [])
        ports = kb_data.get("open_ports", [])
        techs = kb_data.get("target_info", {}).get("technologies", [])
        dirs = kb_data.get("directories", [])
        subdomains = kb_data.get("subdomains", [])
        credentials = kb_data.get("credentials", [])
        
        executive_summary = ""
        risk_rating = "UNKNOWN"
        ai_findings = []
        recommendations = []
        
        if isinstance(report_data, dict):
            executive_summary = report_data.get("executive_summary", "No AI analysis available.")
            risk_rating = report_data.get("risk_rating", "UNKNOWN")
            ai_findings = report_data.get("all_findings", report_data.get("critical_findings", []))
            recommendations = report_data.get("recommendations", [])

        # Count severities
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in vulns:
            s = v.get("severity", "INFO").upper()
            if s in sev_counts:
                sev_counts[s] += 1
            else:
                sev_counts["INFO"] += 1
        
        total_vulns = sum(sev_counts.values())

        # Build HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZenithAI Security Report - {self._escape(target)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0e1a; color: #c9d1d9; line-height: 1.6; }}
        
        .container {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}
        
        /* Header */
        .header {{ background: linear-gradient(135deg, #0d1117 0%, #161b22 100%); border: 1px solid #30363d; border-radius: 12px; padding: 40px; margin-bottom: 24px; text-align: center; }}
        .header h1 {{ color: #58a6ff; font-size: 2.2em; margin-bottom: 8px; }}
        .header .subtitle {{ color: #8b949e; font-size: 1.1em; }}
        .header .target {{ color: #f0883e; font-size: 1.4em; font-weight: bold; margin: 16px 0; padding: 12px; background: rgba(240,136,62,0.1); border-radius: 8px; border: 1px solid rgba(240,136,62,0.3); }}
        .header .meta {{ display: flex; justify-content: center; gap: 30px; margin-top: 16px; flex-wrap: wrap; }}
        .header .meta-item {{ text-align: center; }}
        .header .meta-item .label {{ color: #8b949e; font-size: 0.85em; }}
        .header .meta-item .value {{ color: #c9d1d9; font-weight: bold; font-size: 1.1em; }}
        
        /* Risk Badge */
        .risk-badge {{ display: inline-block; padding: 8px 24px; border-radius: 20px; font-weight: bold; font-size: 1.2em; margin: 12px 0; }}
        .risk-CRITICAL {{ background: rgba(248,81,73,0.2); color: #f85149; border: 2px solid #f85149; }}
        .risk-HIGH {{ background: rgba(219,109,40,0.2); color: #db6d28; border: 2px solid #db6d28; }}
        .risk-MEDIUM {{ background: rgba(210,153,34,0.2); color: #d29922; border: 2px solid #d29922; }}
        .risk-LOW {{ background: rgba(88,166,255,0.2); color: #58a6ff; border: 2px solid #58a6ff; }}
        .risk-UNKNOWN {{ background: rgba(139,148,158,0.2); color: #8b949e; border: 2px solid #8b949e; }}
        
        /* Cards */
        .card {{ background: #0d1117; border: 1px solid #30363d; border-radius: 12px; padding: 24px; margin-bottom: 20px; }}
        .card h2 {{ color: #58a6ff; margin-bottom: 16px; font-size: 1.3em; display: flex; align-items: center; gap: 10px; }}
        .card h2 .icon {{ font-size: 1.3em; }}
        
        /* Stats Grid */
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .stat-box {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 20px; text-align: center; }}
        .stat-box .number {{ font-size: 2em; font-weight: bold; }}
        .stat-box .label {{ color: #8b949e; font-size: 0.9em; margin-top: 4px; }}
        .stat-critical .number {{ color: #f85149; }}
        .stat-high .number {{ color: #db6d28; }}
        .stat-medium .number {{ color: #d29922; }}
        .stat-low .number {{ color: #58a6ff; }}
        .stat-info .number {{ color: #8b949e; }}
        .stat-total .number {{ color: #f0883e; }}
        
        /* Severity Bar */
        .severity-bar {{ display: flex; height: 12px; border-radius: 6px; overflow: hidden; margin: 16px 0; }}
        .sev-segment {{ transition: width 0.5s; }}
        .sev-critical {{ background: #f85149; }}
        .sev-high {{ background: #db6d28; }}
        .sev-medium {{ background: #d29922; }}
        .sev-low {{ background: #58a6ff; }}
        .sev-info {{ background: #8b949e; }}
        
        /* Vulnerability List */
        .vuln-item {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 12px; border-left: 4px solid; }}
        .vuln-item.sev-CRITICAL {{ border-left-color: #f85149; }}
        .vuln-item.sev-HIGH {{ border-left-color: #db6d28; }}
        .vuln-item.sev-MEDIUM {{ border-left-color: #d29922; }}
        .vuln-item.sev-LOW {{ border-left-color: #58a6ff; }}
        .vuln-item.sev-INFO {{ border-left-color: #8b949e; }}
        .vuln-title {{ font-weight: bold; font-size: 1.05em; color: #c9d1d9; }}
        .vuln-badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.75em; font-weight: bold; margin-left: 8px; }}
        .badge-CRITICAL {{ background: rgba(248,81,73,0.2); color: #f85149; }}
        .badge-HIGH {{ background: rgba(219,109,40,0.2); color: #db6d28; }}
        .badge-MEDIUM {{ background: rgba(210,153,34,0.2); color: #d29922; }}
        .badge-LOW {{ background: rgba(88,166,255,0.2); color: #58a6ff; }}
        .badge-INFO {{ background: rgba(139,148,158,0.2); color: #8b949e; }}
        .vuln-desc {{ color: #8b949e; margin-top: 8px; font-size: 0.95em; }}
        .vuln-evidence {{ background: #0d1117; padding: 10px; border-radius: 6px; margin-top: 8px; font-family: monospace; font-size: 0.85em; color: #7ee787; word-break: break-all; }}
        .vuln-recommendation {{ color: #58a6ff; margin-top: 8px; font-size: 0.9em; }}
        
        /* Port Table */
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th {{ background: #161b22; color: #58a6ff; padding: 10px; text-align: left; font-size: 0.9em; }}
        td {{ padding: 10px; border-bottom: 1px solid #21262d; font-size: 0.9em; }}
        tr:hover td {{ background: rgba(88,166,255,0.05); }}
        
        /* Tags */
        .tag {{ display: inline-block; background: #161b22; border: 1px solid #30363d; padding: 4px 12px; border-radius: 16px; margin: 4px; font-size: 0.85em; color: #8b949e; }}
        
        /* Summary Box */
        .summary-text {{ background: #161b22; padding: 16px; border-radius: 8px; border-left: 4px solid #58a6ff; line-height: 1.8; }}
        
        /* Footer */
        .footer {{ text-align: center; padding: 30px; color: #484f58; font-size: 0.85em; border-top: 1px solid #21262d; margin-top: 30px; }}
        .footer a {{ color: #58a6ff; text-decoration: none; }}

        /* Responsive */
        @media (max-width: 768px) {{
            .header .meta {{ flex-direction: column; gap: 12px; }}
            .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        
        <!-- HEADER -->
        <div class="header">
            <h1>⚡ ZenithAI Security Report</h1>
            <p class="subtitle">Autonomous AI-Powered Vulnerability Assessment</p>
            <div class="target">🎯 {self._escape(target)}</div>
            <span class="risk-badge risk-{risk_rating}">{risk_rating} RISK</span>
            <div class="meta">
                <div class="meta-item">
                    <div class="label">AI Model</div>
                    <div class="value">🧠 {self._escape(model)}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Duration</div>
                    <div class="value">⏱️ {self._escape(str(duration))}</div>
                </div>
                <div class="meta-item">
                    <div class="label">AI Iterations</div>
                    <div class="value">🔄 {iterations}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Commands</div>
                    <div class="value">💻 {commands}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Generated</div>
                    <div class="value">📅 {datetime.now().strftime("%Y-%m-%d %H:%M")}</div>
                </div>
            </div>
        </div>

        <!-- VULNERABILITY STATS -->
        <div class="card">
            <h2><span class="icon">📊</span> Vulnerability Overview</h2>
            <div class="stats-grid">
                <div class="stat-box stat-total">
                    <div class="number">{total_vulns}</div>
                    <div class="label">Total Findings</div>
                </div>
                <div class="stat-box stat-critical">
                    <div class="number">{sev_counts['CRITICAL']}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-box stat-high">
                    <div class="number">{sev_counts['HIGH']}</div>
                    <div class="label">High</div>
                </div>
                <div class="stat-box stat-medium">
                    <div class="number">{sev_counts['MEDIUM']}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat-box stat-low">
                    <div class="number">{sev_counts['LOW']}</div>
                    <div class="label">Low</div>
                </div>
                <div class="stat-box stat-info">
                    <div class="number">{sev_counts['INFO']}</div>
                    <div class="label">Info</div>
                </div>
            </div>
            {self._severity_bar(sev_counts, total_vulns)}
        </div>

        <!-- EXECUTIVE SUMMARY -->
        <div class="card">
            <h2><span class="icon">📋</span> Executive Summary</h2>
            <div class="summary-text">{self._escape(executive_summary)}</div>
        </div>

        <!-- VULNERABILITIES -->
        <div class="card">
            <h2><span class="icon">🔓</span> Vulnerabilities ({total_vulns})</h2>
            {self._vuln_list(vulns, ai_findings)}
        </div>

        <!-- OPEN PORTS -->
        {self._ports_section(ports)}

        <!-- TECHNOLOGIES -->
        {self._tech_section(techs)}

        <!-- DIRECTORIES -->
        {self._dirs_section(dirs)}

        <!-- SUBDOMAINS -->
        {self._subdomains_section(subdomains)}

        <!-- CREDENTIALS -->
        {self._credentials_section(credentials)}

        <!-- RECOMMENDATIONS -->
        {self._recommendations_section(recommendations)}

        <!-- FOOTER -->
        <div class="footer">
            <p>Generated by <strong>ZenithAI Security Scanner v2.0</strong></p>
            <p><a href="https://github.com/jasiritech/ZenithAI">github.com/jasiritech/ZenithAI</a></p>
            <p style="margin-top:8px;">⚠️ This report is for authorized security testing only.</p>
        </div>

    </div>
</body>
</html>"""

        # Write file
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else ".", exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)

        return output_file

    def _escape(self, text):
        """HTML escape."""
        if not isinstance(text, str):
            text = str(text)
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    def _severity_bar(self, counts, total):
        """Generate severity distribution bar."""
        if total == 0:
            return '<p style="color:#8b949e;">No vulnerabilities detected.</p>'
        
        bar = '<div class="severity-bar">'
        for sev, cls in [("CRITICAL", "critical"), ("HIGH", "high"), ("MEDIUM", "medium"), ("LOW", "low"), ("INFO", "info")]:
            pct = (counts[sev] / total * 100) if total > 0 else 0
            if pct > 0:
                bar += f'<div class="sev-segment sev-{cls}" style="width:{pct}%" title="{sev}: {counts[sev]}"></div>'
        bar += '</div>'
        return bar

    def _vuln_list(self, vulns, ai_findings):
        """Generate vulnerability list HTML."""
        if not vulns and not ai_findings:
            return '<p style="color:#8b949e;">No vulnerabilities were automatically detected. Check the AI analysis for manual findings.</p>'
        
        # Merge KB vulns and AI findings
        all_vulns = list(vulns)
        seen_titles = {v.get("title", "").lower() for v in all_vulns}
        
        for f in ai_findings:
            if isinstance(f, dict) and f.get("title", "").lower() not in seen_titles:
                all_vulns.append(f)
                seen_titles.add(f.get("title", "").lower())
        
        # Sort by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        all_vulns.sort(key=lambda v: sev_order.get(v.get("severity", "INFO").upper(), 5))
        
        html = ""
        for v in all_vulns:
            sev = v.get("severity", "INFO").upper()
            title = self._escape(v.get("title", "Unknown"))
            desc = self._escape(v.get("description", ""))
            evidence = self._escape(v.get("evidence", ""))
            rec = self._escape(v.get("recommendation", ""))
            
            html += f'''<div class="vuln-item sev-{sev}">
                <div class="vuln-title">{title} <span class="vuln-badge badge-{sev}">{sev}</span></div>
                {"<div class='vuln-desc'>" + desc + "</div>" if desc else ""}
                {"<div class='vuln-evidence'>" + evidence + "</div>" if evidence else ""}
                {"<div class='vuln-recommendation'>💡 " + rec + "</div>" if rec else ""}
            </div>'''
        
        return html

    def _ports_section(self, ports):
        """Generate ports section."""
        if not ports:
            return ""
        
        rows = ""
        for p in ports:
            rows += f"""<tr>
                <td>{p.get('port', '')}</td>
                <td>{self._escape(p.get('protocol', 'tcp'))}</td>
                <td>{self._escape(p.get('service', ''))}</td>
                <td>{self._escape(p.get('version', ''))}</td>
            </tr>"""
        
        return f"""<div class="card">
            <h2><span class="icon">🔌</span> Open Ports ({len(ports)})</h2>
            <table>
                <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr>
                {rows}
            </table>
        </div>"""

    def _tech_section(self, techs):
        """Generate technologies section."""
        if not techs:
            return ""
        tags = "".join(f'<span class="tag">{self._escape(t)}</span>' for t in techs)
        return f"""<div class="card">
            <h2><span class="icon">🛠️</span> Technologies Detected ({len(techs)})</h2>
            <div>{tags}</div>
        </div>"""

    def _dirs_section(self, dirs):
        """Generate directories section."""
        if not dirs:
            return ""
        items = "".join(f'<span class="tag" style="font-family:monospace;">{self._escape(d)}</span>' for d in dirs[:50])
        extra = f'<p style="color:#8b949e;margin-top:12px;">...and {len(dirs)-50} more</p>' if len(dirs) > 50 else ""
        return f"""<div class="card">
            <h2><span class="icon">📁</span> Discovered Directories ({len(dirs)})</h2>
            <div>{items}</div>{extra}
        </div>"""

    def _subdomains_section(self, subdomains):
        """Generate subdomains section."""
        if not subdomains:
            return ""
        items = "".join(f'<span class="tag">{self._escape(s)}</span>' for s in subdomains[:50])
        return f"""<div class="card">
            <h2><span class="icon">🌐</span> Subdomains ({len(subdomains)})</h2>
            <div>{items}</div>
        </div>"""

    def _credentials_section(self, creds):
        """Generate credentials section."""
        if not creds:
            return ""
        rows = ""
        for c in creds:
            rows += f"""<tr>
                <td>{self._escape(c.get('username', ''))}</td>
                <td style="color:#f85149;">{self._escape(c.get('password', ''))}</td>
                <td>{self._escape(c.get('source', ''))}</td>
            </tr>"""
        return f"""<div class="card">
            <h2><span class="icon">🔑</span> Discovered Credentials ({len(creds)})</h2>
            <table>
                <tr><th>Username</th><th>Password</th><th>Source</th></tr>
                {rows}
            </table>
        </div>"""

    def _recommendations_section(self, recs):
        """Generate recommendations section."""
        if not recs:
            return ""
        items = ""
        for i, r in enumerate(recs, 1):
            if isinstance(r, str):
                items += f'<div style="padding:8px 0;border-bottom:1px solid #21262d;"><strong>{i}.</strong> {self._escape(r)}</div>'
            elif isinstance(r, dict):
                items += f'<div style="padding:8px 0;border-bottom:1px solid #21262d;"><strong>{i}.</strong> {self._escape(r.get("title", r.get("recommendation", str(r))))}</div>'
        return f"""<div class="card">
            <h2><span class="icon">💡</span> Recommendations</h2>
            {items}
        </div>"""
