"""
Recon Agent - Advanced Reconnaissance Pipeline.

Pipeline:
    Domain → Subdomain discovery → Alive host detection
    → Service detection → Technology fingerprinting
    → Feed results to AttackGraph + SharedMemory

Tools used:
    amass / subfinder / assetfinder / httpx / nmap / whatweb / wafw00f
"""

import re
import json
from typing import Dict, List

from zenith.agents.base_agent import BaseAgent, AgentResult


class ReconAgent(BaseAgent):
    """Performs full reconnaissance: subdomains, IPs, ports, services, tech stack."""

    NAME        = "recon"
    DESCRIPTION = "Full recon pipeline: subdomains, ports, services, tech fingerprinting"
    REQUIRES    = []
    PROVIDES    = ["subdomains", "open_ports", "technologies", "waf_detected"]

    # ──────────────────────────────────────────────
    # Entry point
    # ──────────────────────────────────────────────

    def run(self, target: str, **kwargs) -> AgentResult:
        self._start()
        self.memory.set_agent_status(self.NAME, "running")
        self._log(f"Starting recon on {target}", "info")

        findings: List[Dict] = []
        errors:   List[str]  = []

        try:
            # 1. Extract base domain from target URL
            domain = self._extract_domain(target)
            self._log(f"Base domain: {domain}", "info")
            if self.graph:
                self.graph.add_domain(domain)

            # 2. Subdomain enumeration
            subdomains = self._discover_subdomains(domain, errors)
            for sd in subdomains:
                if self.graph:
                    self.graph.add_subdomain(sd, parent_domain=domain)
            self._update("subdomains", subdomains)
            self._write("subdomains", subdomains)
            self._emit("subdomains_found", subdomains)
            self._log(f"Found {len(subdomains)} subdomains", "success" if subdomains else "info")

            # 3. Alive host detection
            alive = self._check_alive_hosts(subdomains or [target], errors)
            self._write("alive_hosts", alive)

            # 4. Port + service scan
            ports = self._port_scan(target, errors)
            self._update("open_ports", ports)
            self._write("open_ports", ports)
            for p in ports:
                port_num = p.get("port", 0)
                svc      = p.get("service", "unknown")
                ver      = p.get("version", "")
                ip_hint  = p.get("ip", None)
                if self.graph:
                    self.graph.add_service(port_num, svc, ver, parent_ip=ip_hint)
            self._emit("ports_found", ports)

            # 5. Technology fingerprinting
            techs = self._fingerprint_tech(target, errors)
            self._update("technologies", techs)
            self._write("technologies", techs)
            self._emit("technologies_found", techs)

            # 6. WAF detection
            waf = self._detect_waf(target, errors)
            if waf:
                self._update("waf_detected", True)
                self._update("waf_type", waf)
                self._update("scan_speed", "slow")
                self._emit("waf_detected", waf)
                self._log(f"WAF detected: {waf} — enabling stealth mode", "warning")
                findings.append({"title": f"WAF Detected: {waf}", "severity": "INFO",
                                  "description": f"Web Application Firewall ({waf}) was detected. Stealth mode enabled."})
            else:
                self._update("waf_detected", False)

            # Summarise findings
            if ports:
                findings.append({"title": f"Discovered {len(ports)} open ports",
                                  "severity": "INFO", "description": str(ports[:10])})
            if subdomains:
                findings.append({"title": f"Found {len(subdomains)} subdomains",
                                  "severity": "INFO", "description": ", ".join(subdomains[:10])})
            if techs:
                findings.append({"title": "Technology stack identified",
                                  "severity": "INFO", "description": ", ".join(techs[:10])})

            self.memory.set_agent_status(self.NAME, "done")
            self.memory.store_agent_result(self.NAME, {
                "subdomains": subdomains, "ports": ports,
                "technologies": techs, "alive_hosts": alive,
            })

            return AgentResult(
                agent_name = self.NAME,
                status     = "success" if not errors else "partial",
                findings   = findings,
                data       = {"subdomains": subdomains, "ports": ports,
                              "technologies": techs, "alive": alive},
                errors     = errors,
                duration   = self._elapsed(),
                message    = (f"Recon complete: {len(ports)} ports, "
                              f"{len(subdomains)} subdomains, {len(techs)} technologies"),
            )

        except Exception as exc:
            self.memory.set_agent_status(self.NAME, "failed")
            self._log(f"Recon failed: {exc}", "error")
            return AgentResult(
                agent_name = self.NAME,
                status     = "failed",
                errors     = [str(exc)],
                duration   = self._elapsed(),
                message    = f"Recon failed: {exc}",
            )

    # ──────────────────────────────────────────────
    # Sub-tasks
    # ──────────────────────────────────────────────

    def _extract_domain(self, target: str) -> str:
        """Strip protocol and path to get the bare domain/IP."""
        domain = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
        return domain

    def _discover_subdomains(self, domain: str, errors: List) -> List[str]:
        """Try subfinder → assetfinder → fallback to DNS brute."""
        results: set = set()

        # subfinder
        if self._tool_exists("subfinder"):
            out = self._output(f"subfinder -d {domain} -silent -timeout 30", timeout=90)
            for line in out.splitlines():
                s = line.strip()
                if s and domain in s:
                    results.add(s)

        # assetfinder
        if self._tool_exists("assetfinder"):
            out = self._output(f"assetfinder --subs-only {domain}", timeout=60)
            for line in out.splitlines():
                s = line.strip()
                if s and domain in s:
                    results.add(s)

        # amass (if present and we haven't found much)
        if len(results) < 3 and self._tool_exists("amass"):
            out = self._output(
                f"amass enum -passive -d {domain} -timeout 30", timeout=120
            )
            for line in out.splitlines():
                s = line.strip()
                if s and domain in s:
                    results.add(s)

        if not results:
            # Minimal DNS-based fallback
            common = ["www", "admin", "api", "mail", "dev", "staging", "test", "vpn", "ftp"]
            for prefix in common:
                sub = f"{prefix}.{domain}"
                out = self._output(f"host {sub} 2>/dev/null", timeout=10)
                if "has address" in out or "alias" in out.lower():
                    results.add(sub)

        return sorted(results)

    def _check_alive_hosts(self, hosts: List[str], errors: List) -> List[str]:
        """Use httpx to confirm alive HTTP/HTTPS hosts."""
        if not hosts:
            return []

        if self._tool_exists("httpx"):
            host_list = "\n".join(hosts)
            out = self._output(
                f"echo '{host_list}' | httpx -silent -timeout 10 -status-code", timeout=90
            )
            alive = []
            for line in out.splitlines():
                url = line.split()[0].strip()
                if url.startswith("http"):
                    alive.append(url)
            return alive

        # Fallback: curl HEAD
        alive = []
        for host in hosts[:10]:
            out = self._output(f"curl -sI --max-time 5 http://{host} 2>&1 | head -1", timeout=10)
            if "HTTP/" in out:
                alive.append(host)
        return alive

    def _port_scan(self, target: str, errors: List) -> List[Dict]:
        """Run nmap service detection; fall back to top-100 fast scan."""
        domain = self._extract_domain(target)
        ports  = []

        # Fast top-1000 + service version
        out = self._output(
            f"nmap -sV -T4 --open -oX - {domain} 2>/dev/null", timeout=180
        )
        if out and "<port " in out:
            ports = self._parse_nmap_xml(out)

        if not ports:
            # Fallback: grep-able output
            out = self._output(f"nmap -F -T4 --open {domain} 2>/dev/null", timeout=120)
            ports = self._parse_nmap_grep(out)

        return ports

    def _fingerprint_tech(self, target: str, errors: List) -> List[str]:
        """Identify technologies via whatweb."""
        techs: List[str] = []

        if self._tool_exists("whatweb"):
            out = self._output(f"whatweb -a 1 --no-errors {target} 2>/dev/null", timeout=60)
            for item in re.findall(r'\[([^\[\]]+)\]', out):
                for tech in item.split(','):
                    tech = tech.strip()
                    if tech and len(tech) > 2 and tech not in techs:
                        techs.append(tech)

        if not techs:
            # Fallback: parse curl headers
            out = self._output(f"curl -sI --max-time 10 {target} 2>/dev/null", timeout=15)
            for line in out.splitlines():
                ll = line.lower()
                for sig, label in [("wordpress", "WordPress"), ("drupal", "Drupal"),
                                    ("joomla", "Joomla"), ("apache", "Apache"),
                                    ("nginx", "Nginx"), ("php", "PHP"), ("iis", "IIS")]:
                    if sig in ll and label not in techs:
                        techs.append(label)

        return techs[:20]

    def _detect_waf(self, target: str, errors: List):
        """Detect WAF with wafw00f or header heuristics."""
        if self._tool_exists("wafw00f"):
            out = self._output(f"wafw00f -a {target} 2>/dev/null", timeout=60)
            match = re.search(r'is behind (.+?)( \(|$)', out, re.IGNORECASE)
            if match:
                return match.group(1).strip()
            if "is not behind" in out.lower():
                return None

        # Header heuristics
        out = self._output(f"curl -sI --max-time 10 {target} 2>/dev/null", timeout=15)
        waf_headers = {
            "x-sucuri-id":      "Sucuri",
            "x-cdn":            "CDN/WAF",
            "x-firewall":       "Firewall",
            "server: cloudflare": "Cloudflare",
            "cf-ray":           "Cloudflare",
            "x-mod-security":   "ModSecurity",
            "x-shield":         "Shield",
        }
        out_lower = out.lower()
        for sig, name in waf_headers.items():
            if sig in out_lower:
                return name

        return None

    # ──────────────────────────────────────────────
    # Parsers
    # ──────────────────────────────────────────────

    def _parse_nmap_xml(self, xml: str) -> List[Dict]:
        """Minimal nmap XML parser (no external deps)."""
        ports = []
        for m in re.finditer(
            r'<port protocol="[^"]*" portid="(\d+)">'
            r'.*?<state state="([^"]*)".*?>'
            r'(?:.*?<service name="([^"]*)"(?:[^/]*/)?(?:[^>]*version="([^"]*)")?)?',
            xml, re.DOTALL
        ):
            if m.group(2) == "open":
                ports.append({
                    "port":    int(m.group(1)),
                    "service": m.group(3) or "unknown",
                    "version": m.group(4) or "",
                })
        return ports

    def _parse_nmap_grep(self, text: str) -> List[Dict]:
        """Parse nmap default output."""
        ports = []
        for line in text.splitlines():
            m = re.match(r'(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?', line)
            if m:
                ports.append({
                    "port":    int(m.group(1)),
                    "service": m.group(2),
                    "version": (m.group(3) or "").strip(),
                })
        return ports

    def _tool_exists(self, name: str) -> bool:
        """Check if a tool is on PATH."""
        out = self._output(f"which {name} 2>/dev/null", timeout=5)
        return bool(out.strip())
