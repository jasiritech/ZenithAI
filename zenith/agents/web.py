"""
Web Agent - Browser-based security testing with Playwright (or requests fallback).

Capabilities:
  - Crawl web applications (up to configured depth)
  - Detect and enumerate forms + input fields
  - Discover API endpoints (from JS source, network intercepts, link extraction)
  - Capture JavaScript-rendered content
  - Detect authentication flows (login forms, JWT cookies, OAuth)
  - Basic form fuzzing (XSS probes, SSTI probes)
  - Screenshot capture for report evidence
"""

import re
import json
import os
import tempfile
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from zenith.agents.base_agent import BaseAgent, AgentResult


class WebAgent(BaseAgent):
    """Browser-based web surface mapping and light vulnerability testing."""

    NAME        = "web"
    DESCRIPTION = "Browser-driven crawl: forms, JS, API endpoints, screenshots, basic fuzzing"
    REQUIRES    = ["recon"]
    PROVIDES    = ["forms", "api_endpoints", "directories", "js_files"]

    # Payloads for quick probe
    _XSS_PROBE   = "<script>alert('ZENITH_XSS')</script>"
    _SSTI_PROBE  = "{{7*7}}"
    _SQLI_PROBE  = "' OR '1'='1"
    _PATH_PROBE  = "/../../../etc/passwd"

    # Common sensitive paths to always check
    _SENSITIVE_PATHS = [
        "/admin", "/administrator", "/login", "/wp-admin", "/phpmyadmin",
        "/.git/HEAD", "/.env", "/config.php", "/backup.zip", "/robots.txt",
        "/sitemap.xml", "/api", "/api/v1", "/api/v2", "/graphql",
        "/swagger.json", "/openapi.json", "/.well-known/security.txt",
        "/server-status", "/server-info", "/.DS_Store", "/web.config",
        "/readme.txt", "/readme.md", "/CHANGELOG.md",
    ]

    def run(self, target: str, max_depth: int = 2, **kwargs) -> AgentResult:
        self._start()
        self.memory.set_agent_status(self.NAME, "running")
        self._log(f"Web surface mapping → {target}", "info")

        findings: List[Dict] = []
        errors:   List[str]  = []

        # Try Playwright first; fall back to requests-based crawler
        playwright_ok = self._playwright_available()
        if playwright_ok:
            self._log("Using Playwright for browser-based testing", "info")
            data = self._playwright_crawl(target, max_depth, findings, errors)
        else:
            self._log("Playwright not available — using requests-based crawler", "warning")
            data = self._requests_crawl(target, max_depth, findings, errors)

        # Always run sensitive path probe (no browser needed)
        self._probe_sensitive_paths(target, findings, errors)

        # Directory brute-force
        dirs = self._dir_brute(target, errors)
        self._update("directories", dirs)

        # Persist
        self._update("forms",         data.get("forms", []))
        self._update("api_endpoints", data.get("api_endpoints", []))
        self.memory.set_agent_status(self.NAME, "done")
        self.memory.store_agent_result(self.NAME, data)
        self._emit("web_surface_mapped", data)

        return AgentResult(
            agent_name = self.NAME,
            status     = "success" if not errors else "partial",
            findings   = findings,
            data       = data,
            errors     = errors,
            duration   = self._elapsed(),
            message    = (
                f"Web mapping done: {len(data.get('forms', []))} forms, "
                f"{len(data.get('api_endpoints', []))} API endpoints, "
                f"{len(dirs)} dirs found"
            ),
        )

    # ──────────────────────────────────────────────
    # Playwright path
    # ──────────────────────────────────────────────

    def _playwright_available(self) -> bool:
        try:
            import importlib
            return importlib.util.find_spec("playwright") is not None
        except Exception:
            return False

    def _playwright_crawl(
        self, target: str, max_depth: int,
        findings: List, errors: List,
    ) -> Dict:
        """Full Playwright crawl with request interception."""
        forms: List[Dict]          = []
        api_endpoints: List[str]   = []
        js_files: List[str]        = []
        screenshots: List[str]     = []
        visited: Set[str]          = set()
        to_visit: List[str]        = [target]
        base_domain                = urlparse(target).netloc

        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
                ctx     = browser.new_context(
                    user_agent="Mozilla/5.0 (compatible; SecurityScanner/2.0)",
                    ignore_https_errors=True,
                )
                page = ctx.new_page()

                # Intercept all network requests to capture API endpoints
                def _on_request(req):
                    url = req.url
                    if any(kw in url for kw in ["/api/", "/graphql", "/rest/", "/v1/", "/v2/"]):
                        ep = f"{req.method} {url}"
                        if ep not in api_endpoints:
                            api_endpoints.append(ep)
                page.on("request", _on_request)

                depth = 0
                while to_visit and depth <= max_depth:
                    next_wave = []
                    for url in to_visit[:5]:   # cap per-depth crawl to 5 URLs
                        if url in visited:
                            continue
                        visited.add(url)
                        try:
                            page.goto(url, timeout=15000, wait_until="domcontentloaded")
                        except Exception as e:
                            errors.append(f"Playwright nav failed {url}: {e}")
                            continue

                        # Screenshot first page
                        if not screenshots:
                            shot_path = os.path.join(
                                tempfile.gettempdir(),
                                f"zenith_shot_{len(screenshots)}.png"
                            )
                            try:
                                page.screenshot(path=shot_path, full_page=True)
                                screenshots.append(shot_path)
                                self._update("screenshot_paths",
                                             [{"url": url, "path": shot_path}])
                            except Exception:
                                pass

                        # Extract forms
                        try:
                            form_data = page.evaluate("""() => {
                                return Array.from(document.querySelectorAll('form')).map(f => ({
                                    action: f.action || window.location.href,
                                    method: f.method || 'GET',
                                    params: Array.from(f.querySelectorAll('input,select,textarea'))
                                              .map(i => ({name: i.name, type: i.type || 'text'}))
                                              .filter(i => i.name)
                                }));
                            }""")
                            for form in form_data or []:
                                if form not in forms:
                                    forms.append(form)
                        except Exception:
                            pass

                        # Extract JS files
                        try:
                            js = page.evaluate("""() => {
                                return Array.from(document.querySelectorAll('script[src]'))
                                           .map(s => s.src);
                            }""")
                            for j in (js or []):
                                if j not in js_files:
                                    js_files.append(j)
                        except Exception:
                            pass

                        # Collect links for next depth
                        try:
                            hrefs = page.evaluate("""() => {
                                return Array.from(document.querySelectorAll('a[href]'))
                                           .map(a => a.href);
                            }""")
                            for href in (hrefs or []):
                                if urlparse(href).netloc == base_domain and href not in visited:
                                    next_wave.append(href)
                        except Exception:
                            pass

                    to_visit = next_wave
                    depth += 1

                browser.close()

        except Exception as exc:
            errors.append(f"Playwright error: {exc}")

        # Check for login forms
        for form in forms:
            params  = [p.get("name", "").lower() for p in form.get("params", [])]
            is_auth = any(kw in params for kw in ["password", "passwd", "pass", "pwd", "token"])
            if is_auth:
                findings.append({
                    "title":       "Authentication Form Detected",
                    "severity":    "INFO",
                    "description": f"Login form at {form.get('action')} — target for brute force/bypass",
                    "evidence":    f"Params: {params}",
                })

        self._write("forms",         forms)
        self._write("api_endpoints", api_endpoints)
        self._write("js_files",      js_files)

        if forms:
            findings.append({"title": f"Found {len(forms)} web forms",
                              "severity": "INFO", "description": str(forms[:3])})
        if api_endpoints:
            findings.append({"title": f"Discovered {len(api_endpoints)} API endpoints",
                              "severity": "INFO", "description": str(api_endpoints[:5])})

        return {
            "forms": forms, "api_endpoints": api_endpoints,
            "js_files": js_files[:20], "screenshots": screenshots,
        }

    # ──────────────────────────────────────────────
    # Requests-based fallback crawler
    # ──────────────────────────────────────────────

    def _requests_crawl(
        self, target: str, max_depth: int,
        findings: List, errors: List,
    ) -> Dict:
        """Pure-requests HTML crawler with regex parsing."""
        import urllib.request
        import urllib.error
        import html

        forms:         List[Dict] = []
        api_endpoints: List[str]  = []
        visited:       Set[str]   = set()
        to_visit:      List[str]  = [target]
        base_domain    = urlparse(target).netloc

        depth = 0
        while to_visit and depth <= max_depth:
            next_wave = []
            for url in to_visit[:8]:
                if url in visited:
                    continue
                visited.add(url)

                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 SecurityScanner/2.0"})
                    with urllib.request.urlopen(req, timeout=10) as r:
                        body = r.read().decode("utf-8", errors="ignore")
                except Exception as e:
                    errors.append(f"Fetch failed {url}: {e}")
                    continue

                # Forms
                for fm in re.finditer(r'<form[^>]*>(.*?)</form>', body, re.DOTALL | re.IGNORECASE):
                    form_html = fm.group()
                    action_m  = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
                    method_m  = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
                    params    = re.findall(r'name=["\']([^"\']+)["\']', form_html, re.I)
                    form = {
                        "action": urljoin(url, action_m.group(1)) if action_m else url,
                        "method": (method_m.group(1) if method_m else "GET").upper(),
                        "params": [{"name": p} for p in params],
                    }
                    if form not in forms:
                        forms.append(form)

                # API links
                for ep in re.findall(r'["\'/](api|graphql|rest|v[12])/[^\s"\'<>]+', body, re.I):
                    full = urljoin(url, "/" + ep)
                    if full not in api_endpoints:
                        api_endpoints.append(full)

                # Links for next depth
                for href in re.findall(r'href=["\']([^"\']+)["\']', body, re.I):
                    full = urljoin(url, href)
                    if urlparse(full).netloc == base_domain and full not in visited:
                        next_wave.append(full)

            to_visit = next_wave
            depth += 1

        self._write("forms", forms)
        self._write("api_endpoints", api_endpoints)

        return {"forms": forms, "api_endpoints": api_endpoints, "js_files": [], "screenshots": []}

    # ──────────────────────────────────────────────
    # Sensitive path probing
    # ──────────────────────────────────────────────

    def _probe_sensitive_paths(self, target: str, findings: List, errors: List) -> None:
        """HTTP probe all sensitive paths and flag exposures."""
        base = target.rstrip("/")
        for path in self._SENSITIVE_PATHS:
            url = base + path
            out = self._output(
                f"curl -s -o /dev/null -w '%{{http_code}} %{{url_effective}}' "
                f"--max-time 8 '{url}' 2>/dev/null",
                timeout=12,
            )
            parts = out.strip().split()
            if not parts:
                continue
            code = parts[0]
            if code in ("200", "301", "302", "403"):
                severity = "CRITICAL" if path in ("/.env", "/.git/HEAD", "/backup.zip",
                                                    "/config.php") else (
                            "HIGH"   if path in ("/admin", "/administrator", "/wp-admin",
                                                   "/phpmyadmin") else "INFO")
                finding = {
                    "title":       f"Sensitive Path Accessible: {path}",
                    "severity":    severity,
                    "description": f"HTTP {code} returned for {url}",
                    "evidence":    f"URL: {url}  HTTP Status: {code}",
                    "url":         url,
                }
                findings.append(finding)
                self._update("vulnerabilities", finding)
                if self.graph:
                    self.graph.add_vulnerability(
                        finding["title"], severity,
                        finding["description"], evidence=finding["evidence"], url=url,
                    )
                self._emit("vulnerability_found", finding)
                if severity in ("CRITICAL", "HIGH"):
                    self._log(f"[{severity}] {path} → HTTP {code}", "warning")

    # ──────────────────────────────────────────────
    # Directory brute-force
    # ──────────────────────────────────────────────

    def _dir_brute(self, target: str, errors: List) -> List[str]:
        """Fast directory brute-force with dirsearch or ffuf."""
        dirs: List[str] = []

        if self._tool_exists("dirsearch"):
            out = self._output(
                f"dirsearch -u {target} -x 404,403 -q --format plain -t 20 2>/dev/null",
                timeout=120,
            )
            for line in out.splitlines():
                m = re.search(r'(https?://\S+)', line)
                if m:
                    dirs.append(m.group(1))

        elif self._tool_exists("ffuf"):
            wl = "/usr/share/seclists/Discovery/Web-Content/common.txt"
            if not os.path.exists(wl):
                wl = "/usr/share/wordlists/dirb/common.txt"
            if os.path.exists(wl):
                out = self._output(
                    f"ffuf -u {target}/FUZZ -w {wl} -mc 200,301,302 -s -t 30 2>/dev/null",
                    timeout=120,
                )
                for line in out.splitlines():
                    path = line.strip()
                    if path:
                        dirs.append(f"{target.rstrip('/')}/{path}")

        return dirs[:200]

    def _tool_exists(self, name: str) -> bool:
        out = self._output(f"which {name} 2>/dev/null", timeout=5)
        return bool(out.strip())
