"""
Zenith Open Redirect Scanner Module - Unvalidated Redirects and Forwards Detection.
Tests query parameters across endpoints for open redirect vulnerabilities.
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import re
from typing import Dict, List, Optional


class RedirectScanner:
    """Automated Open Redirect scanner."""

    REDIRECT_PARAMS = [
        'url', 'next', 'target', 'dest', 'destination', 'redirect',
        'redirect_url', 'redirect_uri', 'r', 'return', 'return_url',
        'go', 'goto', 'out', 'link', 'to', 'view', 'continue', 'callback'
    ]

    PAYLOADS = [
        "https://evil-attacker.com",
        "//evil-attacker.com",
        "/\\evil-attacker.com",
        "https:evil-attacker.com",
        "https://evil-attacker.com%23",
        "https://evil-attacker.com?param=test"
    ]

    def __init__(self, target: str, cookies: str = None, headers: dict = None):
        clean = re.sub(r'^https?://', '', target).split('/')[0]
        self.host = clean
        self.base_url = f"https://{clean}" if not target.startswith("http") else target.rstrip('/')
        self.cookies = cookies
        self.custom_headers = headers or {}
        self.findings: List[Dict] = []

    def scan(self) -> List[Dict]:
        """Run open redirect checks."""
        self.findings = []
        endpoints = [
            "/login",
            "/logout",
            "/signin",
            "/redirect",
            "/out",
            "/go",
            "/auth",
            "/callback"
        ]

        # No-redirect handler to capture 30x Location header
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def http_error_302(self, req, fp, code, msg, headers):
                return fp
            http_error_301 = http_error_302
            http_error_303 = http_error_302
            http_error_307 = http_error_302
            http_error_308 = http_error_302

        ctx = ssl._create_unverified_context()
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            NoRedirectHandler()
        )

        for ep in endpoints:
            for param in self.REDIRECT_PARAMS:
                for payload in self.PAYLOADS:
                    query = urllib.parse.urlencode({param: payload})
                    test_url = f"{self.base_url}{ep}?{query}"

                    req = urllib.request.Request(
                        test_url,
                        headers={
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ZenithAI-Redirect/2.0",
                            **self.custom_headers
                        }
                    )
                    if self.cookies:
                        req.add_header("Cookie", self.cookies)

                    try:
                        resp = opener.open(req, timeout=6)
                        location = resp.headers.get("Location", "")
                        
                        if location and ("evil-attacker.com" in location):
                            self.findings.append({
                                "title": f"Open Redirect Vulnerability: {ep} (?{param}=)",
                                "severity": "MEDIUM",
                                "type": "OPEN_REDIRECT",
                                "detail": f"Parameter '{param}' on endpoint '{ep}' redirects to untrusted domain: {location}",
                                "evidence": f"URL: {test_url} -> Location: {location}",
                                "endpoint": test_url
                            })
                            break
                    except Exception:
                        continue

        return self.findings