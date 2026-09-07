"""
Zenith CORS Scanner Module - Cross-Origin Resource Sharing Misconfiguration Detection.
Tests for:
1. Reflected arbitrary Origin header
2. Null Origin acceptance
3. Subdomain / suffix bypasses
4. Credential exposure (Access-Control-Allow-Credentials: true with reflected origin)
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import re
from typing import Dict, List, Optional


class CORSScanner:
    """Automated CORS misconfiguration vulnerability scanner."""

    TEST_ORIGINS = [
        ("arbitrary_origin", "https://evil-attacker.com"),
        ("null_origin", "null"),
        ("subdomain_prefix", "https://not-target.com"),
    ]

    def __init__(self, target: str, cookies: str = None, headers: dict = None):
        self.raw_target = target
        clean = re.sub(r'^https?://', '', target).split('/')[0]
        self.host = clean
        self.base_url = f"https://{clean}" if not target.startswith("http") else target.rstrip('/')
        self.cookies = cookies
        self.custom_headers = headers or {}
        self.findings: List[Dict] = []

    def scan(self) -> List[Dict]:
        """Run all CORS vulnerability tests."""
        self.findings = []
        endpoints = [
            "/",
            "/api",
            "/api/v1",
            "/api/user",
            "/api/me",
            "/api/account",
            "/graphql"
        ]

        ctx = ssl._create_unverified_context()

        for ep in endpoints:
            test_url = f"{self.base_url}{ep}"
            for test_name, test_origin in self.TEST_ORIGINS:
                if test_name == "subdomain_prefix":
                    test_origin = f"https://{self.host}.evil-attacker.com"

                req_headers = {
                    "Origin": test_origin,
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ZenithAI-CORS/2.0",
                }
                if self.cookies:
                    req_headers["Cookie"] = self.cookies
                req_headers.update(self.custom_headers)

                try:
                    req = urllib.request.Request(test_url, headers=req_headers, method="GET")
                    with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
                        acao = resp.getheader("Access-Control-Allow-Origin")
                        acac = resp.getheader("Access-Control-Allow-Credentials")

                        if acao:
                            # Critical: reflected origin + credentials allowed
                            if (acao == test_origin or acao == "*") and str(acac).lower() == "true":
                                self.findings.append({
                                    "title": f"CORS Misconfiguration (Credentials Exposed): {ep}",
                                    "severity": "CRITICAL" if acao == test_origin else "HIGH",
                                    "type": "CORS_CREDENTIALS_EXPOSED",
                                    "detail": f"Endpoint {ep} reflects origin '{acao}' with credentials enabled.",
                                    "evidence": f"Origin: {test_origin} -> ACAO: {acao}, ACAC: {acac}",
                                    "endpoint": test_url
                                })
                                break
                            # Medium: arbitrary origin reflection without credentials
                            elif acao == test_origin and test_origin != "null":
                                self.findings.append({
                                    "title": f"Arbitrary CORS Origin Reflected: {ep}",
                                    "severity": "MEDIUM",
                                    "type": "CORS_ARBITRARY_ORIGIN",
                                    "detail": f"Endpoint {ep} reflects arbitrary origin header without validation.",
                                    "evidence": f"Origin: {test_origin} -> ACAO: {acao}",
                                    "endpoint": test_url
                                })
                                break
                            # Low/Medium: null origin accepted
                            elif acao == "null" and test_origin == "null":
                                self.findings.append({
                                    "title": f"CORS Null Origin Allowed: {ep}",
                                    "severity": "MEDIUM" if str(acac).lower() == "true" else "LOW",
                                    "type": "CORS_NULL_ORIGIN",
                                    "detail": f"Endpoint {ep} accepts Origin: null which can be exploited via sandboxed iframes.",
                                    "evidence": "Origin: null -> ACAO: null",
                                    "endpoint": test_url
                                })
                                break
                except Exception:
                    continue

        return self.findings