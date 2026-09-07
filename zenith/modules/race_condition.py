"""
Zenith Race Condition Tester - Concurrency Vulnerability Detection
Race conditions = double-spend, coupon abuse, account privilege escalation.

Tests for:
1. TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities
2. Double-spend / duplicate transactions
3. Coupon/voucher reuse
4. Parallel account operations (follow, like, vote manipulation)
5. Inventory/stock bypass
6. Password reset race conditions
7. Rate limit bypass via concurrent requests

Usage from AI scripts:
    from zenith.modules.race_condition import RaceConditionTester
    tester = RaceConditionTester("target.com")
    results = tester.scan()
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import json
import re
import time
import hashlib
import threading
import concurrent.futures
from collections import defaultdict


class RaceConditionTester:
    """Automated Race Condition vulnerability tester."""

    # Number of concurrent requests for race testing
    DEFAULT_THREADS = 20
    BURST_THREADS = 50

    # Endpoints commonly vulnerable to race conditions
    RACE_ENDPOINTS = [
        # Financial / transactions
        {'path': '/api/transfer', 'method': 'POST', 'category': 'financial',
         'data': {'amount': '1', 'to': 'test_account'},
         'description': 'Money transfer - double spend'},
        {'path': '/api/payment', 'method': 'POST', 'category': 'financial',
         'data': {'amount': '1'},
         'description': 'Payment processing - double charge'},
        {'path': '/api/withdraw', 'method': 'POST', 'category': 'financial',
         'data': {'amount': '1'},
         'description': 'Withdrawal - overdraft'},

        # Coupon/voucher
        {'path': '/api/coupon/apply', 'method': 'POST', 'category': 'coupon',
         'data': {'code': 'TEST'},
         'description': 'Coupon application - multiple use'},
        {'path': '/api/redeem', 'method': 'POST', 'category': 'coupon',
         'data': {'code': 'PROMO'},
         'description': 'Voucher redemption - reuse'},
        {'path': '/api/discount/apply', 'method': 'POST', 'category': 'coupon',
         'data': {'discount_code': 'SAVE10'},
         'description': 'Discount code - multiple application'},

        # Social actions
        {'path': '/api/follow', 'method': 'POST', 'category': 'social',
         'data': {'user_id': '1'},
         'description': 'Follow action - duplicate follow'},
        {'path': '/api/like', 'method': 'POST', 'category': 'social',
         'data': {'post_id': '1'},
         'description': 'Like action - multiple likes'},
        {'path': '/api/vote', 'method': 'POST', 'category': 'social',
         'data': {'option_id': '1'},
         'description': 'Vote - multiple votes'},

        # Account operations
        {'path': '/api/register', 'method': 'POST', 'category': 'account',
         'data': {'email': 'race_test@test.com', 'password': 'test123'},
         'description': 'Registration - duplicate accounts'},
        {'path': '/api/invite', 'method': 'POST', 'category': 'account',
         'data': {'email': 'invite@test.com'},
         'description': 'Invite - multiple invites (referral abuse)'},

        # Inventory
        {'path': '/api/cart/add', 'method': 'POST', 'category': 'inventory',
         'data': {'product_id': '1', 'quantity': '1'},
         'description': 'Add to cart - inventory bypass'},
        {'path': '/api/checkout', 'method': 'POST', 'category': 'inventory',
         'data': {},
         'description': 'Checkout - overselling'},
        {'path': '/api/claim', 'method': 'POST', 'category': 'inventory',
         'data': {'item_id': '1'},
         'description': 'Claim item - limited stock bypass'},

        # Auth / Password reset
        {'path': '/api/password/reset', 'method': 'POST', 'category': 'auth',
         'data': {'email': 'test@test.com'},
         'description': 'Password reset - token collision'},
        {'path': '/api/otp/verify', 'method': 'POST', 'category': 'auth',
         'data': {'otp': '000000'},
         'description': 'OTP verification - brute force bypass'},
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
        self._lock = threading.Lock()

    def _request(self, url, method="GET", data=None):
        """Make HTTP request with timing."""
        start = time.time()
        try:
            hdrs = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json, */*',
            }
            hdrs.update(self.custom_headers)
            if self.cookies:
                hdrs['Cookie'] = self.cookies

            if data and isinstance(data, dict):
                data = json.dumps(data).encode()
                hdrs['Content-Type'] = 'application/json'
            elif data and isinstance(data, str):
                data = data.encode()
                hdrs['Content-Type'] = 'application/x-www-form-urlencoded'

            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            resp = urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout)
            body = resp.read(100000).decode(errors='ignore')
            elapsed = time.time() - start

            with self._lock:
                self.tested += 1

            return {
                'status': resp.status,
                'body': body,
                'headers': dict(resp.getheaders()),
                'length': len(body),
                'time': elapsed,
                'hash': hashlib.md5(body.encode()).hexdigest()[:12],
            }
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read(10000).decode(errors='ignore')
            except:
                pass
            elapsed = time.time() - start
            with self._lock:
                self.tested += 1
            return {
                'status': e.code,
                'body': body,
                'headers': {},
                'length': len(body),
                'time': elapsed,
                'hash': hashlib.md5(body.encode()).hexdigest()[:12],
            }
        except Exception as e:
            elapsed = time.time() - start
            with self._lock:
                self.tested += 1
            return {
                'status': 0,
                'body': str(e),
                'headers': {},
                'length': 0,
                'time': elapsed,
                'hash': '',
            }

    def _discover_race_endpoints(self):
        """Discover endpoints that might be vulnerable to race conditions."""
        found = []
        print(f"  [*] Discovering endpoints...")

        # Check which predefined endpoints exist
        for endpoint in self.RACE_ENDPOINTS:
            url = f"{self.base_url}{endpoint['path']}"
            resp = self._request(url, method="OPTIONS")

            # Also try GET to see if endpoint exists
            if resp['status'] == 0 or resp['status'] == 404:
                resp = self._request(url)

            if resp['status'] not in (0, 404):
                found.append(endpoint)
                print(f"  [+] Found: {endpoint['path']} [{resp['status']}] - {endpoint['description']}")

        # Crawl for additional endpoints
        resp = self._request(self.base_url)
        if resp['body']:
            # Find form actions (POST endpoints)
            forms = re.findall(r'<form[^>]*action=["\']([^"\']+)["\'][^>]*method=["\']post', resp['body'], re.I)
            for action in forms:
                if action.startswith('/'):
                    # Look for inputs to determine what data to send
                    inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)', resp['body'])
                    data = {inp: 'test' for inp in inputs[:5]}
                    found.append({
                        'path': action,
                        'method': 'POST',
                        'category': 'form',
                        'data': data,
                        'description': f'Form submission: {action}',
                    })

            # Find API endpoints in JavaScript
            api_endpoints = re.findall(r'["\']/(api/[^"\']+)["\']', resp['body'])
            for ep in api_endpoints:
                ep = '/' + ep
                if any(word in ep.lower() for word in ['create', 'add', 'submit', 'send', 'post', 'apply', 'claim']):
                    found.append({
                        'path': ep,
                        'method': 'POST',
                        'category': 'api',
                        'data': {},
                        'description': f'API: {ep}',
                    })

        return found

    def _fire_concurrent_requests(self, url, method, data, num_threads):
        """Fire N concurrent identical requests and collect all responses."""
        results = []
        barrier = threading.Barrier(num_threads, timeout=10)

        def _worker(_id):
            """Worker that waits at barrier then fires request simultaneously."""
            try:
                barrier.wait()  # All threads release at the same instant
            except threading.BrokenBarrierError:
                pass
            resp = self._request(url, method=method, data=data)
            resp['thread_id'] = _id
            return resp

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(_worker, i) for i in range(num_threads)]
            for future in concurrent.futures.as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    results.append({'status': 0, 'body': str(e), 'time': 0, 'hash': ''})

        return results

    def _analyze_race_results(self, results, endpoint):
        """Analyze concurrent request results for race condition indicators."""
        findings = []

        success_responses = [r for r in results if r.get('status') in (200, 201, 204)]
        error_responses = [r for r in results if r.get('status') in (400, 409, 429)]
        server_errors = [r for r in results if r.get('status') in (500, 502, 503)]

        total = len(results)
        success_count = len(success_responses)

        # Indicator 1: Multiple success responses where only 1 should succeed
        if success_count > 1:
            # Check if responses are actually different (not just same cached response)
            unique_hashes = set(r.get('hash', '') for r in success_responses if r.get('hash'))

            finding = {
                'type': 'RACE_CONDITION',
                'severity': 'HIGH',
                'endpoint': endpoint['path'],
                'method': endpoint['method'],
                'category': endpoint['category'],
                'success_count': success_count,
                'total_requests': total,
                'unique_responses': len(unique_hashes),
                'detail': f"Race condition: {success_count}/{total} requests succeeded "
                         f"({len(unique_hashes)} unique responses) - {endpoint['description']}",
            }

            # Upgrade severity for financial/coupon operations
            if endpoint['category'] in ('financial', 'coupon', 'inventory'):
                finding['severity'] = 'CRITICAL'
                finding['detail'] += " ⚡ FINANCIAL IMPACT"

            findings.append(finding)

        # Indicator 2: Server errors under concurrency (may indicate improper locking)
        if len(server_errors) > total * 0.3:
            findings.append({
                'type': 'RACE_SERVER_ERROR',
                'severity': 'MEDIUM',
                'endpoint': endpoint['path'],
                'category': endpoint['category'],
                'error_count': len(server_errors),
                'total_requests': total,
                'detail': f"Server errors under concurrency: {len(server_errors)}/{total} "
                         f"requests returned 5xx - possible race condition or deadlock",
            })

        # Indicator 3: No rate limiting detected
        if success_count == total and total >= 10:
            findings.append({
                'type': 'NO_RATE_LIMIT',
                'severity': 'MEDIUM',
                'endpoint': endpoint['path'],
                'success_count': success_count,
                'detail': f"No rate limiting: All {total} concurrent requests succeeded on {endpoint['path']}",
            })

        # Indicator 4: Inconsistent responses (some success, some error = timing-dependent = race)
        if 0 < success_count < total and error_responses:
            response_times = [r.get('time', 0) for r in results if r.get('time')]
            if response_times:
                avg_time = sum(response_times) / len(response_times)
                time_variance = max(response_times) - min(response_times)

                if time_variance > 0.5:  # More than 500ms variance
                    findings.append({
                        'type': 'RACE_TIMING',
                        'severity': 'MEDIUM',
                        'endpoint': endpoint['path'],
                        'detail': f"Timing-dependent behavior: {success_count} success, "
                                 f"{len(error_responses)} errors, {time_variance:.2f}s variance",
                        'avg_time': avg_time,
                        'time_variance': time_variance,
                    })

        return findings

    def _test_single_use_race(self, url, method, data, num_threads=None):
        """Test if a 'single-use' operation can be exploited via race condition.
        Sends a burst of concurrent requests and checks how many succeed."""
        threads = num_threads or self.DEFAULT_THREADS
        print(f"    → Firing {threads} concurrent {method} requests...")

        results = self._fire_concurrent_requests(url, method, data, threads)
        return results

    def _test_limit_bypass(self, endpoint):
        """Test if rate limits can be bypassed with concurrent requests."""
        url = f"{self.base_url}{endpoint['path']}"
        data = json.dumps(endpoint.get('data', {})) if endpoint.get('data') else None

        # First: establish baseline (single request)
        baseline = self._request(url, method=endpoint['method'], data=data)

        if baseline['status'] in (0, 404):
            return []

        # Fire burst
        results = self._fire_concurrent_requests(url, endpoint['method'], data, self.DEFAULT_THREADS)

        return self._analyze_race_results(results, endpoint)

    def _test_double_action(self, endpoint):
        """Test for double-action race conditions (e.g., double-spend)."""
        url = f"{self.base_url}{endpoint['path']}"
        data = json.dumps(endpoint.get('data', {})) if endpoint.get('data') else None

        # Send two waves
        # Wave 1: Small burst
        print(f"    → Wave 1: {self.DEFAULT_THREADS} requests")
        results1 = self._fire_concurrent_requests(url, endpoint['method'], data, self.DEFAULT_THREADS)

        # Short pause
        time.sleep(0.5)

        # Wave 2: Larger burst
        print(f"    → Wave 2: {self.BURST_THREADS} requests")
        results2 = self._fire_concurrent_requests(url, endpoint['method'], data, self.BURST_THREADS)

        # Analyze combined results
        all_results = results1 + results2
        findings = self._analyze_race_results(all_results, endpoint)

        # Additional analysis: compare waves
        success1 = len([r for r in results1 if r.get('status') in (200, 201, 204)])
        success2 = len([r for r in results2 if r.get('status') in (200, 201, 204)])

        if success1 > 0 and success2 > 0:
            findings.append({
                'type': 'DOUBLE_ACTION',
                'severity': 'HIGH' if endpoint['category'] in ('financial', 'coupon') else 'MEDIUM',
                'endpoint': endpoint['path'],
                'category': endpoint['category'],
                'wave1_success': success1,
                'wave2_success': success2,
                'detail': f"Double-action possible: Wave1={success1}/{self.DEFAULT_THREADS}, "
                         f"Wave2={success2}/{self.BURST_THREADS} - {endpoint['description']}",
            })

        return findings

    def scan(self):
        """Run the full race condition test suite."""
        print(f"\n{'='*60}")
        print(f"  Race Condition Tester - {self.target}")
        print(f"{'='*60}")

        all_findings = []

        # Phase 1: Discover endpoints
        print(f"\n[Phase 1] Endpoint Discovery")
        endpoints = self._discover_race_endpoints()
        print(f"  [*] Found {len(endpoints)} testable endpoints")

        if not endpoints:
            print(f"  [!] No endpoints found. Testing common paths anyway...")
            endpoints = self.RACE_ENDPOINTS[:5]

        # Phase 2: Single-use race condition testing
        print(f"\n[Phase 2] Race Condition Testing ({self.DEFAULT_THREADS} threads)")
        for endpoint in endpoints:
            url = f"{self.base_url}{endpoint['path']}"
            print(f"\n  Testing: {endpoint['method']} {endpoint['path']}")
            print(f"  Category: {endpoint['category']} - {endpoint['description']}")

            findings = self._test_limit_bypass(endpoint)
            all_findings.extend(findings)

            for f in findings:
                sev = f.get('severity', 'INFO')
                sev_icon = '🔴' if sev == 'CRITICAL' else '🟠' if sev == 'HIGH' else '🟡'
                print(f"  {sev_icon} {f['detail']}")

        # Phase 3: Double-action testing on most critical endpoints
        print(f"\n[Phase 3] Double-Action Testing (2 waves)")
        critical_categories = ('financial', 'coupon', 'inventory')
        critical_endpoints = [e for e in endpoints if e['category'] in critical_categories]

        for endpoint in critical_endpoints[:5]:
            print(f"\n  Double-action test: {endpoint['path']}")
            findings = self._test_double_action(endpoint)
            all_findings.extend(findings)

            for f in findings:
                sev_icon = '🔴' if f.get('severity') == 'CRITICAL' else '🟠'
                print(f"  {sev_icon} {f['detail']}")

        # Phase 4: Rate limit bypass check
        print(f"\n[Phase 4] Rate Limit Analysis")
        for endpoint in endpoints[:5]:
            url = f"{self.base_url}{endpoint['path']}"
            print(f"  Checking rate limit: {endpoint['path']}")

            # Send many sequential requests quickly
            success_count = 0
            for _ in range(30):
                data = json.dumps(endpoint.get('data', {})) if endpoint.get('data') else None
                resp = self._request(url, method=endpoint['method'], data=data)
                if resp['status'] in (200, 201, 204):
                    success_count += 1
                elif resp['status'] == 429:
                    break

            if success_count >= 25:
                all_findings.append({
                    'type': 'RATE_LIMIT_BYPASS',
                    'severity': 'MEDIUM',
                    'endpoint': endpoint['path'],
                    'success_count': success_count,
                    'detail': f"Weak/no rate limiting on {endpoint['path']}: "
                             f"{success_count}/30 sequential requests succeeded",
                })
                print(f"  🟡 No rate limit: {success_count}/30 requests succeeded")

        self.findings = all_findings

        # Deduplicate findings
        seen = set()
        unique_findings = []
        for f in all_findings:
            key = f"{f['type']}:{f.get('endpoint', '')}:{f.get('severity', '')}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        # Report
        print(f"\n{'='*60}")
        print(f"  RACE CONDITION TEST RESULTS")
        print(f"{'='*60}")
        print(f"  Endpoints tested: {len(endpoints)}")
        print(f"  Total requests: {self.tested}")
        print(f"  Unique findings: {len(unique_findings)}")

        if unique_findings:
            critical = [f for f in unique_findings if f.get('severity') == 'CRITICAL']
            high = [f for f in unique_findings if f.get('severity') == 'HIGH']

            for i, f in enumerate(unique_findings, 1):
                sev = f.get('severity', 'INFO')
                sev_icon = '🔴' if sev == 'CRITICAL' else '🟠' if sev == 'HIGH' else '🟡'
                print(f"\n  {sev_icon} [{sev}] Finding #{i}: {f['type']}")
                print(f"     Detail: {f.get('detail', 'N/A')}")
                if f.get('endpoint'):
                    print(f"     Endpoint: {f['endpoint']}")
                if f.get('success_count'):
                    print(f"     Success count: {f['success_count']}")

            if critical:
                print(f"\n  ⚡ {len(critical)} CRITICAL - Financial race conditions detected!")
            if high:
                print(f"  🟠 {len(high)} HIGH - Race conditions confirmed!")
        else:
            print(f"\n  ✓ No race condition vulnerabilities detected.")
            print(f"  Note: Full testing requires valid session tokens and real transaction endpoints.")

        return unique_findings


# CLI entry point
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "TARGET_DOMAIN"
    cookies = sys.argv[2] if len(sys.argv) > 2 else ""
    tester = RaceConditionTester(target, cookies=cookies)
    results = tester.scan()
    if results:
        print(f"\n⚠ TOTAL RACE CONDITION FINDINGS: {len(results)}")
        for r in results:
            print(json.dumps(r, indent=2, default=str))
