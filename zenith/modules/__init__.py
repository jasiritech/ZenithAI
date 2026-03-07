"""
Zenith Advanced Security Modules
Real-world attack modules used by professional pentesters and bug bounty hunters.

Available modules:
- IDORScanner: Insecure Direct Object Reference (#1 bug bounty finding)
- SSRFScanner: Server-Side Request Forgery (cloud metadata, internal services)
- JWTAttacker: JSON Web Token attacks (alg:none, weak secrets, kid injection)
- SSTIScanner: Server-Side Template Injection (Jinja2, Twig, Freemarker → RCE)
- RaceConditionTester: Concurrency attacks (double-spend, rate limit bypass)
"""

from zenith.modules.idor_scanner import IDORScanner
from zenith.modules.ssrf_scanner import SSRFScanner
from zenith.modules.jwt_attacks import JWTAttacker
from zenith.modules.ssti_scanner import SSTIScanner
from zenith.modules.race_condition import RaceConditionTester

__all__ = [
    'IDORScanner',
    'SSRFScanner',
    'JWTAttacker',
    'SSTIScanner',
    'RaceConditionTester',
]
