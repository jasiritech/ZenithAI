"""
Zenith Scan Profiles - Pre-configured scan templates.
Quick, Full, Stealth, Web-Only, Network-Only, and Custom profiles.
"""


# Each profile defines default settings that override the scanner behavior
PROFILES = {
    "quick": {
        "name": "⚡ Quick Scan",
        "description": "Fast surface-level scan. Good for a first look.",
        "max_iterations": 30,
        "goal_template": (
            "Perform a QUICK security scan on {target}. "
            "Run a fast nmap scan (-F flag), check HTTP headers, "
            "and run a basic nuclei scan. Keep it under 15 commands total. "
            "Focus on the most obvious vulnerabilities only."
        ),
        "phases": ["recon", "scan", "report"],
        "timeout_per_command": 120,
    },
    "full": {
        "name": "🔥 Full Scan",
        "description": "Comprehensive scan. Thorough and deep - takes longer.",
        "max_iterations": 150,
        "goal_template": (
            "Perform a COMPREHENSIVE security assessment on {target}. "
            "Do thorough reconnaissance: full port scan, subdomain enumeration, "
            "technology fingerprinting. Then scan for all vulnerabilities: "
            "SQL injection, XSS, directory traversal, SSRF, misconfigurations, "
            "default credentials, exposed APIs, sensitive files. "
            "Try to exploit any found vulnerabilities. Be extremely thorough."
        ),
        "phases": ["recon", "scan", "exploit", "post_exploit", "report"],
        "timeout_per_command": 600,
    },
    "stealth": {
        "name": "🥷 Stealth Scan",
        "description": "Low and slow - minimize detection by IDS/WAF.",
        "max_iterations": 80,
        "goal_template": (
            "Perform a STEALTH security scan on {target}. "
            "IMPORTANT: Minimize detection. Use slow scan rates, "
            "avoid aggressive scanning. Use nmap with -T2 timing, "
            "randomize scan order, use decoy techniques where possible. "
            "Avoid tools that generate lots of traffic like dirb or gobuster "
            "with high thread counts. Prefer manual/targeted checks. "
            "Space out requests to avoid triggering WAF/IDS."
        ),
        "phases": ["recon", "scan", "report"],
        "timeout_per_command": 300,
    },
    "web": {
        "name": "🌐 Web Application",
        "description": "Focused on web vulnerabilities (SQLi, XSS, LFI, etc.).",
        "max_iterations": 100,
        "goal_template": (
            "Perform a WEB APPLICATION security scan on {target}. "
            "Focus exclusively on web vulnerabilities: "
            "1) Fingerprint the web stack (server, CMS, framework) "
            "2) Crawl and enumerate directories/endpoints "
            "3) Test for SQL injection on all parameters "
            "4) Test for XSS (reflected and stored) "
            "5) Test for LFI/RFI/path traversal "
            "6) Test for SSRF "
            "7) Check for insecure headers, CORS misconfig "
            "8) Check for exposed admin panels, backup files "
            "9) Test authentication and session management "
            "10) Check for API vulnerabilities "
            "Use tools like nikto, sqlmap, nuclei with web templates."
        ),
        "phases": ["recon", "scan", "exploit", "report"],
        "timeout_per_command": 300,
    },
    "network": {
        "name": "🔌 Network Scan",
        "description": "Focused on network-level vulnerabilities and services.",
        "max_iterations": 80,
        "goal_template": (
            "Perform a NETWORK security scan on {target}. "
            "Focus on network-level vulnerabilities: "
            "1) Full port scan (all 65535 ports) with service detection "
            "2) OS fingerprinting "
            "3) Check for default credentials on all services "
            "4) Test SSH, FTP, SMB, RDP, MySQL, etc. for weaknesses "
            "5) Check for known CVEs on detected service versions "
            "6) Test for DNS zone transfers "
            "7) Check SNMP, NTP, and other UDP services "
            "8) Look for misconfigurations in network services "
            "Do NOT focus on web application attacks."
        ),
        "phases": ["recon", "scan", "exploit", "report"],
        "timeout_per_command": 600,
    },
    "api": {
        "name": "🔗 API Testing",
        "description": "Focused on REST/GraphQL API security testing.",
        "max_iterations": 80,
        "goal_template": (
            "Perform an API security assessment on {target}. "
            "Focus on API-specific vulnerabilities: "
            "1) Discover API endpoints (check /api, /v1, /graphql, swagger, openapi) "
            "2) Test for broken authentication "
            "3) Test for BOLA/IDOR vulnerabilities "
            "4) Test for mass assignment "
            "5) Check rate limiting "
            "6) Test for injection in API parameters "
            "7) Check for sensitive data exposure in responses "
            "8) Test GraphQL introspection if applicable "
            "9) Check CORS policy "
            "10) Test for API key/token leaks"
        ),
        "phases": ["recon", "scan", "exploit", "report"],
        "timeout_per_command": 300,
    },
    "recon-only": {
        "name": "🔍 Recon Only",
        "description": "Reconnaissance only - no active scanning or exploitation.",
        "max_iterations": 50,
        "goal_template": (
            "Perform PASSIVE and ACTIVE RECONNAISSANCE ONLY on {target}. "
            "DO NOT scan for vulnerabilities or exploit anything. "
            "Gather as much information as possible: "
            "1) DNS records, subdomains "
            "2) WHOIS information "
            "3) Port scanning and service detection "
            "4) Technology fingerprinting "
            "5) Web crawling for structure "
            "6) Check for email addresses, names "
            "7) Certificate transparency logs "
            "8) Archive.org/wayback machine data "
            "Then generate a complete recon report."
        ),
        "phases": ["recon", "report"],
        "timeout_per_command": 180,
    },
}


def get_profile(profile_name):
    """
    Get a scan profile by name.
    
    Args:
        profile_name: Profile key (quick, full, stealth, web, network, api, recon-only)
        
    Returns:
        dict or None: Profile configuration
    """
    return PROFILES.get(profile_name.lower())


def get_profile_goal(profile_name, target):
    """
    Get the goal text for a profile, with target substituted.
    
    Args:
        profile_name: Profile key
        target: Target URL/IP
        
    Returns:
        str: Goal text with target filled in
    """
    profile = get_profile(profile_name)
    if not profile:
        return None
    return profile["goal_template"].format(target=target)


def list_profiles():
    """
    List all available profiles.
    
    Returns:
        list: List of (key, name, description) tuples
    """
    return [
        (key, p["name"], p["description"])
        for key, p in PROFILES.items()
    ]
