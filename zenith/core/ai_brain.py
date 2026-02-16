"""
Zenith AI Brain - Multi-Provider AI Integration
Supports: Gemini (Google) and Groq (Fast & Free)
This is the brain of the tool - it thinks, plans, and decides the next action.
"""

import json
import time
from datetime import datetime

# Try to import Gemini
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    genai = None
    GEMINI_AVAILABLE = False

# Try to import Groq
try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False


class AIBrain:
    """
    AI Brain powered by Gemini or Groq for security scanning decisions.
    Thinks like a HACKER - selects tools, reads results, finds new attack paths.
    
    Providers:
    - Gemini (Google): Default, good quality
    - Groq: FAST & FREE (14,400 requests/day!) - use key starting with 'gsk_'
    """

    # Model fallback chains - tries each until one works
    # Tested & verified working as of Feb 2026
    MODEL_CHAINS = {
        "pro": [
            "gemini-2.5-pro",
            "gemini-2.5-flash",
            "gemini-1.5-flash",
            "gemini-2.0-flash",
            "gemini-2.0-flash-lite",
        ],
        "flash": [
            "gemini-2.5-flash",
            "gemini-1.5-flash",
            "gemini-2.0-flash",
            "gemini-2.0-flash-lite",
            "gemini-2.5-pro",
        ],
    }
    
    # Groq models - FAST and FREE! (Updated Feb 2026)
    # Production models with good context windows
    GROQ_MODELS = [
        "llama-3.3-70b-versatile",    # Best quality, 131k ctx, 32k output
        "llama-3.1-8b-instant",       # Fast, 131k ctx
        "qwen/qwen3-32b",             # Good alternative, 131k ctx
        "meta-llama/llama-4-scout-17b-16e-instruct",  # Llama 4! 131k ctx
    ]

    # Keep for backward compat - points to first in chain
    SUPPORTED_MODELS = {
        "pro": "gemini-2.5-pro",
        "flash": "gemini-2.5-flash",
        "groq": "llama-3.3-70b-versatile",
    }

    def __init__(self, api_key, model_choice="flash"):
        """
        Initialize AI Brain with automatic provider detection and model fallback.
        
        Args:
            api_key: API key (Gemini: AIza..., Groq: gsk_...)
            model_choice: 'pro' for deep thinking, 'flash' for speed, 'groq' for Groq
        """
        if not api_key or api_key == "":
            raise ValueError("[!] API Key is required! Please provide your API key.")
        
        self.api_key = api_key
        self.model_choice = model_choice
        self.total_tokens = 0
        self.call_count = 0
        self.consecutive_errors = 0
        self.max_consecutive_errors = 5
        self.chat_history = []
        
        # Detect provider: key format OR explicit model_choice
        # Key starting with gsk_ = always Groq
        # model_choice == 'groq' = user explicitly chose Groq
        if api_key.startswith("gsk_") or model_choice == "groq":
            self.provider = "groq"
            self._init_groq(api_key)
        else:
            self.provider = "gemini"
            self._init_gemini(api_key, model_choice)
    
    def _init_groq(self, api_key):
        """Initialize Groq provider."""
        if not GROQ_AVAILABLE:
            raise ValueError(
                "[!] Groq library not installed!\n"
                "    Run: pip install groq\n"
                "    Or: pip install -r requirements.txt"
            )
        
        self.groq_client = Groq(api_key=api_key)
        self.model = None
        self.model_name = None
        
        for model_name in self.GROQ_MODELS:
            try:
                print(f"    [*] Trying Groq model: {model_name}...")
                # Test the model
                response = self.groq_client.chat.completions.create(
                    model=model_name,
                    messages=[{"role": "user", "content": "Reply with OK"}],
                    max_tokens=10
                )
                _ = response.choices[0].message.content
                
                self.model_name = model_name
                print(f"    [✓] AI Brain initialized: Groq/{model_name}")
                print(f"    [💡] Groq FREE tier: 30 req/min, 14,400 req/day!")
                break
            except Exception as e:
                err = str(e)
                print(f"    [!] Groq model {model_name} failed: {err[:80]}")
                continue
        
        if self.model_name is None:
            raise ValueError(
                "[!] No working Groq model found!\n"
                "    Get your FREE API key at: https://console.groq.com/keys"
            )
    
    def _init_gemini(self, api_key, model_choice):
        """Initialize Gemini provider."""
        if not GEMINI_AVAILABLE:
            # Only fall back to Groq if the API key is actually a Groq key
            if GROQ_AVAILABLE and api_key.startswith("gsk_"):
                print("    [!] google-generativeai not installed, falling back to Groq...")
                self.provider = "groq"
                self._init_groq(api_key)
                return
            
            # Gemini key but no Gemini library - tell user exactly what to do
            raise ValueError(
                "[!] google-generativeai library not installed!\n"
                "    Your Gemini API key needs this library.\n\n"
                "    Fix: Run this command on your terminal:\n"
                "      pip install --break-system-packages google-generativeai\n\n"
                "    OR switch to Groq (FREE, no extra install needed):\n"
                "      Get key at: https://console.groq.com/keys\n"
                "      Then choose [2] Groq when starting ZenithAI"
            )
        genai.configure(api_key=api_key)
        
        # Try models in the fallback chain until one works
        chain = self.MODEL_CHAINS.get(model_choice, self.MODEL_CHAINS["flash"])
        self.model = None
        self.model_name = None
        
        for model_name in chain:
            try:
                print(f"    [*] Trying model: {model_name}...")
                candidate = genai.GenerativeModel(
                    model_name=model_name,
                    generation_config={
                        "temperature": 0.7,
                        "top_p": 0.95,
                        "top_k": 40,
                        "max_output_tokens": 8192,
                    },
                    safety_settings=[
                        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                    ]
                )
                # Test with a quick call to verify the model exists
                test_resp = candidate.generate_content("Reply with OK")
                _ = test_resp.text  # Force evaluation
                
                self.model = candidate
                self.model_name = model_name
                print(f"    [✓] AI Brain initialized: {model_name}")
                break
            except Exception as e:
                err = str(e)
                if "404" in err or "not found" in err.lower():
                    print(f"    [!] Model {model_name} not available, trying next...")
                    continue
                elif "429" in err or "quota" in err.lower():
                    print(f"    [!] Rate limited on {model_name}, waiting 10s...")
                    time.sleep(10)
                    continue
                else:
                    print(f"    [!] Error with {model_name}: {err}")
                    continue
        
        if self.model is None:
            raise ValueError(
                "[!] No working Gemini model found! Tried: " + ", ".join(chain) +
                "\n    Check your API key and available models at https://aistudio.google.com"
            )
        
        self.chat = self.model.start_chat(history=[])

    def _build_groq_prompt(self, target, goal, knowledge_base, last_command, last_output, phase):
        """Build a SHORT prompt for Groq (limited context window)."""
        # Extract only essential KB info
        vulns = knowledge_base.get("vulnerabilities", [])
        ports = knowledge_base.get("open_ports", [])
        
        kb_summary = ""
        if ports:
            kb_summary += f"Ports: {ports[:5]}\n"
        if vulns:
            kb_summary += f"Vulns: {[v.get('title','')[:30] for v in vulns[:3]]}\n"
        
        return f"""You are an elite pentester AI on Kali Linux. Target: {target}. Phase: {phase}.
Goal: {goal[:500]}

{kb_summary}
Last cmd: {last_command[:100] if last_command else 'None'}
Output: {last_output[:600] if last_output else 'None'}

ABSOLUTE RULES:
1. NEVER add proxychains/torsocks - proxy is AUTOMATIC
2. NEVER use nmap -p- - use --top-ports 1000 or -F
3. ONLY action values allowed: COMMAND, GOAL_ACHIEVED, SWITCH_PHASE
4. NEVER repeat a command that already failed. Use DIFFERENT tool
5. If output says "not found" - that tool is NOT installed. Use alternative
6. Speed: nmap -T4, sqlmap --batch --threads=10, ffuf -t 50
7. Wordlists: /usr/share/wordlists/rockyou.txt, /usr/share/wordlists/dirb/common.txt
8. Use bash -c 'for...' for loops (not raw for/while)
9. If blocked/refused, switch to OSINT (crt.sh, dig, whois)
10. curl: -sk --max-time 15
11. If sqlmap needs CSRF: use --csrf-token and --threads=1 (not 10)
12. Hydra for web: get fresh CSRF token each time or it gives false positives
13. PREFER writing custom bash/python scripts over basic tool commands

INSTALLED TOOLS: nmap, nikto, sqlmap, nuclei, ffuf, gobuster, curl, dig, whois, host, assetfinder, hydra, searchsploit, wpscan, sslscan, openssl, dirsearch, grep, jq, python3, bash, sed, awk
NOT INSTALLED: httpx(Go), dalfox, xsstrike, hakrawler, paramspider, gau, qsreplace, gospider, subfinder, testssl.sh, sublist3r, amass, waybackurls, wapiti, shodan

=== ADVANCED SCRIPTING (USE THIS! Better than basic tools) ===
Write custom scripts instead of relying on basic tool commands:

CRAWL & EXTRACT LINKS: bash -c 'curl -sk https://{target}/ | grep -oP "(href|src)=\"[^\"]+\"" | sort -u'
FIND JS FILES & SECRETS: bash -c 'for js in $(curl -sk https://{target}/ | grep -oP "src=\"[^\"]+\\.js\"" | grep -oP "\"[^\"]+\"" | tr -d \'\"\'); do echo "==$js=="; curl -sk "https://{target}/$js" 2>/dev/null | grep -oiE "(api[_-]?key|token|secret|password|authorization|firebase|aws_)[a-zA-Z0-9_]*[=:][^\"\' ]+" | head -20; done'
PARAMETER FUZZING: bash -c 'for p in id user admin page file path cmd search query url redirect next callback; do r=$(curl -sk -o /dev/null -w "%{{http_code}}:%{{size_download}}" "https://{target}/page?$p=test123" --max-time 10); echo "$p -> $r"; done'
CSRF-AWARE LOGIN BRUTE: bash -c 'for pw in admin password 123456 admin123 letmein master; do TOKEN=$(curl -sk https://{target}/login -c /tmp/zcookie | grep -oP "name=\"_token\" value=\"\\K[^\"]+"); RESP=$(curl -sk -X POST https://{target}/login -b /tmp/zcookie -d "email=admin@{target}&password=$pw&_token=$TOKEN" -w "\n%{{http_code}}" -o /tmp/zbody --max-time 15); CODE=$(echo "$RESP" | tail -1); SIZE=$(wc -c < /tmp/zbody); echo "$pw -> HTTP $CODE (size: $SIZE)"; done'
SECURITY HEADER CHECK: bash -c 'H=$(curl -skI https://{target}/); echo "$H" | head -20; echo "---MISSING HEADERS---"; for h in X-Frame-Options Content-Security-Policy X-XSS-Protection Strict-Transport-Security X-Content-Type-Options; do echo "$H" | grep -qi "$h" || echo "MISSING: $h"; done'
SUBDOMAIN BRUTE: bash -c 'for sub in www mail ftp admin dev staging api test vpn portal app cdn; do ip=$(dig +short $sub.{target} 2>/dev/null | head -1); [ -n "$ip" ] && echo "FOUND: $sub.{target} -> $ip"; done'
DIR ENUM CUSTOM: bash -c 'for p in .env .git/HEAD wp-config.php.bak robots.txt sitemap.xml .htaccess server-status info.php phpinfo.php api/v1 graphql .well-known/security.txt debug trace web.config; do CODE=$(curl -sk -o /dev/null -w "%{{http_code}}" "https://{target}/$p" --max-time 10); [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "$p -> $CODE"; done'
XSS PROBE: bash -c 'PAYLOADS=(\'<script>alert(1)</script>\' \'"onmouseover=alert(1)\' \'\'\'><img src=x onerror=alert(1)>\' \'javascript:alert(1)\'); for param in $(curl -sk https://{target}/ | grep -oP "name=\"\\K[^\"]+" | sort -u); do for pay in "${{PAYLOADS[@]}}"; do RESP=$(curl -sk "https://{target}/?$param=$pay" --max-time 10); echo "$RESP" | grep -q "alert(1)" && echo "POSSIBLE XSS: $param with $pay"; done; done'
PYTHON SCANNER: python3 -c "import urllib.request,ssl,json; ctx=ssl._create_unverified_context(); [print(f'{{p}}: {{urllib.request.urlopen(f\"https://{target}/{{p}}\",context=ctx).status}}') for p in ['.env','debug','trace','api','graphql','wp-json/wp/v2/users','server-info','.git/config'] if (lambda u: (True, urllib.request.urlopen(u,context=ctx).status))(f'https://{target}/{{p}}')]"
WAYBACK ENUM: bash -c 'curl -s "http://web.archive.org/cdx/search/cdx?url={target}/*&output=text&fl=original&collapse=urlkey" 2>/dev/null | head -50 | sort -u'
OPEN REDIRECT TEST: bash -c 'for param in url redirect next callback return_to goto dest destination rurl; do for target_url in "https://evil.com" "//evil.com" "/\\evil.com"; do CODE=$(curl -sk -o /dev/null -w "%{{http_code}}" "https://{target}/?$param=$target_url" --max-time 10); [ "$CODE" = "301" ] || [ "$CODE" = "302" ] && echo "POSSIBLE REDIRECT: $param=$target_url -> $CODE"; done; done'
SSRF PROBE: bash -c 'for param in url file path page load fetch src dest redirect; do RESP=$(curl -sk "https://{target}/?$param=http://127.0.0.1:22" -w "\n%{{http_code}}" --max-time 10); echo "$param -> $(echo $RESP | tail -1)"; done'

ALWAYS prefer scripts when:
- Basic tools fail or timeout
- Need multi-step logic (get token → use token → check result)
- Need to chain results (find URLs → test each one)
- WAF blocks standard tools (custom curl bypasses WAF signatures)
- Need to test specific parameters or endpoints

RESPOND JSON ONLY:
{{"reasoning":"why","action":"COMMAND","command":"linux cmd or bash script","phase":"{phase}","expected_outcome":"what"}}
OR: {{"reasoning":"done","action":"GOAL_ACHIEVED","findings_summary":"results","phase":"REPORT"}}
"""

    def _build_gemini_prompt(self, target, goal, knowledge_base, last_command, last_output, phase):
        """Build full prompt for Gemini (larger context)."""
        return f"""
You are ZenithAI - an elite autonomous pentester on Kali Linux.
Analyze outputs carefully and choose the BEST next action.

=== MISSION ===
Target: {target}
Goal: {goal[:2000]}
Phase: {phase}

=== KNOWLEDGE BASE ===
{json.dumps(knowledge_base, indent=2, default=str)[:3000]}

=== LAST ACTION ===
Command: {last_command if last_command else "None"}
Output: {last_output[:1500] if last_output else "None"}

=== ABSOLUTE RULES (VIOLATION = SCAN FAILURE) ===
1. NEVER add proxychains, torsocks, or any proxy wrapper. Proxy is AUTOMATIC. "proxychains nmap" = DOUBLE proxy = BROKEN.
2. NEVER use nmap -p- (takes forever). Use --top-ports 1000 or -F.
3. ONLY allowed actions: COMMAND, GOAL_ACHIEVED, SWITCH_PHASE. Nothing else (no DNS_RESOLUTION, PORT_SCAN, etc).
4. NEVER repeat a failed command. Use a COMPLETELY DIFFERENT tool.
5. If output says "not found", the tool is NOT installed. Skip it forever.
6. Use bash -c '...' for shell loops (for/while/do). Raw loops WILL break.
7. If connection refused/blocked, switch to passive OSINT immediately.
8. sqlmap + CSRF: use --csrf-token="_token" --csrf-url=URL --threads=1 (NOT 10, they conflict).
9. Hydra + CSRF: CSRF tokens expire. For Laravel, get fresh token per request or expect false positives.

=== INSTALLED TOOLS (USE THESE ONLY) ===
nmap, nikto, sqlmap, nuclei, ffuf, gobuster, curl, dig, whois, host, assetfinder, hydra, searchsploit, wpscan, sslscan, openssl, dirsearch, grep, jq, sed, awk, bash

=== NOT INSTALLED (DO NOT USE) ===
httpx(Go version), dalfox, xsstrike, hakrawler, paramspider, gau, qsreplace, gospider, subfinder, testssl.sh, sublist3r, amass, waybackurls, wapiti, shodan

=== SPEED RULES ===
- nmap: -sV -sC -T4 --top-ports 1000 (NEVER -p-)
- sqlmap: --batch --level=3 --risk=3 (add --threads=10 ONLY without --csrf-url)
- ffuf: -w /usr/share/wordlists/dirb/common.txt -t 50 -mc 200,301,302,403
- curl: -sk --max-time 15 (quick checks)
- nuclei: -u URL -severity critical,high (NOT -l with empty files)
- Prefer: nuclei > nikto, ffuf > gobuster, curl > httpx

=== KALI WORDLISTS ===
- /usr/share/wordlists/rockyou.txt (passwords)
- /usr/share/wordlists/dirb/common.txt (web dirs - SMALL, fast)
- /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt (web dirs - MEDIUM)
- /usr/share/wordlists/fasttrack.txt (quick passwords)

=== SMART TECHNIQUES ===
- Subdomains: assetfinder --subs-only domain.tld
- Probe subs: bash -c 'for s in $(cat subs.txt); do curl -sk -o /dev/null -w "%{{http_code}} $s\n" http://$s --max-time 10; done'
- DNS: dig ANY domain.tld, dig axfr domain.tld @ns
- SSL: echo | openssl s_client -connect host:443 2>/dev/null | openssl x509 -noout -text
- Certs: curl -s "https://crt.sh/?q=%25.domain.tld&output=json" | jq -r '.[].name_value' | sort -u
- Wayback: curl -s "http://web.archive.org/cdx/search/cdx?url=domain.tld/*&output=text&fl=original&collapse=urlkey"
- Web tech: curl -sI https://target | head -30
- Exploits: searchsploit service version

=== ⚡ ADVANCED SCRIPTING (PREFERRED OVER BASIC TOOLS) ===
You are an elite hacker. Write CUSTOM scripts that are smarter than basic tool runs.
ALWAYS prefer writing bash/python scripts when possible. They bypass WAFs, handle multi-step logic, and give better results.

--- WEB CRAWLING & LINK EXTRACTION ---
bash -c 'curl -sk https://{target}/ | grep -oP "(href|src)=\\"[^\\"]+\\"" | sed "s/href=//;s/src=//;s/\\"//g" | sort -u | while read url; do [[ "$url" == /* ]] && url="https://{target}$url"; echo "$url"; done'

--- FIND JAVASCRIPT FILES & EXTRACT SECRETS ---
bash -c 'for js in $(curl -sk https://{target}/ | grep -oP "src=\\"[^\\"]+\\.js\\"" | grep -oP "\\"[^\\"]+\\"" | tr -d \'\\"\'); do full_url="$js"; [[ "$js" == /* ]] && full_url="https://{target}$js"; echo "\n=== $full_url ==="; curl -sk "$full_url" 2>/dev/null | grep -oiE "(api[_-]?key|token|secret|password|authorization|firebase|aws_|private[_-]?key|access[_-]?key)[a-zA-Z0-9_]*[\\"\'\'=:][^\\"\'\' ,;}}]+" | head -30; done'

--- SMART PARAMETER DISCOVERY & FUZZING ---
bash -c 'echo "=== Form Parameters ==="; curl -sk https://{target}/ | grep -oP "name=\\"\\K[^\\"]+" | sort -u; echo "\n=== URL Parameter Fuzz ==="; for p in id user admin page file path cmd search query url redirect next callback action type format debug test; do r=$(curl -sk -o /dev/null -w "%{{http_code}}:%{{size_download}}" "https://{target}/?$p=test123zenith" --max-time 10); echo "$p -> $r"; done'

--- CSRF-AWARE LOGIN BRUTE FORCE (Laravel/PHP) ---
bash -c 'echo "=== Login Brute Force (CSRF-aware) ==="; for pw in admin password 123456 admin123 letmein master welcome P@ssw0rd root toor changeme; do TOKEN=$(curl -sk https://{target}/login -c /tmp/zcookie 2>/dev/null | grep -oP "name=\\"_token\\" value=\\"\\K[^\\"]+"); if [ -z "$TOKEN" ]; then TOKEN=$(curl -sk https://{target}/login -c /tmp/zcookie 2>/dev/null | grep -oP "csrf[_-]token.*?content=\\"\\K[^\\"]+"); fi; RESP=$(curl -sk -X POST https://{target}/login -b /tmp/zcookie -d "email=admin@{target}&password=$pw&_token=$TOKEN" -w "HTTP_%{{http_code}}_SIZE_%{{size_download}}" -o /tmp/zbody -D /tmp/zheaders --max-time 15 2>/dev/null); CODE=$(echo "$RESP" | grep -oP "HTTP_\\K[0-9]+"); SIZE=$(echo "$RESP" | grep -oP "SIZE_\\K[0-9]+"); REDIR=$(grep -i "location:" /tmp/zheaders 2>/dev/null | head -1); echo "$pw -> HTTP $CODE (size: $SIZE) $REDIR"; sleep 1; done'

--- SECURITY HEADER AUDIT ---
bash -c 'echo "=== Security Header Analysis ==="; H=$(curl -skI https://{target}/); echo "$H" | head -20; echo "\n--- Missing Security Headers ---"; for h in "X-Frame-Options" "Content-Security-Policy" "X-XSS-Protection" "Strict-Transport-Security" "X-Content-Type-Options" "Referrer-Policy" "Permissions-Policy" "Cross-Origin-Opener-Policy" "Cross-Origin-Resource-Policy"; do echo "$H" | grep -qi "$h" || echo "⚠ MISSING: $h"; done; echo "\n--- Cookie Security ---"; echo "$H" | grep -i set-cookie | while read line; do echo "$line" | grep -qi "httponly" || echo "⚠ Cookie missing HttpOnly"; echo "$line" | grep -qi "secure" || echo "⚠ Cookie missing Secure flag"; echo "$line" | grep -qi "samesite" || echo "⚠ Cookie missing SameSite"; done'

--- SUBDOMAIN BRUTEFORCE ---
bash -c 'echo "=== Subdomain Bruteforce ==="; for sub in www mail ftp admin dev staging api test vpn portal app cdn beta internal git jenkins ci cd grafana kibana elastic monitor status blog shop store; do ip=$(dig +short $sub.{target} 2>/dev/null | head -1); [ -n "$ip" ] && echo "FOUND: $sub.{target} -> $ip"; done'

--- SENSITIVE FILE DISCOVERY ---
bash -c 'echo "=== Sensitive File Discovery ==="; for p in .env .git/HEAD .git/config wp-config.php.bak .htaccess .htpasswd server-status server-info info.php phpinfo.php test.php debug trace web.config appsettings.json config.json config.yml config.php database.yml .DS_Store Thumbs.db crossdomain.xml clientaccesspolicy.xml sitemap.xml robots.txt security.txt .well-known/security.txt api/ api/v1 api/v2 graphql swagger swagger/v1/swagger.json api-docs v1/api-docs openapi.json wp-json/wp/v2/users actuator/env actuator/health; do CODE=$(curl -sk -o /tmp/zbody -w "%{{http_code}}:%{{size_download}}" "https://{target}/$p" --max-time 10 2>/dev/null); HTTP=$(echo "$CODE" | cut -d: -f1); SIZE=$(echo "$CODE" | cut -d: -f2); [ "$HTTP" != "404" ] && [ "$HTTP" != "000" ] && [ "$SIZE" != "0" ] && echo "$p -> HTTP $HTTP ($SIZE bytes)"; done'

--- XSS TESTING SCRIPT ---
bash -c 'echo "=== XSS Testing ==="; PARAMS=$(curl -sk https://{target}/ | grep -oP "name=\\"\\K[^\\"]+" | sort -u); PAYLOADS=(\'<script>alert(1)</script>\' \'"onmouseover="alert(1)"\' \'\'\'><img src=x onerror=alert(1)>\' \'<svg onload=alert(1)>\' \'javascript:alert(1)\'); for param in $PARAMS; do for pay in "${{PAYLOADS[@]}}"; do RESP=$(curl -sk "https://{target}/?$param=$(echo $pay | python3 -c "import sys,urllib.parse;print(urllib.parse.quote(sys.stdin.read().strip()))" 2>/dev/null)" --max-time 10 2>/dev/null); echo "$RESP" | grep -q "alert(1)" && echo "⚠ POSSIBLE XSS: param=$param payload=$pay"; done; done'

--- OPEN REDIRECT TESTING ---
bash -c 'echo "=== Open Redirect Testing ==="; for param in url redirect next callback return_to goto dest destination rurl redirect_url continue return; do for target_url in "https://evil.com" "//evil.com" "/\\\\evil.com" "////evil.com" "https:evil.com"; do RESP=$(curl -sk -D- -o /dev/null "https://{target}/?$param=$target_url" --max-time 10 2>/dev/null); LOC=$(echo "$RESP" | grep -i "^location:" | head -1); CODE=$(echo "$RESP" | head -1 | grep -oP "[0-9]{{3}}"); [ -n "$LOC" ] && echo "⚠ REDIRECT: $param=$target_url -> $CODE $LOC"; done; done'

--- SSRF PROBE ---
bash -c 'echo "=== SSRF Probe ==="; for param in url file path page load fetch src dest redirect uri data; do RESP=$(curl -sk -o /dev/null -w "%{{http_code}}:%{{size_download}}" "https://{target}/?$param=http://127.0.0.1:22" --max-time 10 2>/dev/null); echo "$param -> $RESP"; done'

--- PYTHON ADVANCED SCANNER ---
python3 -c "
import urllib.request, ssl, sys, json
ctx = ssl._create_unverified_context()
target = '{target}'
paths = ['.env', '.git/config', 'debug', 'trace', 'api', 'graphql', 'wp-json/wp/v2/users', 'server-info', 'actuator/env', 'swagger/v1/swagger.json', '.well-known/security.txt']
for p in paths:
    try:
        r = urllib.request.urlopen(f'https://{{target}}/{{p}}', context=ctx, timeout=10)
        body = r.read(500).decode(errors='ignore')
        print(f'[{{r.status}}] /{{p}} ({{len(body)}}b): {{body[:100]}}')
    except urllib.error.HTTPError as e:
        if e.code != 404: print(f'[{{e.code}}] /{{p}}')
    except: pass
"

--- TECHNOLOGY FINGERPRINTING ---
bash -c 'echo "=== Deep Fingerprint ==="; H=$(curl -skI https://{target}/); echo "SERVER: $(echo "$H" | grep -i ^server: | head -1)"; echo "POWERED: $(echo "$H" | grep -i ^x-powered | head -1)"; BODY=$(curl -sk https://{target}/ | head -100); echo "$BODY" | grep -oiE "(wp-content|wordpress|joomla|drupal|laravel|django|express|rails|angular|react|vue|next|nuxt|jquery-[0-9.]+|bootstrap-[0-9.]+)" | sort -u | while read t; do echo "TECH: $t"; done; echo "GENERATOR: $(echo "$BODY" | grep -oP "content=\\"\\K[^\\"]+" | head -3)"

=== SCRIPTING RULES ===
1. ALWAYS prefer custom scripts over basic single-tool commands
2. Write bash -c '...' for multi-step operations
3. Use python3 -c '...' for complex logic (urllib, json parsing, encoding)
4. Chain operations: extract → analyze → test in ONE command
5. Custom scripts bypass WAF because they don't have tool signatures
6. ALWAYS add --max-time to curl inside scripts (prevents hanging)
7. Use /tmp/z* for temp files (zcookie, zbody, zheaders, zurls)
8. For login brute: ALWAYS get fresh CSRF token before EACH attempt
9. Test MULTIPLE payloads per parameter, not just one
10. Extract info from responses (headers, body, status codes, sizes)

=== RESPOND WITH JSON ONLY ===
{{"reasoning":"brief analysis","action":"COMMAND","command":"linux command (NO proxychains!)","phase":"{phase}","expected_outcome":"what we expect"}}

OR if done:
{{"reasoning":"summary","action":"GOAL_ACHIEVED","findings_summary":"all findings","phase":"REPORT"}}
"""

    def think(self, target, goal, knowledge_base, last_command="", last_output="", phase="recon"):
        """
        AI thinks and decides the next action to take.
        
        Returns:
            dict: {"action": "COMMAND|ANALYZE|GOAL_ACHIEVED|SWITCH_PHASE", 
                   "command": "...", "reasoning": "...", "phase": "..."}
        """
        
        # Use shorter prompt for Groq to avoid 413 errors
        if self.provider == "groq":
            prompt = self._build_groq_prompt(target, goal, knowledge_base, last_command, last_output, phase)
        else:
            prompt = self._build_gemini_prompt(target, goal, knowledge_base, last_command, last_output, phase)

        try:
            self.call_count += 1
            
            # Call the appropriate provider
            if self.provider == "groq":
                raw_text = self._call_groq(prompt)
            else:
                raw_text = self._call_gemini(prompt)
            
            # Clean up response - remove markdown code blocks if present
            if raw_text.startswith("```"):
                raw_text = raw_text.split("\n", 1)[1] if "\n" in raw_text else raw_text[3:]
            if raw_text.endswith("```"):
                raw_text = raw_text[:-3]
            raw_text = raw_text.strip()
            
            # Parse JSON - fix invalid escape sequences from AI
            def _fix_json_escapes(text):
                """Fix invalid JSON escape sequences that AI produces.
                JSON only allows: backslash-quote, double-backslash, and a few control chars.
                AI often writes grep regex patterns which break JSON parsing."""
                import re
                # Fix invalid backslash-X escapes where X is not a valid JSON escape char
                # Valid JSON escapes after backslash: " \ / b f n r t u
                def _replace_invalid(m):
                    return '\\\\' + m.group(1)
                fixed = re.sub(r'\\([^"\\/bfnrtu])', _replace_invalid, text)
                return fixed
            
            try:
                decision = json.loads(raw_text)
            except json.JSONDecodeError:
                # Try fixing escape sequences first
                try:
                    fixed_text = _fix_json_escapes(raw_text)
                    decision = json.loads(fixed_text)
                except json.JSONDecodeError:
                    # Try to extract JSON from the response
                    import re
                    json_match = re.search(r'\{.*\}', raw_text, re.DOTALL)
                    if json_match:
                        try:
                            decision = json.loads(json_match.group())
                        except json.JSONDecodeError:
                            try:
                                decision = json.loads(_fix_json_escapes(json_match.group()))
                            except json.JSONDecodeError:
                                decision = {
                                    "reasoning": "Failed to parse AI response, running web scan",
                                    "action": "COMMAND",
                                    "command": f"curl -skI https://{target}/ | head -30",
                                    "phase": phase,
                                    "expected_outcome": "HTTP headers and server info"
                                }
                    else:
                        decision = {
                            "reasoning": "Failed to parse AI response, running web scan",
                            "action": "COMMAND",
                            "command": f"curl -skI https://{target}/ | head -30",
                            "phase": phase,
                            "expected_outcome": "HTTP headers and server info"
                        }
            
            # Success - reset error counter
            self.consecutive_errors = 0
            return decision
            
        except Exception as e:
            error_msg = str(e)
            self.consecutive_errors += 1
            print(f"    [!] AI Error ({self.consecutive_errors}/{self.max_consecutive_errors}): {error_msg[:150]}")
            
            # MODEL NOT FOUND - fatal, don't retry with same model
            if "404" in error_msg or "not found" in error_msg.lower():
                print("    [!] Model not found! Attempting to switch model...")
                if self._try_switch_model():
                    self.consecutive_errors = 0
                    return self.think(target, goal, knowledge_base, last_command, last_output, phase)
                else:
                    return {
                        "reasoning": "FATAL: No working AI model found. Cannot continue scanning.",
                        "action": "GOAL_ACHIEVED",
                        "findings_summary": "Scan aborted - AI model not available. Check your API key and model availability.",
                        "phase": "REPORT"
                    }
            
            # RATE LIMITED - wait and retry (but respect max errors)
            if "429" in error_msg or "quota" in error_msg.lower():
                # Rate limit hit - ask user for new API key
                print(f"\n    {'='*50}")
                print(f"    ⚠️  RATE LIMIT HIT - API quota exhausted!")
                print(f"    {'='*50}")
                print(f"    Current API key: {self.api_key[:10]}...{self.api_key[-4:]}")
                print(f"    \n    Options:")
                print(f"    1. Enter new API key to continue")
                print(f"    2. Press Enter to wait 60s and retry")
                print(f"    3. Type 'quit' to stop scan")
                print()
                
                try:
                    user_input = input("    🔑 New API Key (or Enter to wait): ").strip()
                    
                    if user_input.lower() == 'quit':
                        return {
                            "reasoning": "User chose to stop scan after rate limit.",
                            "action": "GOAL_ACHIEVED",
                            "findings_summary": "Scan stopped by user after API rate limit.",
                            "phase": "REPORT"
                        }
                    elif user_input and len(user_input) > 20:
                        # User provided new API key
                        if self._switch_api_key(user_input):
                            print(f"    [✓] Switched to new API key! Continuing scan...")
                            self.consecutive_errors = 0
                            return self.think(target, goal, knowledge_base, last_command, last_output, phase)
                        else:
                            print(f"    [!] New API key failed. Waiting 60s and retrying with old key...")
                            time.sleep(60)
                            return self.think(target, goal, knowledge_base, last_command, last_output, phase)
                    else:
                        # User pressed Enter - wait and retry
                        print(f"    [*] Waiting 60 seconds before retry...")
                        time.sleep(60)
                        return self.think(target, goal, knowledge_base, last_command, last_output, phase)
                        
                except EOFError:
                    # Non-interactive mode - just wait
                    time.sleep(60)
                    return self.think(target, goal, knowledge_base, last_command, last_output, phase)
            
            # TOO MANY CONSECUTIVE ERRORS - stop
            if self.consecutive_errors >= self.max_consecutive_errors:
                print(f"    [!] {self.max_consecutive_errors} consecutive errors. Stopping scan.")
                return {
                    "reasoning": f"Too many consecutive AI errors ({self.consecutive_errors}). Last error: {error_msg[:100]}",
                    "action": "GOAL_ACHIEVED",
                    "findings_summary": "Scan stopped due to repeated AI errors. Check API key, quota, and model availability.",
                    "phase": "REPORT"
                }
            
            # Other errors - fallback action (vary commands to avoid duplicate detection)
            fallback_commands = [
                (f"curl -skI https://{target}/ | head -30", "HTTP headers check"),
                (f"dig ANY {target}", "DNS records lookup"),
                (f"whois {target} | head -40", "WHOIS information"),
                (f'bash -c \'for p in .env .git/HEAD robots.txt sitemap.xml; do CODE=$(curl -sk -o /dev/null -w "%{{http_code}}" "https://{target}/$p" --max-time 10); [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "$p -> $CODE"; done\'', "Sensitive file discovery"),
                (f"sslscan --no-colour {target} | head -40", "SSL/TLS scan"),
                (f"nikto -h https://{target} -maxtime 120 -C all", "Web vulnerability scan"),
            ]
            import random
            cmd, outcome = random.choice(fallback_commands)
            return {
                "reasoning": f"AI error occurred: {error_msg[:100]}. Using fallback command.",
                "action": "COMMAND",
                "command": cmd,
                "phase": phase,
                "expected_outcome": outcome
            }

    def _call_groq(self, prompt):
        """Call Groq API and return response text."""
        # Truncate prompt if too long (Groq has ~8k context for llama models)
        if len(prompt) > 6000:
            prompt = prompt[:6000] + "\n...[truncated]...\nRespond with JSON only."
        
        # Add to chat history for context
        self.chat_history.append({"role": "user", "content": prompt})
        
        # Keep only last 4 messages to avoid context overflow (Groq has small context)
        if len(self.chat_history) > 4:
            self.chat_history = self.chat_history[-4:]
        
        response = self.groq_client.chat.completions.create(
            model=self.model_name,
            messages=self.chat_history,
            max_tokens=2048,
            temperature=0.7,
        )
        
        assistant_msg = response.choices[0].message.content
        self.chat_history.append({"role": "assistant", "content": assistant_msg})
        
        return assistant_msg.strip()
    
    def _call_gemini(self, prompt):
        """Call Gemini API and return response text."""
        response = self.chat.send_message(prompt)
        return response.text.strip()

    def _switch_api_key(self, new_api_key):
        """
        Switch to a new API key and reinitialize the model.
        Returns True if successful, False if the key doesn't work.
        """
        try:
            print(f"    [*] Testing new API key: {new_api_key[:10]}...{new_api_key[-4:]}")
            
            # Auto-detect provider for new key
            if new_api_key.startswith("gsk_"):
                return self._switch_to_groq(new_api_key)
            
            # Default to Gemini
            genai.configure(api_key=new_api_key)
            
            # Try to create a model and test it
            candidate = genai.GenerativeModel(
                model_name=self.model_name if self.provider == "gemini" else "gemini-2.5-flash",
                generation_config={
                    "temperature": 0.7,
                    "top_p": 0.95,
                    "top_k": 40,
                    "max_output_tokens": 8192,
                },
                safety_settings=[
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                ]
            )
            
            # Test the new key
            test_resp = candidate.generate_content("Reply with OK")
            _ = test_resp.text
            
            # Success! Update everything
            self.api_key = new_api_key
            self.provider = "gemini"
            self.model = candidate
            self.chat = self.model.start_chat(history=[])
            print(f"    [✓] New Gemini API key is working!")
            return True
            
        except Exception as e:
            print(f"    [!] New API key failed: {str(e)[:100]}")
            # Revert to old key
            if self.provider == "gemini":
                genai.configure(api_key=self.api_key)
            return False
    
    def _switch_to_groq(self, new_api_key):
        """Switch to Groq provider with new key."""
        if not GROQ_AVAILABLE:
            print("    [!] Groq library not installed. Run: pip install groq")
            return False
        
        try:
            new_client = Groq(api_key=new_api_key)
            
            # Test the key
            for model_name in self.GROQ_MODELS:
                try:
                    response = new_client.chat.completions.create(
                        model=model_name,
                        messages=[{"role": "user", "content": "Reply with OK"}],
                        max_tokens=10
                    )
                    _ = response.choices[0].message.content
                    
                    # Success!
                    self.api_key = new_api_key
                    self.provider = "groq"
                    self.groq_client = new_client
                    self.model_name = model_name
                    self.chat_history = []
                    print(f"    [✓] Switched to Groq/{model_name}!")
                    return True
                except:
                    continue
            
            print("    [!] Groq key failed on all models")
            return False
        except Exception as e:
            print(f"    [!] Groq switch failed: {str(e)[:80]}")
            return False

    def _try_switch_model(self):
        """
        Try to switch to a different working model.
        Returns True if successful, False if no model works.
        """
        # Build a list of all models we haven't tried yet
        all_models = []
        for chain in self.MODEL_CHAINS.values():
            for m in chain:
                if m != self.model_name and m not in all_models:
                    all_models.append(m)
        
        for model_name in all_models:
            try:
                print(f"    [*] Trying fallback model: {model_name}...")
                candidate = genai.GenerativeModel(
                    model_name=model_name,
                    generation_config={
                        "temperature": 0.7,
                        "top_p": 0.95,
                        "top_k": 40,
                        "max_output_tokens": 8192,
                    },
                    safety_settings=[
                        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                    ]
                )
                test_resp = candidate.generate_content("Reply with OK")
                _ = test_resp.text
                
                self.model = candidate
                self.model_name = model_name
                self.chat = self.model.start_chat(history=[])
                print(f"    [✓] Switched to model: {model_name}")
                return True
            except Exception:
                continue
        
        print("    [!] No fallback model available!")
        return False

    def analyze_findings(self, knowledge_base, target, goal):
        """
        AI analyzes all findings and generates a comprehensive report.
        """
        prompt = f"""
Analyze all the security findings from this penetration test and create a detailed report.

Target: {target}
Goal: {goal}

Full Knowledge Base:
{json.dumps(knowledge_base, indent=2, default=str)}

Create a comprehensive security report in this JSON format:
{{
    "executive_summary": "Brief overview",
    "target": "{target}",
    "total_vulnerabilities": number,
    "critical_findings": [
        {{"title": "", "severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO", "description": "", "evidence": "", "recommendation": ""}}
    ],
    "all_findings": [
        {{"title": "", "severity": "", "description": "", "evidence": "", "recommendation": ""}}
    ],
    "open_ports": [],
    "technologies_detected": [],
    "recommendations": [],
    "risk_rating": "CRITICAL/HIGH/MEDIUM/LOW"
}}

Output ONLY the JSON object.
"""
        try:
            # Call appropriate provider
            if self.provider == "groq":
                raw_text = self._call_groq(prompt)
            else:
                response = self.model.generate_content(prompt)
                raw_text = response.text.strip()
            
            if raw_text.startswith("```"):
                raw_text = raw_text.split("\n", 1)[1] if "\n" in raw_text else raw_text[3:]
            if raw_text.endswith("```"):
                raw_text = raw_text[:-3]
            
            return json.loads(raw_text.strip())
        except Exception as e:
            return {
                "executive_summary": f"Auto-analysis failed: {e}",
                "findings": knowledge_base.get("vulnerabilities", []),
                "risk_rating": "UNKNOWN"
            }

    def get_stats(self):
        """Return AI usage statistics."""
        return {
            "provider": self.provider.upper(),
            "model": self.model_name,
            "total_calls": self.call_count,
        }
