"""
Zenith Command Validator - Validates and sanitizes AI-generated commands.
Ensures commands make sense, target is correct, and dangerous patterns are caught.
"""

import re
import shlex


class CommandValidator:
    """
    Validates commands before execution.
    Catches common AI mistakes and dangerous patterns.
    """

    # Patterns that should NEVER be in commands
    BLOCKED_PATTERNS = [
        r'rm\s+-rf\s+/',
        r'mkfs\.',
        r'dd\s+if=/dev/zero\s+of=/dev/',
        r'>\s*/dev/sd[a-z]',
        r'chmod\s+-R\s+777\s+/',
        r'mv\s+/\s',
        r':\(\)\s*\{\s*:\|:&\s*\}\s*;',
        r'fork\s+bomb',
    ]

    # Commands that require the target to be present
    TARGET_REQUIRED_COMMANDS = [
        "nmap", "nikto", "sqlmap", "nuclei", "subfinder",
        "whatweb", "gobuster", "dirb", "dirsearch", "wpscan",
        "hydra", "ffuf", "httpx",
    ]

    # Commands that are OK to run without target (downloads, installs, file ops)
    TARGET_EXEMPT_COMMANDS = [
        "wget", "curl", "apt-get", "apt", "pip", "pip3", "go", "gem", "npm",
        "snap", "gunzip", "unzip", "tar", "cat", "ls", "test", "echo",
        "mkdir", "cp", "mv", "chmod", "head", "tail", "grep", "find",
        "searchsploit", "msfconsole", "msfvenom",
    ]

    # Allowed download sources (legitimate tool sources)
    ALLOWED_DOWNLOAD_SOURCES = [
        "github.com",
        "raw.githubusercontent.com",
        "gitlab.com",
        "exploit-db.com",
        "packetstormsecurity.com",
        "kali.org",
        "debian.org",
        "ubuntu.com",
        "pypi.org",
        "npmjs.com",
        "seclists",
    ]

    # Maximum command length
    MAX_COMMAND_LENGTH = 2000

    # Commands that are safe package managers / installers
    INSTALLER_COMMANDS = [
        "apt-get install", "apt install", "pip install", "pip3 install",
        "go install", "gem install", "npm install", "snap install",
        "apt-get update", "apt update", "gunzip",
    ]

    def __init__(self, target=""):
        """
        Initialize validator.
        
        Args:
            target: The authorized target URL/IP
        """
        self.target = target
        self.target_parts = self._extract_target_parts(target)
        self.warnings = []

    def validate(self, command):
        """
        Validate a command before execution.
        
        Args:
            command: The command string to validate
            
        Returns:
            tuple: (is_valid: bool, cleaned_command: str, warnings: list)
        """
        self.warnings = []
        
        if not command or not command.strip():
            return False, "", ["Empty command"]

        command = command.strip()

        # Check length
        if len(command) > self.MAX_COMMAND_LENGTH:
            return False, "", [f"Command too long ({len(command)} chars, max {self.MAX_COMMAND_LENGTH})"]

        # Check blocked patterns
        for pattern in self.BLOCKED_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return False, "", [f"Blocked dangerous pattern detected"]

        # Check command type
        base_cmd = command.split()[0].lower() if command.split() else ""
        is_installer = any(inst in command.lower() for inst in self.INSTALLER_COMMANDS)
        is_exempt = any(exempt in base_cmd for exempt in self.TARGET_EXEMPT_COMMANDS)
        is_download = "wget" in base_cmd or ("curl" in base_cmd and ("-o" in command.lower() or "-O" in command))
        
        # For downloads, check if source is legitimate
        if is_download:
            is_legit_source = any(src in command.lower() for src in self.ALLOWED_DOWNLOAD_SOURCES)
            if is_legit_source:
                is_exempt = True  # Allow downloads from known sources
        
        if not is_installer and not is_exempt:
            # Check that scanning commands target the right host
            self._check_target_scope(command)

        # Check for common AI mistakes
        self._check_common_mistakes(command)

        # Clean up the command
        cleaned = self._clean_command(command)

        is_valid = not any("[BLOCKED]" in w for w in self.warnings)
        
        return is_valid, cleaned, self.warnings

    def _extract_target_parts(self, target):
        """Extract hostname, IP, and domain parts from target."""
        parts = set()
        if not target:
            return parts
        
        # Remove protocol
        clean = re.sub(r'^https?://', '', target)
        # Remove path/port
        clean = clean.split('/')[0].split(':')[0]
        
        parts.add(clean)
        
        # Add IP if it looks like one
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', target)
        if ip_match:
            parts.add(ip_match.group(1))
        
        # Add base domain
        domain_parts = clean.split('.')
        if len(domain_parts) >= 2:
            parts.add('.'.join(domain_parts[-2:]))
        
        return parts

    def _check_target_scope(self, command):
        """Check if the command targets the right host."""
        cmd_lower = command.lower()
        base_cmd = cmd_lower.split()[0] if cmd_lower.split() else ""
        
        # Only check for scanning/attack commands
        is_scanning_cmd = any(tool in base_cmd for tool in self.TARGET_REQUIRED_COMMANDS)
        
        if is_scanning_cmd and self.target_parts:
            # Check if any target part appears in the command
            has_target = any(part.lower() in cmd_lower for part in self.target_parts)
            
            if not has_target:
                # Check if targeting localhost (sometimes legitimate)
                targets_localhost = any(loc in cmd_lower for loc in ["127.0.0.1", "localhost", "0.0.0.0"])
                
                if not targets_localhost:
                    self.warnings.append(
                        f"[WARNING] Command may target wrong host. Expected: {self.target}"
                    )

    def _check_common_mistakes(self, command):
        """Check for common AI-generated command mistakes."""
        # Check for placeholder values (expanded list)
        placeholders = [
            "<target>", "<url>", "<ip>", "{target}", "{url}", "example.com", "TARGET_HERE",
            "YOUR_", "CHANGEME", "REPLACE_", "INSERT_", "PASTE_", "PUT_",
            "<token>", "{token}", "<cookie>", "{cookie}", "<password>", "{password}",
            "TOKEN_HERE", "COOKIE_HERE", "PASSWORD_HERE", "API_KEY_HERE",
            "your-", "your_token", "your_cookie", "your_session", "your_api",
            "xxx", "yyy", "zzz",
        ]
        for ph in placeholders:
            if ph.lower() in command.lower():
                self.warnings.append(f"[BLOCKED] Placeholder value detected: '{ph}' - fetch REAL values first (use curl -c /tmp/cookies.txt)")
                break  # One is enough

        # Check for very long timeouts in nmap
        if "nmap" in command and "-T5" in command:
            self.warnings.append("[WARNING] nmap -T5 is very aggressive and may trigger IDS")

        # Check for missing flags that could be dangerous
        if command.strip().startswith("sqlmap") and "--batch" not in command:
            self.warnings.append("[INFO] Consider adding --batch to sqlmap for non-interactive mode")

    def _clean_command(self, command):
        """Clean and sanitize command."""
        # Remove any ANSI color codes that AI might include
        command = re.sub(r'\033\[[0-9;]*m', '', command)
        
        # Remove markdown code block markers
        command = command.strip('`').strip()
        if command.startswith('bash\n'):
            command = command[5:]
        if command.startswith('sh\n'):
            command = command[3:]
        
        # Remove leading $ or # (common AI mistake)
        command = re.sub(r'^\s*[$#]\s*', '', command)
        
        return command.strip()
