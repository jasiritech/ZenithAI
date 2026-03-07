"""
Zenith Terminal Executor - Runs commands on the Linux shell safely.
"""

import subprocess
import shlex
import time
import os
import re
import signal
from datetime import datetime


class TerminalExecutor:
    """
    Executes Linux commands and captures output.
    Includes safety checks and timeout management.
    """

    # Commands that are BLOCKED for safety
    BLOCKED_COMMANDS = [
        "rm -rf /",
        "mkfs",
        "dd if=/dev/zero",
        ":(){ :|:& };:",
        "> /dev/sda",
        "mv / ",
        "chmod -R 777 /",
    ]

    def __init__(self, working_dir="/tmp/zenith_workspace", sudo_password=None, default_timeout=None, profile="custom"):
        """Initialize Terminal Executor."""
        self.working_dir = working_dir
        self.command_history = []
        self.total_commands = 0
        self.failed_commands = 0
        self.cache_hits = 0
        self.current_process = None  # Track running subprocess for Ctrl+C kill
        self.sudo_password = sudo_password  # Optional sudo password for automated execution
        self.default_timeout = default_timeout
        self.profile = profile
        self.command_cache = {}
        self.cache_ttl = 300
        
        # Create working directory
        os.makedirs(working_dir, exist_ok=True)
        
        print(f"    [✓] Terminal Executor ready (workspace: {working_dir})")
        if default_timeout:
            print(f"    [⚡] Fast mode timeout profile: {default_timeout}s default")
        if sudo_password:
            print(f"    [✓] Sudo password configured (commands will run with privileges)")

    def kill_current(self):
        """Kill the currently running subprocess (called on Ctrl+C)."""
        if self.current_process and self.current_process.poll() is None:
            try:
                if os.name != 'nt':
                    os.killpg(os.getpgid(self.current_process.pid), signal.SIGTERM)
                    # Give it 2 seconds, then SIGKILL
                    try:
                        self.current_process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        os.killpg(os.getpgid(self.current_process.pid), signal.SIGKILL)
                else:
                    self.current_process.kill()
                return True
            except (ProcessLookupError, OSError):
                pass
        return False

    def is_safe(self, command):
        """Check if command is safe to execute."""
        cmd_lower = command.lower().strip()
        
        for blocked in self.BLOCKED_COMMANDS:
            if blocked in cmd_lower:
                return False, f"Command blocked for safety: contains '{blocked}'"
        
        return True, "OK"

    # Generous timeouts - let commands finish properly (seconds)
    COMMAND_TIMEOUTS = {
        "nmap -p-": 600,       # 10 min - full port scan takes time
        "nmap -sV -p-": 600,   # 10 min - version detection + all ports
        "nmap": 300,           # 5 min - normal nmap
        "nikto": 300,          # 5 min - web scanner
        "sqlmap": 600,         # 10 min - SQL injection testing
        "nuclei": 600,         # 10 min - multi-vuln scanner
        "gobuster": 300,       # 5 min - directory bruteforce
        "dirb": 300,           # 5 min - directory bruteforce
        "ffuf": 300,           # 5 min - fast fuzzer
        "hydra": 600,          # 10 min - brute force
        "subfinder": 180,      # 3 min - subdomain finder
        "whatweb": 120,        # 2 min - fingerprint (aggression modes are slow)
        "whois": 30,           # 30 sec - quick lookup
        "dig": 30,             # 30 sec - DNS lookup
        "curl": 120,           # 2 min - proxied connections need 30s+ to connect
        "wget": 180,           # 3 min - download
        "wpscan": 600,         # 10 min - wordpress deep scan
        "httpx": 180,          # 3 min - http probe
        "wafw00f": 60,         # 1 min - WAF detect
        "wfuzz": 300,          # 5 min - fuzzer
        "amass": 600,          # 10 min - subdomain enum
        "masscan": 180,        # 3 min - fast port scan
        "dirsearch": 300,      # 5 min - directory scan
        "wapiti": 300,         # 5 min - web vuln scanner
        "openssl": 60,         # 1 min - SSL checks
        "grep": 30,            # 30 sec - text search
        "cat": 10,             # 10 sec - file read
        "echo": 10,            # 10 sec - echo command
        "jq": 30,              # 30 sec - JSON processing
        "testssl": 300,        # 5 min - SSL/TLS testing
        "sslscan": 120,        # 2 min - SSL scan
        "enum4linux": 300,     # 5 min - SMB enum
        "dnsenum": 180,        # 3 min - DNS enum
        "fierce": 180,         # 3 min - DNS recon
        "searchsploit": 30,    # 30 sec - exploit search
        "theHarvester": 300,   # 5 min - OSINT harvester
        "theharvester": 300,   # 5 min - case variant
        "assetfinder": 120,    # 2 min - subdomain finder
        "xargs": 180,          # 3 min - parallel execution
        "host": 30,            # 30 sec - DNS lookup
        "waybackurls": 120,    # 2 min - wayback machine
        "python3": 300,        # 5 min - custom python scripts
        "python": 300,         # 5 min - python scripts
        "bash": 300,           # 5 min - custom bash scripts
        "sh": 180,             # 3 min - shell scripts
        "sed": 30,             # 30 sec - text processing
        "awk": 30,             # 30 sec - text processing
        "sort": 30,            # 30 sec - sorting
        "head": 10,            # 10 sec - head
        "tail": 10,            # 10 sec - tail
        "wc": 10,              # 10 sec - word count
        "tr": 10,              # 10 sec - translate
        "cut": 10,             # 10 sec - cut fields
        "uniq": 10,            # 10 sec - unique
    }

    def _get_smart_timeout(self, command):
        """Get a smart timeout based on the command being run."""
        cmd_lower = command.lower().strip()
        # Check specific patterns first (longer matches)
        for pattern in sorted(self.COMMAND_TIMEOUTS.keys(), key=len, reverse=True):
            if pattern in cmd_lower:
                return self.COMMAND_TIMEOUTS[pattern]
        return self.default_timeout or 300  # Default 5 minutes - let commands finish

    def _is_cacheable_command(self, command):
        """Cache only read-style commands to speed up repeated scan loops."""
        cmd = command.strip().lower()
        write_indicators = [" apt ", " install ", " rm ", " mv ", " cp ", " >", " >>", " tee ", " chmod ", " chown "]
        if any(x in f" {cmd} " for x in write_indicators):
            return False
        if cmd.startswith("sudo "):
            return False
        return True

    def _get_cached_result(self, command):
        """Return cached successful result if still fresh."""
        if not self._is_cacheable_command(command):
            return None
        entry = self.command_cache.get(command)
        if not entry:
            return None
        age = time.time() - entry["ts"]
        if age > self.cache_ttl:
            return None
        self.cache_hits += 1
        cached = dict(entry["result"])
        cached["cached"] = True
        cached["duration"] = 0.0
        cached["output"] = (cached.get("output", "") or "") + "\n\n[cache] reused recent result"
        return cached

    def _set_cached_result(self, command, result):
        """Cache successful read-style command output."""
        if not result.get("success"):
            return
        if not self._is_cacheable_command(command):
            return
        self.command_cache[command] = {"ts": time.time(), "result": dict(result)}

    def _wrap_sudo(self, command):
        """
        Auto-pipe sudo password to commands that need it.
        Converts: sudo apt install -y nmap
        To:       echo 'password' | sudo -S apt install -y nmap
        """
        if not self.sudo_password:
            return command
        
        cmd_stripped = command.strip()
        
        # Handle 'sudo' at the start
        if cmd_stripped.startswith('sudo '):
            # Don't double-wrap if already using -S
            if 'sudo -S' in cmd_stripped or 'echo' in cmd_stripped.split('sudo')[0]:
                return command
            # Replace 'sudo' with 'echo password | sudo -S'
            return cmd_stripped.replace('sudo ', f"echo '{self.sudo_password}' | sudo -S ", 1)
        
        # Handle 'sudo' in the middle (e.g., 'command && sudo apt install')
        if ' sudo ' in cmd_stripped:
            return cmd_stripped.replace(' sudo ', f" echo '{self.sudo_password}' | sudo -S ")
        
        return command

    def execute(self, command, timeout=None):
        """
        Execute a Linux command and return the output.
        
        Args:
            command: The command to run
            timeout: Max seconds to wait (auto-detected if None)
            
        Returns:
            dict: {"success": bool, "output": str, "error": str, "return_code": int, "duration": float}
        """
        # Auto-detect smart timeout if not specified
        if timeout is None:
            timeout = self._get_smart_timeout(command)

        cached_result = self._get_cached_result(command)
        if cached_result is not None:
            self.total_commands += 1
            self._log_command(command, cached_result)
            return cached_result

        # Safety check
        is_safe, reason = self.is_safe(command)
        if not is_safe:
            return {
                "success": False,
                "output": "",
                "error": reason,
                "return_code": -1,
                "duration": 0,
                "command": command
            }

        start_time = time.time()
        self.total_commands += 1

        # Auto-pipe sudo password if available
        command = self._wrap_sudo(command)

        try:
            # Set environment for non-interactive execution
            env = os.environ.copy()
            env["DEBIAN_FRONTEND"] = "noninteractive"
            env["TERM"] = "dumb"

            process = subprocess.Popen(
                command,
                shell=True,
                executable='/bin/bash' if os.name != 'nt' else None,  # Use bash for for/while/do loops
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=self.working_dir,
                env=env,
                preexec_fn=os.setsid if os.name != 'nt' else None
            )
            self.current_process = process  # Track for Ctrl+C kill

            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                # Kill the process group
                if os.name != 'nt':
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                else:
                    process.kill()
                stdout, stderr = process.communicate()
                self.failed_commands += 1
                
                duration = time.time() - start_time
                
                # Give AI actionable feedback on timeout
                timeout_hints = {
                    "nmap -p-": "Use --top-ports 1000 or -F instead of -p-",
                    "nmap --top-ports": "Scan timed out. Try fewer ports: --top-ports 100 or -F, and add -T4 -Pn",
                    "nmap": "Add -T4 -Pn for speed, or use -F (fast mode) or --top-ports 100",
                    "nikto": "Use nuclei -u URL -severity critical,high instead (faster)",
                    "gobuster": "Use ffuf instead (much faster)",
                    "dirb": "Use ffuf instead (much faster)",
                    "dirsearch": "Use ffuf instead or a smaller wordlist: /usr/share/wordlists/dirb/common.txt",
                    "sqlmap": "Add --threads=10 --batch. With --csrf-url use --threads=1",
                    "hydra": "Use smaller wordlist: /usr/share/wordlists/fasttrack.txt",
                    "whatweb": "Use curl -sI URL instead for quick header check",
                    "amass": "Use assetfinder --subs-only instead (much faster)",
                    "nuclei": "Try targeting specific templates: nuclei -u URL -severity critical,high",
                    "ffuf": "Use smaller wordlist: /usr/share/wordlists/dirb/common.txt",
                }
                
                hint = "Try a faster approach or add timeout flags."
                for pattern, advice in timeout_hints.items():
                    if pattern in command.lower():
                        hint = advice
                        break
                
                result = {
                    "success": False,
                    "output": stdout[:5000] if stdout else "",
                    "error": f"⚠️ TIMEOUT after {timeout}s! {hint}",
                    "return_code": -1,
                    "duration": duration,
                    "command": command
                }
                self._log_command(command, result)
                return result

            duration = time.time() - start_time
            success = process.returncode == 0
            self.current_process = None  # Clear - command finished
            
            if not success:
                self.failed_commands += 1

            # Truncate very large outputs
            max_output = 10000
            if stdout and len(stdout) > max_output:
                stdout = stdout[:max_output] + f"\n\n... [OUTPUT TRUNCATED - {len(stdout)} total chars] ..."
            if stderr and len(stderr) > max_output:
                stderr = stderr[:max_output] + f"\n\n... [ERROR TRUNCATED - {len(stderr)} total chars] ..."

            # === SMART OUTPUT ENHANCEMENT ===
            # Detect failed downloads (wget/curl returned 0 but file is empty)
            output_enhanced = stdout or ""
            if success and ("wget " in command or "curl " in command):
                # Check if this was a download command
                if " -O " in command or " -o " in command:
                    # Try to detect the output file (re and os already imported at top)
                    file_match = re.search(r'-[oO]\s+([^\s]+)', command)
                    if file_match:
                        outfile = file_match.group(1)
                        try:
                            if os.path.exists(outfile):
                                size = os.path.getsize(outfile)
                                if size == 0:
                                    output_enhanced += f"\n⚠️ WARNING: Downloaded file '{outfile}' is EMPTY (0 bytes)! Download failed."
                                    output_enhanced += "\n💡 TIP: Try 'sudo apt-get install -y seclists wordlists' for wordlists."
                                    success = False
                                else:
                                    output_enhanced += f"\n✓ Downloaded '{outfile}' ({size} bytes)"
                        except:
                            pass

            # Detect missing wordlist errors
            all_output_lower = ((stdout or "") + (stderr or "")).lower()
            if "file for passwords not found" in all_output_lower or "file for logins not found" in all_output_lower:
                output_enhanced += "\n💡 TIP: Install wordlists with: sudo apt-get install -y seclists wordlists"
                output_enhanced += "\n💡 TIP: Or gunzip rockyou: sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz"
                output_enhanced += "\n💡 Available wordlists: /usr/share/wordlists/rockyou.txt, /usr/share/wordlists/dirb/common.txt, /usr/share/wordlists/fasttrack.txt"
            
            # Detect file not found errors for any path
            if "no such file or directory" in all_output_lower or "file not found" in all_output_lower:
                output_enhanced += "\n💡 TIP: Check file exists first with: test -f /path/to/file && echo EXISTS || echo MISSING"
            
            # Detect connection refused - tell AI to stop retrying this target
            if "connection refused" in all_output_lower:
                output_enhanced += "\n⚠️ TARGET IS BLOCKING CONNECTIONS. Switch to passive OSINT (whois, dig, crt.sh, wayback) instead of retrying active scans."
            
            # Detect tool not found 
            if "not found" in all_output_lower and ("command not found" in all_output_lower or "/bin/sh" in all_output_lower or "no such file" in all_output_lower):
                tool_name = command.split()[0] if command.split() else "unknown"
                # For script execution, extract the actual failed tool from output
                script_runners = ["bash", "sh", "python3", "python", "/bin/bash", "/bin/sh", "/usr/bin/python3"]
                if tool_name in script_runners:
                    # Parse output to find which tool actually failed
                    import re
                    not_found_match = re.search(r'([a-zA-Z0-9_.-]+):\s*(?:command )?not found', all_output_lower)
                    if not_found_match:
                        tool_name = not_found_match.group(1)
                    else:
                        tool_name = None  # Don't report bash/python as missing
                if tool_name:
                    output_enhanced += f"\n⚠️ Tool '{tool_name}' is NOT installed. Use a different tool instead of trying to install it."

            if "file for passwords is empty" in all_output_lower or "file is empty" in all_output_lower:
                output_enhanced += "\n⚠️ The wordlist file exists but is EMPTY. Download failed or wrong file."
                output_enhanced += "\n💡 TIP: Use system wordlist: /usr/share/wordlists/dirb/common.txt"

            result = {
                "success": success,
                "output": output_enhanced,
                "error": stderr or "",
                "return_code": process.returncode,
                "duration": round(duration, 2),
                "command": command
            }

            self._set_cached_result(command, result)
            self._log_command(command, result)
            return result

        except FileNotFoundError:
            self.failed_commands += 1
            result = {
                "success": False,
                "output": "",
                "error": f"Command not found. Try installing it first.",
                "return_code": 127,
                "duration": 0,
                "command": command
            }
            self._log_command(command, result)
            return result
            
        except Exception as e:
            self.failed_commands += 1
            duration = time.time() - start_time
            result = {
                "success": False,
                "output": "",
                "error": str(e),
                "return_code": -1,
                "duration": round(duration, 2),
                "command": command
            }
            self._log_command(command, result)
            return result

    def _log_command(self, command, result):
        """Log command to history."""
        self.command_history.append({
            "command": command,
            "success": result["success"],
            "return_code": result["return_code"],
            "duration": result["duration"],
            "timestamp": datetime.now().isoformat(),
            "output_preview": result["output"][:200] if result["output"] else ""
        })

    def install_tool(self, tool_name, install_cmd=None):
        """
        Install a security tool.
        
        Args:
            tool_name: Name of the tool
            install_cmd: Custom install command (optional)
        """
        # Common tool install commands
        tool_installs = {
            "nmap": "sudo apt-get install -y nmap",
            "nikto": "sudo apt-get install -y nikto",
            "sqlmap": "sudo apt-get install -y sqlmap",
            "dirb": "sudo apt-get install -y dirb",
            "gobuster": "sudo apt-get install -y gobuster",
            "whatweb": "sudo apt-get install -y whatweb",
            "wpscan": "sudo gem install wpscan",
            "hydra": "sudo apt-get install -y hydra",
            "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
            "dirsearch": "pip3 install dirsearch",
            "wafw00f": "pip3 install wafw00f",
            "sslyze": "pip3 install sslyze",
        }

        cmd = install_cmd or tool_installs.get(tool_name, f"sudo apt-get install -y {tool_name}")
        
        print(f"    [*] Installing {tool_name}...")
        result = self.execute(cmd, timeout=120)
        
        if result["success"]:
            print(f"    [✓] {tool_name} installed successfully")
        else:
            print(f"    [!] Failed to install {tool_name}: {result['error'][:100]}")
        
        return result

    def get_stats(self):
        """Return execution statistics."""
        total_duration = sum(h.get("duration", 0) for h in self.command_history)
        avg_duration = (total_duration / max(len(self.command_history), 1))
        return {
            "total_commands": self.total_commands,
            "failed_commands": self.failed_commands,
            "success_rate": f"{((self.total_commands - self.failed_commands) / max(self.total_commands, 1)) * 100:.1f}%",
            "history_size": len(self.command_history),
            "cache_hits": self.cache_hits,
            "avg_duration": round(avg_duration, 2),
        }
