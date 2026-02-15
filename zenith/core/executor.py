"""
Zenith Terminal Executor - Runs commands on the Linux shell safely.
"""

import subprocess
import shlex
import time
import os
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

    def __init__(self, working_dir="/tmp/zenith_workspace", sudo_password=None):
        """Initialize Terminal Executor."""
        self.working_dir = working_dir
        self.command_history = []
        self.total_commands = 0
        self.failed_commands = 0
        self.current_process = None  # Track running subprocess for Ctrl+C kill
        self.sudo_password = sudo_password  # Optional sudo password for automated execution
        
        # Create working directory
        os.makedirs(working_dir, exist_ok=True)
        
        print(f"    [✓] Terminal Executor ready (workspace: {working_dir})")
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

    # Smart timeouts per command type (seconds)
    COMMAND_TIMEOUTS = {
        "nmap": 180,           # 3 minutes for normal nmap
        "nmap -p-": 300,       # 5 minutes for full port scan (not forever)
        "nmap -sV -p-": 300,   # 5 minutes max
        "nikto": 180,
        "sqlmap": 240,
        "nuclei": 240,
        "gobuster": 180,
        "dirb": 180,
        "ffuf": 180,
        "hydra": 180,
        "subfinder": 120,
        "whatweb": 60,
        "whois": 30,
        "dig": 30,
        "curl": 60,
        "wget": 120,
        "wpscan": 240,
    }

    def _get_smart_timeout(self, command):
        """Get a smart timeout based on the command being run."""
        cmd_lower = command.lower().strip()
        # Check specific patterns first (longer matches)
        for pattern in sorted(self.COMMAND_TIMEOUTS.keys(), key=len, reverse=True):
            if pattern in cmd_lower:
                return self.COMMAND_TIMEOUTS[pattern]
        return 300  # Default 5 minutes

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
                result = {
                    "success": False,
                    "output": stdout[:5000] if stdout else "",
                    "error": f"TIMEOUT after {timeout}s. Partial output collected.",
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

            result = {
                "success": success,
                "output": stdout or "",
                "error": stderr or "",
                "return_code": process.returncode,
                "duration": round(duration, 2),
                "command": command
            }

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
        return {
            "total_commands": self.total_commands,
            "failed_commands": self.failed_commands,
            "success_rate": f"{((self.total_commands - self.failed_commands) / max(self.total_commands, 1)) * 100:.1f}%",
            "history_size": len(self.command_history)
        }
