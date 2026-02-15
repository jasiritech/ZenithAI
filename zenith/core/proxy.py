"""
Zenith Proxy Manager - Route traffic through proxies, Tor, or proxy chains.
Provides anonymity and helps bypass IP-based blocking.
"""

import os
import subprocess
import shutil


class ProxyManager:
    """
    Manages proxy settings for scanning tools.
    Supports HTTP/SOCKS proxies, Tor, and proxychains.
    """

    def __init__(self, config=None):
        """
        Initialize proxy manager.
        
        Args:
            config: Dict with proxy settings. Example:
                {
                    "type": "tor",            # "tor", "http", "socks5", "proxychains"
                    "host": "127.0.0.1",
                    "port": 9050,
                    "username": "",           # For authenticated proxies
                    "password": "",
                    "verify_connection": True  # Check proxy works before scanning
                }
        """
        self.config = config or {}
        self.proxy_type = self.config.get("type", "none").lower()
        self.host = self.config.get("host", "127.0.0.1")
        self.port = self.config.get("port", 9050)
        self.username = self.config.get("username", "")
        self.password = self.config.get("password", "")
        self.enabled = self.proxy_type != "none" and bool(self.config)
        self.verified = False

    @classmethod
    def from_env(cls):
        """Create proxy manager from environment variables."""
        proxy_type = os.environ.get("ZENITH_PROXY_TYPE", "none")
        if proxy_type == "none":
            return cls()
        
        return cls({
            "type": proxy_type,
            "host": os.environ.get("ZENITH_PROXY_HOST", "127.0.0.1"),
            "port": int(os.environ.get("ZENITH_PROXY_PORT", "9050")),
            "username": os.environ.get("ZENITH_PROXY_USER", ""),
            "password": os.environ.get("ZENITH_PROXY_PASS", ""),
        })

    def get_proxy_url(self):
        """Get the proxy URL string."""
        if not self.enabled:
            return None
        
        auth = ""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"
        
        if self.proxy_type in ("tor", "socks5"):
            return f"socks5://{auth}{self.host}:{self.port}"
        elif self.proxy_type == "socks4":
            return f"socks4://{auth}{self.host}:{self.port}"
        elif self.proxy_type == "http":
            return f"http://{auth}{self.host}:{self.port}"
        
        return None

    def get_env_vars(self):
        """Get environment variables to set for proxied commands."""
        if not self.enabled:
            return {}
        
        proxy_url = self.get_proxy_url()
        if not proxy_url:
            return {}
        
        return {
            "http_proxy": proxy_url,
            "https_proxy": proxy_url,
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "ALL_PROXY": proxy_url,
        }

    def wrap_command(self, command):
        """
        Wrap a command to route through proxy.
        
        Args:
            command: Original command string
            
        Returns:
            str: Proxied command
        """
        if not self.enabled:
            return command
        
        if self.proxy_type == "proxychains":
            # Use proxychains4 or proxychains
            pc = "proxychains4" if shutil.which("proxychains4") else "proxychains"
            if shutil.which(pc):
                return f"{pc} -q {command}"
            else:
                return command
        
        elif self.proxy_type == "tor":
            # Use torsocks if available, otherwise set proxy env
            if shutil.which("torsocks"):
                return f"torsocks {command}"
            else:
                # Fall back to proxychains
                pc = "proxychains4" if shutil.which("proxychains4") else "proxychains"
                if shutil.which(pc):
                    return f"{pc} -q {command}"
                return command
        
        else:
            # For HTTP/SOCKS proxies, many tools support --proxy flag
            proxy_url = self.get_proxy_url()
            cmd_base = command.split()[0] if command.split() else ""
            
            # Tools with native proxy support
            proxy_flags = {
                "curl": f"--proxy {proxy_url}",
                "wget": f"-e use_proxy=yes -e http_proxy={proxy_url}",
                "sqlmap": f"--proxy={proxy_url}",
                "nikto": f"-useproxy {proxy_url}",
                "nuclei": f"-proxy {proxy_url}",
                "gobuster": f"--proxy {proxy_url}",
                "wpscan": f"--proxy {proxy_url}",
                "ffuf": f"-x {proxy_url}",
                "httpx": f"-proxy {proxy_url}",
            }
            
            if cmd_base in proxy_flags:
                return f"{command} {proxy_flags[cmd_base]}"
            
            # For tools without proxy support, try proxychains
            pc = "proxychains4" if shutil.which("proxychains4") else "proxychains"
            if shutil.which(pc):
                return f"{pc} -q {command}"
            
            return command

    def verify(self):
        """
        Verify the proxy connection works.
        
        Returns:
            tuple: (success: bool, message: str)
        """
        if not self.enabled:
            return True, "No proxy configured"
        
        try:
            proxy_url = self.get_proxy_url()
            if not proxy_url:
                return False, "Invalid proxy configuration"

            # Try to connect through the proxy
            test_cmd = f'curl -s --max-time 15 --proxy {proxy_url} https://check.torproject.org/api/ip 2>/dev/null || curl -s --max-time 15 --proxy {proxy_url} https://api.ipify.org?format=json 2>/dev/null'
            
            result = subprocess.run(
                test_cmd, shell=True, capture_output=True, text=True, timeout=20
            )
            
            if result.returncode == 0 and result.stdout.strip():
                self.verified = True
                return True, f"Proxy working. External IP: {result.stdout.strip()[:100]}"
            else:
                return False, f"Proxy connection failed: {result.stderr[:200]}"
                
        except subprocess.TimeoutExpired:
            return False, "Proxy verification timed out"
        except Exception as e:
            return False, f"Proxy verification error: {str(e)}"

    def setup_tor(self):
        """
        Ensure Tor is installed and running.
        
        Returns:
            tuple: (success: bool, message: str)
        """
        try:
            # Check if tor is installed
            if not shutil.which("tor"):
                result = subprocess.run(
                    "sudo apt-get install -y tor", shell=True,
                    capture_output=True, text=True, timeout=120
                )
                if result.returncode != 0:
                    return False, "Failed to install Tor"
            
            # Start tor service
            subprocess.run(
                "sudo systemctl start tor", shell=True,
                capture_output=True, text=True, timeout=30
            )
            
            # Also install torsocks
            if not shutil.which("torsocks"):
                subprocess.run(
                    "sudo apt-get install -y torsocks", shell=True,
                    capture_output=True, text=True, timeout=60
                )
            
            self.enabled = True
            self.proxy_type = "tor"
            self.host = "127.0.0.1"
            self.port = 9050
            
            return True, "Tor installed and started"
            
        except Exception as e:
            return False, f"Tor setup failed: {str(e)}"

    def get_status(self):
        """Get proxy status summary."""
        if not self.enabled:
            return "🔓 Direct connection (no proxy)"
        
        status = f"🔒 Proxy: {self.proxy_type.upper()} → {self.host}:{self.port}"
        if self.verified:
            status += " ✅"
        else:
            status += " ⚠️ (not verified)"
        return status
