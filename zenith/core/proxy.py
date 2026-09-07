"""
Zenith Proxy Manager - Route traffic through proxies, Tor, or proxy chains.
Provides anonymity and helps bypass IP-based blocking.

Supports auto-detection of local Tor SOCKS proxy on anonymous VPS setups,
global Python socket monkey-patching via PySocks, and environment variable
injection for subprocess commands.
"""

import os
import socket
import subprocess
import shutil


# Track whether PySocks monkey-patch has been applied globally
_GLOBAL_PROXY_INSTALLED = False
_ORIGINAL_SOCKET = None


class ProxyManager:
    """
    Manages proxy settings for scanning tools.
    Supports HTTP/SOCKS proxies, Tor, and proxychains.
    
    On anonymous VPS setups (Tor + iptables), this class:
    1. Auto-detects the local Tor SOCKS5 proxy (127.0.0.1:9050)
    2. Monkey-patches Python's socket module via PySocks so ALL HTTP calls
       (urllib, requests, aiohttp) automatically route through the proxy
    3. Provides env vars for subprocess-spawned tools
    4. Wraps external commands with torsocks/proxychains
    """

    def __init__(self, config=None):
        """
        Initialize proxy manager.
        
        Args:
            config: Dict with proxy settings. Example:
                {
                    "type": "tor",            # "tor", "http", "socks5", "proxychains", "auto"
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
        self._global_installed = False

        # Handle "auto" type: detect local Tor/SOCKS
        if self.proxy_type == "auto":
            detected = self._auto_detect()
            if detected:
                self.enabled = True
            else:
                self.enabled = False
                self.proxy_type = "none"

    @classmethod
    def auto_detect(cls):
        """Factory: create a ProxyManager that auto-detects local proxy.
        
        Detection order:
        1. Tor SOCKS5 on 127.0.0.1:9050
        2. SOCKS5 on 127.0.0.1:1080 (common default)
        3. Environment variables (ALL_PROXY, http_proxy, etc.)
        4. No proxy
        """
        instance = cls.__new__(cls)
        instance.config = {}
        instance.proxy_type = "none"
        instance.host = "127.0.0.1"
        instance.port = 9050
        instance.username = ""
        instance.password = ""
        instance.enabled = False
        instance.verified = False
        instance._global_installed = False
        
        detected = instance._auto_detect()
        if detected:
            instance.enabled = True
        return instance

    def _auto_detect(self):
        """Auto-detect local proxy (Tor SOCKS, env vars, etc.)."""
        # 1. Check if Tor SOCKS5 is listening on 127.0.0.1:9050
        if self._port_open("127.0.0.1", 9050):
            self.proxy_type = "tor"
            self.host = "127.0.0.1"
            self.port = 9050
            return True
        
        # 2. Check common SOCKS5 port 1080
        if self._port_open("127.0.0.1", 1080):
            self.proxy_type = "socks5"
            self.host = "127.0.0.1"
            self.port = 1080
            return True
        
        # 3. Check environment variables
        env_proxy = (os.environ.get("ALL_PROXY") or 
                     os.environ.get("all_proxy") or 
                     os.environ.get("HTTPS_PROXY") or 
                     os.environ.get("https_proxy") or
                     os.environ.get("HTTP_PROXY") or
                     os.environ.get("http_proxy"))
        if env_proxy:
            return self._parse_proxy_url(env_proxy)
        
        return False

    def _port_open(self, host, port, timeout=2):
        """Check if a TCP port is open."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((host, port)) == 0
        except (socket.error, OSError):
            return False

    def _parse_proxy_url(self, url):
        """Parse a proxy URL (socks5://host:port) into config."""
        url = url.strip()
        if "socks5" in url.lower():
            self.proxy_type = "socks5"
        elif "socks4" in url.lower():
            self.proxy_type = "socks4"
        elif "http" in url.lower():
            self.proxy_type = "http"
        else:
            return False
        
        # Extract host:port from URL
        try:
            clean = url.split("://", 1)[-1]  # Remove scheme
            clean = clean.split("@")[-1]      # Remove auth
            parts = clean.split(":")
            self.host = parts[0] if parts[0] else "127.0.0.1"
            self.port = int(parts[1]) if len(parts) > 1 else 9050
            return True
        except (ValueError, IndexError):
            return False

    @classmethod
    def from_env(cls):
        """Create proxy manager from environment variables, or auto-detect."""
        proxy_type = os.environ.get("ZENITH_PROXY_TYPE", "").lower()
        
        if proxy_type and proxy_type != "none":
            return cls({
                "type": proxy_type,
                "host": os.environ.get("ZENITH_PROXY_HOST", "127.0.0.1"),
                "port": int(os.environ.get("ZENITH_PROXY_PORT", "9050")),
                "username": os.environ.get("ZENITH_PROXY_USER", ""),
                "password": os.environ.get("ZENITH_PROXY_PASS", ""),
            })
        
        # Auto-detect if no explicit config
        return cls.auto_detect()

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

    def get_socks5h_url(self):
        """Get socks5h:// URL (DNS resolution through proxy - best for Tor)."""
        if not self.enabled:
            return None
        auth = ""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"
        if self.proxy_type in ("tor", "socks5"):
            return f"socks5h://{auth}{self.host}:{self.port}"
        return self.get_proxy_url()

    def get_env_vars(self):
        """Get environment variables to set for proxied commands."""
        if not self.enabled:
            return {}
        
        proxy_url = self.get_socks5h_url() or self.get_proxy_url()
        if not proxy_url:
            return {}
        
        return {
            "http_proxy": proxy_url,
            "https_proxy": proxy_url,
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "ALL_PROXY": proxy_url,
        }

    def get_requests_proxies(self):
        """Get proxy dict for the `requests` library."""
        if not self.enabled:
            return None
        proxy_url = self.get_socks5h_url() or self.get_proxy_url()
        if not proxy_url:
            return None
        return {
            "http": proxy_url,
            "https": proxy_url,
        }

    def install_global_proxy(self):
        """
        Install SOCKS proxy globally into Python's socket layer via PySocks.
        
        After calling this, ALL Python HTTP calls (urllib.request.urlopen,
        requests.get, aiohttp, etc.) will automatically route through the
        SOCKS proxy WITHOUT any code changes in the calling modules.
        
        This is the KEY method for making ZenithAI work on anonymous VPS
        setups where all outbound traffic must go through Tor.
        
        Returns:
            tuple: (success: bool, message: str)
        """
        global _GLOBAL_PROXY_INSTALLED, _ORIGINAL_SOCKET
        
        if not self.enabled:
            return True, "No proxy to install globally"
        
        if _GLOBAL_PROXY_INSTALLED:
            return True, "Global proxy already installed"
        
        try:
            import socks as pysocks
        except ImportError:
            return False, (
                "PySocks not installed! Run: pip install PySocks\n"
                "This is required for SOCKS proxy support on anonymous VPS."
            )
        
        # Map proxy type to PySocks constant
        socks_type_map = {
            "tor": pysocks.SOCKS5,
            "socks5": pysocks.SOCKS5,
            "socks4": pysocks.SOCKS4,
            "http": pysocks.HTTP,
        }
        socks_type = socks_type_map.get(self.proxy_type)
        if not socks_type:
            return False, f"Unsupported proxy type for global install: {self.proxy_type}"
        
        # Save original socket class for restore
        _ORIGINAL_SOCKET = socket.socket
        
        # Set default proxy for ALL sockets
        pysocks.set_default_proxy(
            socks_type,
            self.host,
            self.port,
            rdns=True,  # Resolve DNS through proxy (important for Tor!)
            username=self.username or None,
            password=self.password or None,
        )
        
        # Monkey-patch socket.socket -> socks.socksocket
        socket.socket = pysocks.socksocket
        
        _GLOBAL_PROXY_INSTALLED = True
        self._global_installed = True
        
        # Also set environment variables for subprocess calls
        proxy_url = self.get_socks5h_url() or self.get_proxy_url()
        if proxy_url:
            os.environ["ALL_PROXY"] = proxy_url
            os.environ["http_proxy"] = proxy_url
            os.environ["https_proxy"] = proxy_url
            os.environ["HTTP_PROXY"] = proxy_url
            os.environ["HTTPS_PROXY"] = proxy_url
        
        return True, (
            f"Global SOCKS proxy installed: {self.proxy_type.upper()} "
            f"-> {self.host}:{self.port} (DNS via proxy: ON)"
        )

    def uninstall_global_proxy(self):
        """Restore original socket (remove global proxy monkey-patch)."""
        global _GLOBAL_PROXY_INSTALLED, _ORIGINAL_SOCKET
        
        if _ORIGINAL_SOCKET is not None:
            socket.socket = _ORIGINAL_SOCKET
            _ORIGINAL_SOCKET = None
        
        _GLOBAL_PROXY_INSTALLED = False
        self._global_installed = False
        
        # Clear proxy env vars
        for var in ("ALL_PROXY", "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
            os.environ.pop(var, None)

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
        
        # PREVENT DOUBLE WRAPPING: if AI already included proxychains/torsocks, skip
        cmd_lower = command.strip().lower()
        if cmd_lower.startswith("proxychains") or cmd_lower.startswith("torsocks"):
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
        
        # --- Strategy 1: Use PySocks directly (fastest, no subprocess) ---
        try:
            import socks as pysocks
            test_sock = pysocks.socksocket()
            socks_type = pysocks.SOCKS5 if self.proxy_type in ("tor", "socks5") else pysocks.HTTP
            test_sock.set_proxy(socks_type, self.host, self.port)
            test_sock.settimeout(10)
            test_sock.connect(("check.torproject.org", 443))
            test_sock.close()
            self.verified = True
            return True, f"Proxy working: {self.proxy_type.upper()} -> {self.host}:{self.port}"
        except ImportError:
            pass  # PySocks not available, fall back
        except Exception:
            pass  # Connection failed, try curl
        
        # --- Strategy 2: Use curl with --proxy ---
        try:
            proxy_url = self.get_proxy_url()
            if not proxy_url:
                return False, "Invalid proxy configuration"

            test_cmd = (
                f'curl -s --max-time 15 --proxy {proxy_url} '
                f'https://check.torproject.org/api/ip 2>/dev/null || '
                f'curl -s --max-time 15 --proxy {proxy_url} '
                f'https://api.ipify.org?format=json 2>/dev/null'
            )
            
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
        
        status = f"🔒 Proxy: {self.proxy_type.upper()} -> {self.host}:{self.port}"
        if self.verified:
            status += " ✅"
        elif self._global_installed:
            status += " 🌐 (global)"
        else:
            status += " ⚠️ (not verified)"
        return status
