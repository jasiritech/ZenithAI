"""
Zenith Knowledge Base - Stores everything that has been discovered.
Database of all scanning results and findings.
"""

import json
import os
import re
import time
import tempfile
from datetime import datetime


class KnowledgeBase:
    """
    Knowledge Base - Stores all scanning results and findings.
    The AI reads this to know what has been discovered and choose the next action.
    """

    def __init__(self, target, save_dir=None):
        """Initialize Knowledge Base."""
        self.target = target
        if not save_dir:
            save_dir = os.path.join(tempfile.gettempdir(), "zenith_workspace")
        self.save_dir = save_dir
        os.makedirs(self.save_dir, exist_ok=True)
        
        # Clean target name for filename
        safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', target)
        self.db_file = os.path.join(save_dir, f"{safe_name}_kb.json")
        
        # Load existing or create new
        self.data = self._load() or self._create_default()
        self._save()
        
        print(f"    [✓] Knowledge Base ready: {self.db_file}")

    def _create_default(self):
        """Create default KB structure."""
        return {
            "meta": {
                "target": self.target,
                "start_time": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat(),
                "total_commands_run": 0,
                "current_phase": "recon"
            },
            "target_info": {
                "url": self.target,
                "ip_addresses": [],
                "hostname": "",
                "technologies": [],
                "web_server": "",
                "os_detected": "",
                "cms": "",
                "waf_detected": ""
            },
            "open_ports": [],          # [{"port": 80, "service": "http", "version": "Apache 2.4"}]
            "subdomains": [],          # ["sub1.target.com", ...]
            "directories": [],         # ["/admin", "/login", ...]
            "vulnerabilities": [],     # [{"title": "", "severity": "", "description": "", "evidence": ""}]
            "credentials": [],         # [{"username": "", "password": "", "source": ""}]
            "interesting_files": [],   # [{"path": "", "description": ""}]
            "command_log": [],         # [{"command": "", "output_summary": "", "timestamp": ""}]
            "attack_surface": {
                "forms": [],           # [{"url": "", "method": "", "params": []}]
                "api_endpoints": [],
                "input_points": [],
                "file_uploads": []
            },
            "notes": []               # AI notes to itself
        }

    def _load(self):
        """Load existing KB from file."""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    data = json.load(f)
                print(f"    [*] Loaded existing KB with {len(data.get('command_log', []))} previous commands")
                return data
            except (json.JSONDecodeError, Exception) as e:
                print(f"    [!] KB file corrupted, creating fresh: {e}")
                return None
        return None

    def _save(self):
        """Save KB to file."""
        self.data["meta"]["last_updated"] = datetime.now().isoformat()
        try:
            with open(self.db_file, 'w') as f:
                json.dump(self.data, f, indent=2, default=str)
        except Exception as e:
            print(f"    [!] Failed to save KB: {e}")

    def update_phase(self, new_phase):
        """Update current scanning phase."""
        self.data["meta"]["current_phase"] = new_phase
        self._save()

    def add_port(self, port, service="", version="", protocol="tcp"):
        """Add discovered open port."""
        port_entry = {"port": port, "service": service, "version": version, "protocol": protocol}
        if not any(p["port"] == port and p["protocol"] == protocol for p in self.data["open_ports"]):
            self.data["open_ports"].append(port_entry)
            self._save()

    def add_subdomain(self, subdomain):
        """Add discovered subdomain."""
        if subdomain and subdomain not in self.data["subdomains"]:
            self.data["subdomains"].append(subdomain)
            self._save()

    def add_directory(self, directory):
        """Add discovered directory."""
        if directory and directory not in self.data["directories"]:
            self.data["directories"].append(directory)
            self._save()

    def add_vulnerability(self, title, severity="MEDIUM", description="", evidence=""):
        """Add discovered vulnerability."""
        vuln = {
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence[:500],  # Limit evidence size
            "discovered_at": datetime.now().isoformat()
        }
        # Deduplicate by title
        if not any(v["title"] == title for v in self.data["vulnerabilities"]):
            self.data["vulnerabilities"].append(vuln)
            self._save()

    def add_technology(self, tech):
        """Add detected technology."""
        if tech and tech not in self.data["target_info"]["technologies"]:
            self.data["target_info"]["technologies"].append(tech)
            self._save()

    def add_credential(self, username, password, source=""):
        """Add discovered credential."""
        cred = {"username": username, "password": password, "source": source}
        if cred not in self.data["credentials"]:
            self.data["credentials"].append(cred)
            self._save()

    def log_command(self, command, output, success=True):
        """Log executed command and its output."""
        self.data["meta"]["total_commands_run"] += 1
        
        # Keep output summary short for KB context
        output_summary = output[:500] if output else ""
        
        self.data["command_log"].append({
            "command": command,
            "output_summary": output_summary,
            "success": success,
            "timestamp": datetime.now().isoformat()
        })
        
        # Auto-parse common outputs
        self._auto_parse(command, output)
        self._save()

    def _auto_parse(self, command, output):
        """Automatically parse common tool outputs to extract data."""
        if not output:
            return

        # Parse nmap output
        if "nmap" in command.lower():
            # Extract ports
            port_pattern = re.findall(r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?', output)
            for port, proto, service, version in port_pattern:
                self.add_port(int(port), service, version.strip() if version else "", proto)
            
            # Extract OS
            os_match = re.search(r'OS details?:\s*(.+)', output)
            if os_match:
                self.data["target_info"]["os_detected"] = os_match.group(1).strip()

            # Extract IP
            ip_match = re.search(r'Nmap scan report for .*?(\d+\.\d+\.\d+\.\d+)', output)
            if ip_match:
                ip = ip_match.group(1)
                if ip not in self.data["target_info"]["ip_addresses"]:
                    self.data["target_info"]["ip_addresses"].append(ip)

        # Parse whatweb output
        if "whatweb" in command.lower():
            tech_patterns = re.findall(r'\[(\S+)\]', output)
            for tech in tech_patterns:
                if tech not in ['200', '301', '302', '403', '404', '500']:
                    self.add_technology(tech)

        # Parse gobuster/dirb/dirsearch output
        if any(tool in command.lower() for tool in ["gobuster", "dirb", "dirsearch", "ffuf"]):
            dir_patterns = re.findall(r'(/\S+)\s+.*?(?:Status|Code):\s*(\d+)', output)
            for directory, status in dir_patterns:
                if status in ['200', '301', '302', '403']:
                    self.add_directory(f"{directory} [{status}]")

        # Parse nuclei output
        if "nuclei" in command.lower():
            vuln_patterns = re.findall(r'\[(\w+)\]\s+\[([^\]]+)\]\s+(.+)', output)
            for severity, template, detail in vuln_patterns:
                self.add_vulnerability(
                    title=template,
                    severity=severity.upper(),
                    description=detail.strip(),
                    evidence=f"Nuclei template: {template}"
                )

    def add_note(self, note):
        """AI adds a note to itself."""
        self.data["notes"].append({
            "note": note,
            "timestamp": datetime.now().isoformat()
        })
        self._save()

    def get_context(self):
        """
        Get KB context for AI. Returns a summarized version to save tokens.
        """
        # Create a compact version for AI consumption
        context = {
            "target": self.data["target_info"],
            "phase": self.data["meta"]["current_phase"],
            "commands_run": self.data["meta"]["total_commands_run"],
            "open_ports": self.data["open_ports"],
            "subdomains": self.data["subdomains"][:20],  # Limit
            "directories": self.data["directories"][:30],
            "vulnerabilities": self.data["vulnerabilities"],
            "technologies": self.data["target_info"]["technologies"],
            "credentials": self.data["credentials"],
            "recent_commands": self.data["command_log"][-10:],  # Last 10 commands
            "notes": self.data["notes"][-5:],
            "attack_surface": self.data["attack_surface"]
        }
        return context

    def get_full_data(self):
        """Get complete KB data."""
        return self.data

    def get_vulnerability_count(self):
        """Count vulnerabilities by severity."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for vuln in self.data["vulnerabilities"]:
            sev = vuln.get("severity", "INFO").upper()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["INFO"] += 1
        return counts

    def export_report(self, filename=None):
        """Export full KB as JSON report."""
        if not filename:
            safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', self.target)
            filename = os.path.join(self.save_dir, f"{safe_name}_report.json")
        
        report = {
            "report_info": {
                "tool": "Zenith AI Security Scanner v2.0",
                "target": self.target,
                "generated_at": datetime.now().isoformat(),
                "total_commands": self.data["meta"]["total_commands_run"],
                "duration": "See timestamps in command_log"
            },
            "findings": self.data
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return filename
