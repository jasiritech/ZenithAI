import json
    import os

    class KnowledgeBase:
        def __init__(self, target_name):
            self.target_name = target_name
            self.db_file = f"{target_name}_kb.json"
            self.data = self._load_data()

        def _load_data(self):
            if os.path.exists(self.db_file):
                try:
                    with open(self.db_file, 'r') as f:
                        return json.load(f)
                except json.JSONDecodeError:
                    print(f"Warning: {self.db_file} is corrupted, starting fresh.")
                    return self._default_structure()
            return self._default_structure()

        def _default_structure(self):
            return {
                "target_info": {"initial_target_url": "", "target_hostname": ""},
                "discovered_assets": {
                    "ips": [], "domains": [], "subdomains": [], "urls": [], "ports": [],
                    "cloud_resources": {"aws": [], "azure": [], "gcp": []}
                },
                "vulnerabilities": [], # {"cve": "", "severity": "", "description": "", "exploit_path": ""}
                "credentials": [], # {"username": "", "password": "", "hash": "", "source": ""}
                "users": [], # {"username": "", "uid": "", "privileges": ""}
                "files_of_interest": [], # {"path": "", "content_snippet": "", "type": ""}
                "attack_paths": [], # {"from": "", "to": "", "method": "", "status": "pending/executed/success"}
                "command_history": [] # {"command": "", "output": "", "timestamp": ""}
            }

        def _save_data(self):
            with open(self.db_file, 'w') as f:
                json.dump(self.data, f, indent=4)

        def add_target_info(self, key, value):
            self.data["target_info"][key] = value
            self._save_data()

        def add_discovered_asset(self, type, value):
            if type in self.data["discovered_assets"] and value not in self.data["discovered_assets"][type]:
                self.data["discovered_assets"][type].append(value)
                self._save_data()

        def add_vulnerability(self, vuln_details):
            if vuln_details not in self.data["vulnerabilities"]: # Simple deduplication
                self.data["vulnerabilities"].append(vuln_details)
                self._save_data()

        def add_credential(self, cred_details):
            if cred_details not in self.data["credentials"]:
                self.data["credentials"].append(cred_details)
                self._save_data()
        
        def add_user(self, user_details):
            if user_details not in self.data["users"]:
                self.data["users"].append(user_details)
                self._save_data()

        def add_command_to_history(self, command, output):
            self.data["command_history"].append({"command": command, "output": output, "timestamp": time.time()})
            self._save_data()

        def get_full_context(self):
            return self.data # Return raw dict for AI to parse/dump

        # New method for AI-driven parsing and update
        def parse_and_update(self, command, output):
            self.add_command_to_history(command, output)
            
            # This logic would ideally be handled by the AI itself,
            # but for a conceptual framework, we can add some basic parsing here.
            # In a real setup, AI would be prompted: "Parse this output and update the KB."

            # Example: Nmap output parsing
            if "nmap" in command and "open" in output:
                import re
                ip_match = re.search(r'Nmap scan report for ([\d.]+)', output)
                if ip_match:
                    self.add_discovered_asset("ips", ip_match.group(1))
                
                port_matches = re.findall(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(\S+)', output)
                for port, proto, service, version in port_matches:
                    self.add_discovered_asset("ports", {"port": int(port), "protocol": proto, "service": service, "version": version})
            
            # Example: Sqlmap output parsing
            if "sqlmap" in command and "available databases" in output:
                db_matches = re.findall(r"\'([a-zA-Z0-9_]+)\'", output)
                for db in db_matches:
                    self.add_target_info("discovered_database", db)
            
            if "sqlmap" in command and "--dump" in command and "password" in output:
                lines = output.split('\n')
                for line in lines:
                    if "|" in line and "admin" in line: # Simplified parsing
                        parts = [p.strip() for p in line.split('|') if p.strip()]
                        if len(parts) >= 3:
                            self.add_credential({"username": parts[1], "password_hash": parts[2], "source": "sqlmap_dump"})
            
            # Example: LinPEAS output parsing
            if "linpeas.sh" in command and "SUID" in output:
                suid_matches = re.findall(r'SUID - (.+)', output)
                for suid_bin in suid_matches:
                    self.add_vulnerability({"type": "SUID_Binary", "path": suid_bin, "potential_exploit": "GTFOBins"})
            
            self._save_data()