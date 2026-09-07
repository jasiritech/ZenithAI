"""
Nmap Parser - Converts nmap output (XML and grepable) into structured port/service dicts.
"""

import re
from typing import Dict, List, Optional


class NmapParser:
    """
    Parse nmap output in three formats:
      - XML (-oX or -oX -)
      - Grepable (-oG or default terminal output)
      - JSON-like service banners
    """

    @staticmethod
    def parse(output: str) -> List[Dict]:
        """
        Auto-detect format and parse.

        Returns:
            List of port dicts:
            [{"port": 80, "service": "http", "version": "Apache 2.4.50",
              "state": "open", "protocol": "tcp", "cpe": "...", "scripts": [...]}]
        """
        if output.strip().startswith("<?xml") or "<nmaprun" in output:
            return NmapParser._parse_xml(output)
        return NmapParser._parse_text(output)

    # ──────────────────────────────────────────────
    # XML parser
    # ──────────────────────────────────────────────

    @staticmethod
    def _parse_xml(xml: str) -> List[Dict]:
        ports = []
        host_ip = ""
        m = re.search(r'<address addr="([^"]+)"', xml)
        if m:
            host_ip = m.group(1)

        for port_block in re.finditer(
            r'<port protocol="([^"]*)" portid="(\d+)">(.*?)</port>',
            xml, re.DOTALL
        ):
            protocol = port_block.group(1)
            port_num = int(port_block.group(2))
            body     = port_block.group(3)

            state_m  = re.search(r'<state state="([^"]*)"', body)
            state    = state_m.group(1) if state_m else "unknown"
            if state != "open":
                continue

            svc_m    = re.search(
                r'<service name="([^"]*)"([^/]*/)?([^>]*product="([^"]*)")?'
                r'([^>]*version="([^"]*)")?([^>]*extrainfo="([^"]*)")?',
                body
            )
            service  = svc_m.group(1) if svc_m else "unknown"
            product  = svc_m.group(4) if svc_m and svc_m.group(4) else ""
            version  = svc_m.group(6) if svc_m and svc_m.group(6) else ""
            extra    = svc_m.group(8) if svc_m and svc_m.group(8) else ""
            full_ver = " ".join(filter(None, [product, version, extra])).strip()

            cpe_m    = re.search(r'<cpe>([^<]+)</cpe>', body)
            cpe      = cpe_m.group(1) if cpe_m else ""

            scripts = []
            for sm in re.finditer(
                r'<script id="([^"]*)" output="([^"]*)"', body
            ):
                scripts.append({"id": sm.group(1), "output": sm.group(2)[:200]})

            ports.append({
                "port":     port_num,
                "protocol": protocol,
                "state":    state,
                "service":  service,
                "version":  full_ver,
                "cpe":      cpe,
                "scripts":  scripts,
                "ip":       host_ip,
            })

        return ports

    # ──────────────────────────────────────────────
    # Text / grepable parser
    # ──────────────────────────────────────────────

    @staticmethod
    def _parse_text(text: str) -> List[Dict]:
        ports = []

        # Standard nmap line: "80/tcp   open  http    Apache httpd 2.4.50"
        for line in text.splitlines():
            # Grepable format: "Ports: 80/open/tcp//http//Apache/"
            g = re.findall(r'(\d+)/open/(\w+)//([^/]*)//([^/]*)', line)
            if g:
                for port_num, proto, svc, ver in g:
                    ports.append({
                        "port":     int(port_num),
                        "protocol": proto,
                        "state":    "open",
                        "service":  svc.strip(),
                        "version":  ver.strip(),
                        "cpe":      "",
                        "scripts":  [],
                    })
                continue

            # Normal output format
            m = re.match(
                r'\s*(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?', line
            )
            if m:
                ports.append({
                    "port":     int(m.group(1)),
                    "protocol": m.group(2),
                    "state":    "open",
                    "service":  m.group(3),
                    "version":  (m.group(4) or "").strip(),
                    "cpe":      "",
                    "scripts":  [],
                })

        return ports

    @staticmethod
    def get_risky_services(ports: List[Dict]) -> List[Dict]:
        """Flag ports known to be high-risk."""
        risky = {
            21:   ("FTP - plaintext credentials", "MEDIUM"),
            23:   ("Telnet - plaintext remote access", "HIGH"),
            69:   ("TFTP - unauthenticated file access", "HIGH"),
            139:  ("NetBIOS - potential SMB exposure", "MEDIUM"),
            445:  ("SMB - EternalBlue/ransomware risk", "HIGH"),
            512:  ("rexec - unauthenticated exec", "CRITICAL"),
            513:  ("rlogin - unauthenticated login", "CRITICAL"),
            514:  ("rsh - remote shell no auth", "CRITICAL"),
            1433: ("MSSQL exposed to network", "HIGH"),
            1521: ("Oracle DB exposed to network", "HIGH"),
            2375: ("Docker API (unauth) exposed", "CRITICAL"),
            3306: ("MySQL exposed to network", "HIGH"),
            3389: ("RDP - brute force risk", "HIGH"),
            5432: ("PostgreSQL exposed", "HIGH"),
            5900: ("VNC - GUI remote access", "HIGH"),
            6379: ("Redis (unauthenticated)", "CRITICAL"),
            27017:("MongoDB (unauthenticated)", "CRITICAL"),
        }
        results = []
        for p in ports:
            port_num = p.get("port")
            if port_num in risky:
                desc, sev = risky[port_num]
                results.append({
                    "port":        port_num,
                    "service":     p.get("service", ""),
                    "version":     p.get("version", ""),
                    "risk":        desc,
                    "severity":    sev,
                })
        return results
