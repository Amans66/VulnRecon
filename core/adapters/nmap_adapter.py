"""
Nmap Network & Service Discovery Adapter v6.0.

Executes Nmap via subprocess, uses machine-readable XML output (-oX),
and populates Sentinel's Attack Surface Graph.
"""

import os
import xml.etree.ElementTree as ET
import subprocess
from urllib.parse import urlparse
from core.adapters.base_adapter import BaseToolAdapter
from core.tool_manager import ExternalToolManager
from core.plugin_base import Finding


class NmapAdapter(BaseToolAdapter):
    """Nmap network scanner adapter."""

    def __init__(self):
        super().__init__("Nmap", "nmap")
        self.manager = ExternalToolManager()

    def check_available(self) -> bool:
        status = self.manager.detect_tool("nmap")
        return status.installed

    def get_version(self) -> str:
        return self.manager.detect_tool("nmap").version

    def run(self, target: str, options: dict = None) -> dict:
        """Run Nmap scan with XML output."""
        status = self.manager.detect_tool("nmap")
        if not status.installed:
            return {"error": "Nmap is not installed", "raw_xml": ""}

        parsed = urlparse(target)
        host = parsed.netloc.split(":")[0] if parsed.netloc else target

        xml_out_path = os.path.join("results", f"nmap_{host}.xml")
        os.makedirs("results", exist_ok=True)

        cmd = [
            status.location,
            "-sV", "-T4", "--top-ports", "100",
            "-oX", xml_out_path,
            host
        ]

        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
            if os.path.exists(xml_out_path):
                with open(xml_out_path, "r", encoding="utf-8") as f:
                    xml_content = f.read()
                return {"xml_path": xml_out_path, "raw_xml": xml_content}
        except Exception as e:
            return {"error": str(e), "raw_xml": ""}

        return {"error": "Nmap run failed", "raw_xml": ""}

    def parse_results(self, raw_output: dict) -> list:
        """Parse Nmap XML output into service lists."""
        raw_xml = raw_output.get("raw_xml", "")
        if not raw_xml:
            return []

        services = []
        try:
            root = ET.fromstring(raw_xml)
            for host in root.findall("host"):
                address = host.find("address").attrib.get("addr", "") if host.find("address") is not None else ""
                ports = host.find("ports")
                if ports is not None:
                    for port in ports.findall("port"):
                        port_id = port.attrib.get("portid", "")
                        protocol = port.attrib.get("protocol", "tcp")
                        state = port.find("state").attrib.get("state", "") if port.find("state") is not None else ""
                        service_elem = port.find("service")
                        service_name = service_elem.attrib.get("name", "unknown") if service_elem is not None else "unknown"
                        product = service_elem.attrib.get("product", "") if service_elem is not None else ""
                        version = service_elem.attrib.get("version", "") if service_elem is not None else ""

                        if state == "open":
                            services.append({
                                "host": address,
                                "port": port_id,
                                "protocol": protocol,
                                "service": service_name,
                                "product": product,
                                "version": version,
                            })
        except Exception:
            pass
        return services

    def normalize_results(self, parsed_findings: list) -> List[Finding]:
        """Convert Nmap services into Finding objects for validation."""
        findings = []
        for s in parsed_findings:
            title = f"Open Service Discovered ({s['service'].upper()}:{s['port']})"
            desc = f"Nmap discovered open port {s['port']}/{s['protocol']} running {s['service']} {s['product']} {s['version']}".strip()
            finding = Finding(
                title=title,
                url=f"http://{s['host']}:{s['port']}",
                severity="Informational",
                confidence=99,
                cwe=200,
                cvss=0.0,
                owasp="A05:2021 Security Misconfiguration",
                description=desc,
                evidence=f"Port {s['port']}/{s['protocol']} {s['state'] if 'state' in s else 'open'}",
                validation_status="needs_manual",
            )
            findings.append(finding)
        return findings
