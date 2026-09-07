"""Nikto Web Server Adapter v6.0."""
import os
import json
import subprocess
from core.adapters.base_adapter import BaseToolAdapter
from core.tool_manager import ExternalToolManager
from core.plugin_base import Finding


class NiktoAdapter(BaseToolAdapter):
    def __init__(self):
        super().__init__("Nikto", "nikto")
        self.manager = ExternalToolManager()

    def check_available(self) -> bool:
        return self.manager.detect_tool("nikto").installed

    def get_version(self) -> str:
        return self.manager.detect_tool("nikto").version

    def run(self, target: str, options: dict = None) -> dict:
        status = self.manager.detect_tool("nikto")
        if not status.installed:
            return {"error": "Nikto is not installed", "vulnerabilities": []}

        out_path = os.path.join("results", "nikto_out.json")
        os.makedirs("results", exist_ok=True)

        cmd = [
            status.location,
            "-h", target,
            "-Format", "json",
            "-o", out_path
        ]

        try:
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
            if os.path.exists(out_path):
                with open(out_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return {"vulnerabilities": data.get("vulnerabilities", [])}
        except Exception as e:
            return {"error": str(e), "vulnerabilities": []}
        return {"vulnerabilities": []}

    def parse_results(self, raw_output: dict) -> list:
        return raw_output.get("vulnerabilities", [])

    def normalize_results(self, parsed_findings: list) -> list:
        findings = []
        for item in parsed_findings:
            finding = Finding(
                title="Web Server Finding (Nikto Adapter)",
                url=item.get("url", ""),
                severity="Medium",
                confidence=65,
                cwe=16,
                cvss=5.3,
                owasp="A05:2021 Security Misconfiguration",
                description=item.get("msg", ""),
                evidence=item.get("msg", ""),
                validation_status="needs_manual",
            )
            findings.append(finding)
        return findings
