"""WPScan WordPress Security Adapter v6.0."""
import os
import json
import subprocess
from core.adapters.base_adapter import BaseToolAdapter
from core.tool_manager import ExternalToolManager
from core.plugin_base import Finding


class WPScanAdapter(BaseToolAdapter):
    def __init__(self):
        super().__init__("WPScan", "wpscan")
        self.manager = ExternalToolManager()

    def check_available(self) -> bool:
        return self.manager.detect_tool("wpscan").installed

    def get_version(self) -> str:
        return self.manager.detect_tool("wpscan").version

    def run(self, target: str, options: dict = None) -> dict:
        status = self.manager.detect_tool("wpscan")
        if not status.installed:
            return {"error": "WPScan is not installed", "data": {}}

        out_path = os.path.join("results", "wpscan_out.json")
        os.makedirs("results", exist_ok=True)

        cmd = [
            status.location,
            "--url", target,
            "--format", "json",
            "-o", out_path
        ]

        try:
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
            if os.path.exists(out_path):
                with open(out_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return {"data": data}
        except Exception as e:
            return {"error": str(e), "data": {}}
        return {"data": {}}

    def parse_results(self, raw_output: dict) -> list:
        data = raw_output.get("data", {})
        findings = []
        if "version" in data:
            ver = data["version"]
            for vuln in ver.get("vulnerabilities", []):
                findings.append({"type": "Core", "title": vuln.get("title", ""), "cve": vuln.get("references", {}).get("cve", [])})
        return findings

    def normalize_results(self, parsed_findings: list) -> list:
        findings = []
        for item in parsed_findings:
            finding = Finding(
                title=f"WordPress {item.get('type')} Vulnerability (WPScan Adapter)",
                url="",
                severity="High",
                confidence=85,
                cwe=1104,
                cvss=7.5,
                owasp="A06:2021 Vulnerable and Outdated Components",
                description=item.get("title", ""),
                evidence=f"WPScan CVE: {', '.join(item.get('cve', []))}",
                validation_status="needs_manual",
            )
            findings.append(finding)
        return findings
