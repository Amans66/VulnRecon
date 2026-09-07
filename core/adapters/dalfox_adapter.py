"""Dalfox XSS Adapter v6.0."""
import os
import json
import subprocess
from core.adapters.base_adapter import BaseToolAdapter
from core.tool_manager import ExternalToolManager
from core.plugin_base import Finding


class DalfoxAdapter(BaseToolAdapter):
    def __init__(self):
        super().__init__("Dalfox", "dalfox")
        self.manager = ExternalToolManager()

    def check_available(self) -> bool:
        return self.manager.detect_tool("dalfox").installed

    def get_version(self) -> str:
        return self.manager.detect_tool("dalfox").version

    def run(self, target: str, options: dict = None) -> dict:
        status = self.manager.detect_tool("dalfox")
        if not status.installed:
            return {"error": "Dalfox is not installed", "findings": []}

        out_path = os.path.join("results", "dalfox_out.json")
        os.makedirs("results", exist_ok=True)

        cmd = [
            status.location,
            "url", target,
            "--format", "json",
            "--output", out_path
        ]

        try:
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
            if os.path.exists(out_path):
                with open(out_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return {"findings": data if isinstance(data, list) else [data]}
        except Exception as e:
            return {"error": str(e), "findings": []}
        return {"findings": []}

    def parse_results(self, raw_output: dict) -> list:
        return raw_output.get("findings", [])

    def normalize_results(self, parsed_findings: list) -> list:
        findings = []
        for item in parsed_findings:
            finding = Finding(
                title=f"XSS ({item.get('type', 'Reflected')} - Dalfox Adapter)",
                url=item.get("url", ""),
                parameter=item.get("param", ""),
                severity="High",
                confidence=80,
                cwe=79,
                cvss=6.1,
                owasp="A03:2021 Injection",
                description=f"Dalfox detected XSS in parameter '{item.get('param')}'",
                payload=item.get("payload", ""),
                evidence=item.get("evidence", item.get("payload", "")),
                validation_status="needs_manual",
            )
            findings.append(finding)
        return findings
