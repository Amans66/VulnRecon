"""Burp Suite REST API Adapter v6.0."""
import os
import json
import urllib.request
from core.adapters.base_adapter import BaseToolAdapter
from core.tool_manager import ExternalToolManager
from core.plugin_base import Finding


class BurpAdapter(BaseToolAdapter):
    def __init__(self):
        super().__init__("Burp Suite", "burp")
        self.manager = ExternalToolManager()

    def check_available(self) -> bool:
        return self.manager.detect_tool("burp").installed

    def get_version(self) -> str:
        return self.manager.detect_tool("burp").version

    def run(self, target: str, options: dict = None) -> dict:
        status = self.manager.detect_tool("burp")
        if status.invocation_mode != "api":
            return {"error": "Burp REST API not configured. Set BURP_API_URL and BURP_API_KEY.", "issues": []}
        return {"issues": []}

    def parse_results(self, raw_output: dict) -> list:
        return raw_output.get("issues", [])

    def normalize_results(self, parsed_findings: list) -> list:
        findings = []
        for issue in parsed_findings:
            finding = Finding(
                title=f"{issue.get('name', 'Burp Issue')} (Burp Adapter)",
                url=issue.get("url", ""),
                severity=issue.get("severity", "Medium"),
                confidence=70,
                cwe=200,
                cvss=5.0,
                owasp="A05:2021 Security Misconfiguration",
                description=issue.get("description", ""),
                evidence=issue.get("evidence", ""),
                validation_status="needs_manual",
            )
            findings.append(finding)
        return findings
