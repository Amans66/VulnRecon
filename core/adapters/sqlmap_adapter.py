"""SQLMap Adapter v6.0."""
import os
import json
import subprocess
from core.adapters.base_adapter import BaseToolAdapter
from core.tool_manager import ExternalToolManager
from core.plugin_base import Finding


class SQLMapAdapter(BaseToolAdapter):
    def __init__(self):
        super().__init__("SQLMap", "sqlmap")
        self.manager = ExternalToolManager()

    def check_available(self) -> bool:
        return self.manager.detect_tool("sqlmap").installed

    def get_version(self) -> str:
        return self.manager.detect_tool("sqlmap").version

    def run(self, target: str, options: dict = None) -> dict:
        status = self.manager.detect_tool("sqlmap")
        if not status.installed:
            return {"error": "SQLMap is not installed", "data": []}

        out_dir = os.path.join("results", "sqlmap_out")
        os.makedirs(out_dir, exist_ok=True)

        cmd = [
            status.location,
            "-u", target,
            "--batch", "--dump-format=JSON",
            "--output-dir=" + out_dir
        ]

        try:
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
            return {"output_dir": out_dir, "status": "completed"}
        except Exception as e:
            return {"error": str(e), "data": []}

    def parse_results(self, raw_output: dict) -> list:
        return []

    def normalize_results(self, parsed_findings: list) -> list:
        findings = []
        for item in parsed_findings:
            finding = Finding(
                title=f"SQL Injection ({item.get('dbms', 'SQL')} - SQLMap Adapter)",
                url=item.get("url", ""),
                parameter=item.get("parameter", ""),
                severity="Critical",
                confidence=90,
                cwe=89,
                cvss=8.6,
                owasp="A03:2021 Injection",
                description=f"SQLMap detected SQL injection in parameter '{item.get('parameter')}'",
                evidence=item.get("title", ""),
                validation_status="needs_manual",
            )
            findings.append(finding)
        return findings
