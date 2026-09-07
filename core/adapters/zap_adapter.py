"""
OWASP ZAP REST API & Automation Framework Adapter v6.0.

Integrates with OWASP ZAP REST API or Automation Framework.
Normalizes ZAP alert findings into Sentinel Finding format for internal validation.
"""

import os
import json
import urllib.request
from core.adapters.base_adapter import BaseToolAdapter
from core.tool_manager import ExternalToolManager
from core.plugin_base import Finding


class ZAPAdapter(BaseToolAdapter):
    """OWASP ZAP scanner adapter."""

    def __init__(self):
        super().__init__("OWASP ZAP", "zap")
        self.manager = ExternalToolManager()

    def check_available(self) -> bool:
        status = self.manager.detect_tool("zap")
        return status.installed

    def get_version(self) -> str:
        return self.manager.detect_tool("zap").version

    def run(self, target: str, options: dict = None) -> dict:
        """Fetch ZAP alerts via REST API if configured."""
        status = self.manager.detect_tool("zap")
        if status.invocation_mode != "api":
            return {"error": "ZAP API is not configured. Set ZAP_API_URL and ZAP_API_KEY environment variables.", "alerts": []}

        api_url = status.location.rstrip("/")
        api_key = os.environ.get("ZAP_API_KEY", "")

        try:
            req_url = f"{api_url}/JSON/core/view/alerts/?baseurl={urllib.parse.quote(target)}&apikey={api_key}"
            req = urllib.request.Request(req_url)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                return {"alerts": data.get("alerts", [])}
        except Exception as e:
            return {"error": f"Failed to connect to ZAP API: {e}", "alerts": []}

    def parse_results(self, raw_output: dict) -> list:
        return raw_output.get("alerts", [])

    def normalize_results(self, parsed_findings: list) -> List[Finding]:
        """Convert ZAP alerts to Sentinel findings with validation_status = 'needs_manual'."""
        findings = []
        severity_map = {"3": "High", "2": "Medium", "1": "Low", "0": "Informational"}

        for alert in parsed_findings:
            risk = str(alert.get("risk", "1"))
            sev = severity_map.get(risk, "Medium")
            name = alert.get("name") or alert.get("alert", "ZAP Finding")
            url = alert.get("url", "")
            param = alert.get("param", "")

            finding = Finding(
                title=f"{name} (ZAP Adapter)",
                url=url,
                parameter=param,
                severity=sev,
                confidence=60,
                cwe=int(alert.get("cweid", 0)) if alert.get("cweid") else 0,
                cvss=5.0,
                owasp="A05:2021 Security Misconfiguration",
                description=alert.get("description", ""),
                remediation=alert.get("solution", ""),
                evidence=alert.get("evidence", ""),
                validation_status="needs_manual",  # Must be validated by Sentinel!
            )
            findings.append(finding)
        return findings
