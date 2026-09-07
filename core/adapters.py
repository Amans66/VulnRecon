"""
Third-Party Security Tool Output Adapters v6.0.

Parses third-party tool outputs (Nikto, Dalfox, SQLMap, WPScan) and normalizes
findings into the scanner's standard Finding format for validation.

CRITICAL RULE: Third-party findings are parsed as candidate hypotheses and MUST pass
through our internal ValidationEngine before becoming confirmed findings!
"""

import json
from core.plugin_base import Finding
from core.config import ScannerConfig


class ToolOutputAdapter:
    """Base class for third-party security tool output parsers."""

    @staticmethod
    def parse_dalfox_json(json_str: str) -> list:
        """Parse Dalfox JSON output into normalized Finding objects."""
        findings = []
        try:
            data = json.loads(json_str)
            items = data if isinstance(data, list) else [data]
            for item in items:
                vuln_type = item.get("type", "XSS")
                param = item.get("param", "")
                url = item.get("url", "")
                payload = item.get("payload", "")

                finding = Finding(
                    title=f"XSS ({vuln_type} - Dalfox Adapter)",
                    url=url,
                    parameter=param,
                    severity="High",
                    confidence=80,
                    cwe=79,
                    cvss=6.1,
                    owasp="A03:2021 Injection",
                    description=f"Dalfox detected XSS vulnerability in parameter '{param}'.",
                    payload=payload,
                    evidence=f"Dalfox payload: {payload}",
                    validation_status="needs_manual",  # Requires internal validation!
                )
                findings.append(finding.to_dict())
        except Exception:
            pass
        return findings

    @staticmethod
    def parse_sqlmap_json(json_str: str) -> list:
        """Parse SQLMap JSON report into normalized Finding objects."""
        findings = []
        try:
            data = json.loads(json_str)
            data_items = data.get("data", []) if isinstance(data, dict) else data
            for item in data_items:
                param = item.get("parameter", "")
                url = item.get("url", "")
                dbms = item.get("dbms", "SQL")
                title = item.get("title", "SQL Injection")

                finding = Finding(
                    title=f"SQL Injection ({dbms} - SQLMap Adapter)",
                    url=url,
                    parameter=param,
                    severity="Critical",
                    confidence=90,
                    cwe=89,
                    cvss=8.6,
                    owasp="A03:2021 Injection",
                    description=f"SQLMap detected {dbms} injection in parameter '{param}'. Details: {title}",
                    payload=item.get("payload", ""),
                    evidence=f"SQLMap title: {title}",
                    validation_status="needs_manual",
                )
                findings.append(finding.to_dict())
        except Exception:
            pass
        return findings

    @staticmethod
    def parse_nikto_json(json_str: str) -> list:
        """Parse Nikto JSON report into normalized Finding objects."""
        findings = []
        try:
            data = json.loads(json_str)
            vulnerabilities = data.get("vulnerabilities", [])
            for item in vulnerabilities:
                url = item.get("url", "")
                msg = item.get("msg", "")

                finding = Finding(
                    title="Web Server Security Finding (Nikto Adapter)",
                    url=url,
                    severity="Medium",
                    confidence=70,
                    cwe=16,
                    cvss=5.3,
                    owasp="A05:2021 Security Misconfiguration",
                    description=f"Nikto matcher rule output: {msg}",
                    evidence=msg,
                    validation_status="needs_manual",
                )
                findings.append(finding.to_dict())
        except Exception:
            pass
        return findings
