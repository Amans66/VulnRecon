from pathlib import Path
from types import SimpleNamespace

from core.attack_chain import AttackChainAnalyzer
from core.reporter import generate_html_report


def test_generate_html_report_escapes_chain_content(tmp_path):
    chain = SimpleNamespace(
        name="Chain",
        chain_severity="High",
        description="<script>alert(1)</script>",
        remediation="Fix <b>now</b>",
        steps=[{"vuln": "XSS", "url": "https://example.com"}],
        risk_score=80,
    )

    output_path = tmp_path / "report.html"
    generate_html_report([], str(output_path), [chain], "A")

    html = output_path.read_text(encoding="utf-8")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "Fix &lt;b&gt;now&lt;/b&gt;" in html


def test_attack_chain_enrichment_adds_steps_to_findings():
    findings = [
        {"vuln": "XSS", "url": "https://example.com", "severity": "High", "confidence": 80},
        {"vuln": "Session Fixation", "url": "https://example.com/login", "severity": "Medium", "confidence": 70},
    ]

    analyzer = AttackChainAnalyzer(findings)
    analyzer.analyze()
    enriched = analyzer.enrich_findings()

    assert enriched[0]["attack_chain_steps"]
    assert enriched[0]["attack_chain_steps"][0]["steps"][0]["vuln"] == "XSS"
    assert enriched[1]["attack_chain_steps"]


def test_generate_html_report_contains_professional_writeup_sections(tmp_path):
    output_path = tmp_path / "professional_report.html"
    finding = {
        "vuln": "SQL Injection",
        "url": "https://example.com/login",
        "parameter": "username",
        "severity": "High",
        "confidence": 90,
        "status": "CONFIRMED",
        "owasp": "A05:2025 Injection",
        "cwe": 89,
        "cvss": 8.6,
        "evidence": "Boolean differential confirmed by control test.",
        "root_cause": "User input influences the SQL expression.",
        "reproduction_steps": [
            "1. Open the endpoint.",
            "2. Submit a baseline request.",
            "3. Submit the true-condition payload.",
        ],
        "payload": "' OR '1'='1",
        "writeup": "## SQL Injection\n### Summary\nDetailed reproduction and remediation.",
    }

    generate_html_report([finding], str(output_path), "https://example.com/login", 1.2, [], "A")
    html = output_path.read_text(encoding="utf-8")

    assert "Copy Security Write-up" in html
    assert "## SQL Injection" in html
    assert "Boolean differential confirmed by control test." in html
    assert "A05:2025 Injection" in html
