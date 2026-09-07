"""
Accuracy & Validation Pipeline Test Suite v6.0.

Empirically verifies:
  1. Reflected XSS in safe context (HTML encoded) is correctly classified as FALSE POSITIVE / SAFE.
  2. SQLi boolean differential testing strictly requires TRUE to match baseline and FALSE to differ.
  3. False positives are completely filtered out of reports.
  4. Findings without 100% automated proof are marked 'NEEDS MANUAL VERIFICATION ⚠'.
"""

from core.validator import ValidationEngine
from core.response_analyzer import is_in_executable_context
from core.plugin_base import Finding
from main import should_keep_finding, normalize_finding


def test_xss_html_encoded_reflection_is_false_positive():
    """Verify that HTML-entity encoded payload (<script> -> &lt;script&gt;) is NOT treated as XSS."""
    payload = "<script>alert(1)</script>"
    
    # Executable HTML body
    raw_html = "<div><script>alert(1)</script></div>"
    assert is_in_executable_context(payload, raw_html) is True
    
    # Safe encoded HTML body
    encoded_html = "<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>"
    assert is_in_executable_context(payload, encoded_html) is False
    
    # Validator test
    validator = ValidationEngine()
    fake_finding = {
        "vuln": "XSS (Reflected)",
        "url": "https://example.com/search?q=test",
        "parameter": "q",
        "payload": payload,
        "confidence": 75,
    }
    
    # Mock HTTP response with encoded HTML
    class MockResp:
        status_code = 200
        text = encoded_html
        headers = {"Content-Type": "text/html"}

    validator._get = lambda url: MockResp()
    
    result = validator.validate_finding(fake_finding)
    assert result["validation_status"] == "false_positive"


def test_validator_filters_out_false_positives():
    """Verify that validate_all discards items classified as false_positive."""
    findings = [
        {
            "vuln": "XSS (Reflected)",
            "url": "https://example.com/search?q=test",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "confidence": 75,
        }
    ]
    
    validator = ValidationEngine()
    # Mock response returning escaped payload
    class MockResp:
        status_code = 200
        text = "<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>"
        headers = {"Content-Type": "text/html"}

    validator._get = lambda url: MockResp()
    
    validated = validator.validate_all(findings)
    assert len(validated) == 0  # Discarded false positive!


def test_validator_assigns_needs_manual_for_inconclusive_anomalies():
    """Verify that inconclusive findings receive 'NEEDS MANUAL VERIFICATION ⚠' status."""
    findings = [
        {
            "vuln": "Parameter Manipulation",
            "url": "https://example.com/item",
            "parameter": "id",
            "payload": "id=99",
            "confidence": 50,
            "evidence": "Inconclusive anomaly",
        }
    ]
    
    validator = ValidationEngine()
    # Mock GET returns None (un-reproducible connection timeout during verification)
    validator._get = lambda url: None
    
    validated = validator.validate_all(findings)
    assert len(validated) == 1
    assert "NEEDS MANUAL VERIFICATION" in validated[0]["status"]


def test_should_keep_finding_requires_evidence_or_validation_context():
    """High-confidence candidates without a traceable proof path should not survive the gate."""
    bare_candidate = {
        "vuln": "SQL Injection",
        "url": "https://example.com/search?q=test",
        "parameter": "q",
        "confidence": 80,
        "evidence": "",
    }
    validated_candidate = {
        "vuln": "SQL Injection",
        "url": "https://example.com/search?q=test",
        "parameter": "q",
        "confidence": 80,
        "validation_status": "confirmed",
        "evidence": "Boolean differential confirmed by control test",
    }

    assert should_keep_finding(bare_candidate, 40) is False
    assert should_keep_finding(validated_candidate, 40) is True


def test_validated_finding_has_professional_writeup_fields():
    """Validated findings must carry evidence, reproduction steps, and a professional narrative."""
    validator = ValidationEngine()

    class MockResp:
        def __init__(self, body, status=200):
            self.text = body
            self.status_code = status
            self.headers = {}

    def fake_get(url):
        if "safe_test_string_123" in url:
            return MockResp("<html>normal</html>")
        lowered = url.lower()
        if "and+%271%27=%271" in lowered or "and%20%271%27%3d%271" in lowered:
            return MockResp("<html>normal</html>")
        if "and+%271%27=%272" in lowered or "and%20%271%27%3d%272" in lowered:
            return MockResp("<html>TRUE FALSE diff</html>")
        if "or+1%3d1" in lowered or "or%201%3d1" in lowered:
            return MockResp("<html>TRUE FALSE diff</html>")
        return MockResp("<html>normal</html>")

    validator._get = fake_get
    result = validator.validate_finding({
        "vuln": "SQL Injection",
        "url": "https://example.com/search?id=10",
        "parameter": "id",
        "payload": "10 OR 1=1",
        "confidence": 85,
        "evidence": "",
        "title": "SQL Injection",
    })

    assert result["validation_status"] in {"confirmed", "high_confidence"}
    assert result["detection_method"]
    assert result["root_cause"]
    assert len(result["reproduction_steps"]) >= 3
    assert "writeup" in result and "SQL Injection" in result["writeup"]
    assert result["what_proven"]


def test_normalize_finding_starts_as_discovered_not_confirmed():
    """Raw detector output should remain a discovered hypothesis until a validation pass upgrades it."""
    finding = normalize_finding({
        "vuln": "SQL Injection",
        "url": "https://example.com/search?q=test",
        "parameter": "q",
        "confidence": 85,
        "evidence": "",
    })

    assert finding["status"] == "DISCOVERED"
    assert finding["validation_status"] == "needs_manual"


def test_finding_contract_has_evidence_driven_fields():
    """Canonical findings must carry a full evidence trail and lifecycle state."""
    finding = Finding(title="SQL Injection", url="https://example.com/search", parameter="q")
    data = finding.to_dict()

    for key in [
        "finding_id", "status", "category", "owasp_2025", "asset", "source_engine",
        "source_tools", "baseline_request", "test_request", "baseline_response",
        "test_response", "evidence", "validation_steps", "validation_result",
        "confidence", "reproducible", "security_impact",
    ]:
        assert key in data, f"Missing finding field: {key}"

    assert data["status"] == "DISCOVERED"
    assert data["source_tools"] == ["sentinel"]


def test_owasp_2025_mapping_is_used_for_security_taxonomy():
    """The scanner must use the current top-10 2025 taxonomy rather than legacy 2021 strings."""
    from core.config import ScannerConfig

    assert ScannerConfig.OWASP_CATEGORIES["A01"] == "Broken Access Control"
    assert ScannerConfig.OWASP_CATEGORIES["A05"] == "Injection"
    assert ScannerConfig.OWASP_CATEGORIES["A03"] == "Software Supply Chain Failures"
