"""
Excessive Data Exposure Plugin v6.0.

Analyzes API and JSON responses for sensitive field leaks (passwords, private keys, SSNs, secrets).

CWE-213 | CVSS 5.3 | OWASP A03:2021 Injection
"""

import json
import re
from urllib.parse import urlparse
from core.http_client import get
from core.response_analyzer import calculate_confidence, make_finding

PLUGIN_CWE = 213
PLUGIN_CVSS = 5.3
PLUGIN_OWASP = "A03:2021 Injection"

SENSITIVE_PATTERNS = [
    (re.compile(r'["\']?(?:password|passwd|pwd_hash|secret_key|private_key)["\']?\s*:\s*["\'][^"\']{4,}["\']', re.I), "Credentials / Private Key"),
    (re.compile(r'["\']?(?:ssn|social_security|credit_card|cvv)["\']?\s*:\s*["\']?[0-9\-]{4,}["\']?', re.I), "PII / Financial Data"),
    (re.compile(r'["\']?(?:api_secret|access_token|auth_token)["\']?\s*:\s*["\'][a-zA-Z0-9_\-\.]{16,}["\']', re.I), "API / Auth Secret"),
]


def test_excessive_data_exposure(url):
    """Scan API response body for excessive data exposure / sensitive field leakage."""
    try:
        r = get(url)
        if r is None or r.status_code != 200:
            return None

        # Check content type for JSON / API responses
        ct = r.headers.get("Content-Type", "").lower()
        if "json" not in ct and not r.text.strip().startswith(("{", "[")):
            return None

        body = r.text
        findings_detected = []

        for pattern, label in SENSITIVE_PATTERNS:
            matches = pattern.findall(body)
            if matches:
                findings_detected.append(f"{label} ({len(matches)} match)")

        if findings_detected:
            signals = {
                "sensitive_field": True,
                "data_leak": True,
            }
            confidence = calculate_confidence(signals)
            finding = make_finding(
                url, "Excessive Data Exposure in API",
                confidence=confidence, signals=signals,
                details=f"API response exposes sensitive fields: {', '.join(findings_detected)}",
                severity="High", payload="N/A (Response Leak)",
                evidence=f"Exposed data categories: {', '.join(findings_detected)}",
            )
            if finding:
                finding["cwe"] = PLUGIN_CWE
                finding["cvss"] = PLUGIN_CVSS
                finding["owasp"] = PLUGIN_OWASP
                return finding

    except Exception:
        pass
    return None
