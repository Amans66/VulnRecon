"""
Command Injection Detection Plugin v6.0.

Tests for OS command injection vectors in query string parameters.

CWE-78 | CVSS 9.8 | OWASP A03:2021 Injection
"""

from core.http_client import get
from core.response_analyzer import get_baseline, detect_waf_block, calculate_confidence, make_finding
from core.utils import inject_into_params

PLUGIN_CWE = 78
PLUGIN_CVSS = 9.8
PLUGIN_OWASP = "A03:2021 Injection"

CMDI_PAYLOADS = [
    (";id", ["uid=", "gid="]),
    ("|id", ["uid=", "gid="]),
    ("$(id)", ["uid=", "gid="]),
    ("`id`", ["uid=", "gid="]),
    ("& whoami", ["author", "user", "root", "system"]),
]


def test_command_injection(url):
    """Test parameters for OS command injection vulnerabilities."""
    try:
        baseline = get_baseline(url, get)
        baseline_text = baseline.get("text_lower", "")

        for payload, match_indicators in CMDI_PAYLOADS:
            for param_name, crafted_url in inject_into_params(url, payload):
                try:
                    r = get(crafted_url)
                    if r is None:
                        continue
                    blocked, _ = detect_waf_block(r)
                    if blocked:
                        continue

                    body_lower = r.text.lower()
                    matches = [ind for ind in match_indicators if ind in body_lower and ind not in baseline_text]

                    if matches:
                        signals = {
                            "error_string": True,
                            "reflection": True,
                            "behavioral_anomaly": True,
                        }
                        confidence = calculate_confidence(signals)
                        finding = make_finding(
                            url, "OS Command Injection",
                            confidence=confidence, signals=signals,
                            details=f"Command injection payload executed via parameter '{param_name}'.",
                            severity="Critical", payload=payload,
                            evidence=f"Matched command output keywords: {', '.join(matches)}",
                            parameter=param_name,
                        )
                        if finding:
                            finding["cwe"] = PLUGIN_CWE
                            finding["cvss"] = PLUGIN_CVSS
                            finding["owasp"] = PLUGIN_OWASP
                            return finding
                except Exception:
                    continue
    except Exception:
        pass
    return None
