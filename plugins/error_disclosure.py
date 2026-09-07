"""
Error Disclosure Plugin v6.0.

Triggers application errors with malformed payloads to test for verbose error messages,
stack traces, and debug page leakage.

CWE-209 | CVSS 5.3 | OWASP A05:2021 Security Misconfiguration
"""

from core.http_client import get
from core.response_analyzer import get_baseline, calculate_confidence, make_finding
from core.deep_analyzer import classify_error_response
from core.utils import inject_into_params

PLUGIN_CWE = 209
PLUGIN_CVSS = 5.3
PLUGIN_OWASP = "A05:2021 Security Misconfiguration"

TRIGGER_PAYLOADS = [
    "[[[[", "%00", "%ff", "''''", "1/0", "null", "NaN", "true",
]


def test_error_disclosure(url):
    """Inject malformed parameters to detect verbose stack traces and framework debug pages."""
    try:
        baseline = get_baseline(url, get)
        baseline_text = baseline.get("text_lower", "")

        for payload in TRIGGER_PAYLOADS:
            for param_name, crafted_url in inject_into_params(url, payload):
                try:
                    r = get(crafted_url)
                    if r is None:
                        continue

                    classification = classify_error_response(r.text, r.status_code)
                    if classification["error_type"] == "real_error" and classification["confidence"] > 0.4:
                        # Ensure error indicators weren't already present in baseline
                        new_indicators = [
                            ind for ind in classification["indicators"]
                            if ind.lower() not in baseline_text
                        ]

                        if new_indicators:
                            signals = {
                                "semantic_error": True,
                                "error_verbose": True,
                            }
                            confidence = calculate_confidence(signals)
                            finding = make_finding(
                                url, "Verbose Error Message / Stack Trace Leak",
                                confidence=confidence, signals=signals,
                                details=f"Parameter '{param_name}' triggered verbose error details/stack trace.",
                                severity="Medium", payload=payload,
                                evidence=f"Error indicators: {', '.join(new_indicators[:3])}",
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
