"""
Workflow Bypass Security Plugin v6.0.

Tests for logical workflow bypasses by directly requesting step 2/3 endpoints without completing prior steps.

CWE-841 | CVSS 6.5 | OWASP A04:2021 Insecure Design
"""

from urllib.parse import urlparse
from core.http_client import get, DEFAULT_TIMEOUT
from core.response_analyzer import diff_responses, calculate_confidence, make_finding
from core.utils import get_wildcard_body

PLUGIN_CWE = 841
PLUGIN_CVSS = 6.5
PLUGIN_OWASP = "A04:2021 Insecure Design"

WORKFLOW_STEPS = [
    "/checkout/step2", "/checkout/confirm", "/checkout/success",
    "/payment/process", "/payment/success", "/registration/step2",
    "/registration/verify", "/account/activate", "/reset-password/confirm",
]


def test_workflow_bypass(url):
    """Test direct access to multi-step workflow endpoints."""
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None  # Host-only plugin

    base = url.rstrip("/")
    wildcard_body = get_wildcard_body(base)

    try:
        for step_path in WORKFLOW_STEPS:
            test_url = f"{base}{step_path}"
            try:
                r = get(test_url, timeout=DEFAULT_TIMEOUT)
                if r is None or r.status_code != 200:
                    continue

                body = r.text

                # Filter soft-404s
                if wildcard_body:
                    sim = diff_responses(body, wildcard_body)
                    if sim > 0.90:
                        continue

                # Ensure page has substantial content (not redirect or minimal error message)
                if len(body) > 400:
                    signals = {
                        "workflow_bypass": True,
                        "behavioral_anomaly": True,
                    }
                    confidence = calculate_confidence(signals)
                    finding = make_finding(
                        url, "Business Logic Workflow Bypass",
                        confidence=confidence, signals=signals,
                        details=f"Multi-step workflow endpoint '{step_path}' accessible directly without completing earlier steps.",
                        severity="Medium", payload=step_path,
                        evidence=f"HTTP 200 OK returned for unverified workflow step {step_path}",
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
