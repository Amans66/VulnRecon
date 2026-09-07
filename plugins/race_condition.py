"""
Race Condition Testing Plugin v6.0.

Sends parallel concurrent requests to state-changing forms to test for Time-of-Check to Time-of-Use (TOCTOU) race conditions.

CWE-362 | CVSS 5.9 | OWASP A04:2021 Insecure Design
"""

from concurrent.futures import ThreadPoolExecutor
from core.response_analyzer import calculate_confidence, make_finding
from core.utils import get_forms, submit_form

PLUGIN_CWE = 362
PLUGIN_CVSS = 5.9
PLUGIN_OWASP = "A04:2021 Insecure Design"


def test_race_condition(url):
    """Test POST forms for race condition vulnerability via concurrent requests."""
    try:
        forms = get_forms(url)
        if not forms:
            return None

        for form in forms:
            method = form.get("method", "get").lower()
            if method != "post":
                continue

            action = form.get("action", "")

            def _send_req():
                try:
                    return submit_form(form, url, "race_test_val")
                except Exception:
                    return None

            # Execute 5 parallel requests simultaneously
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(_send_req) for _ in range(5)]
                responses = [f.result() for f in futures if f.result() is not None]

            if len(responses) >= 3:
                statuses = [r.status_code for r in responses]
                body_lengths = [len(r.text) for r in responses]

                # Inconsistent success responses under concurrent submission indicate potential race condition
                if statuses.count(200) >= 2 and (max(body_lengths) - min(body_lengths) > 50):
                    signals = {
                        "race_condition": True,
                        "behavioral_anomaly": True,
                    }
                    confidence = calculate_confidence(signals)
                    finding = make_finding(
                        url, "Potential Race Condition (TOCTOU)",
                        confidence=confidence, signals=signals,
                        details=f"Concurrent form submissions to '{action}' yielded inconsistent response behaviors.",
                        severity="Medium", payload="Concurrent Submissions",
                        evidence=f"5 parallel POSTs resulted in status codes: {statuses}",
                    )
                    if finding:
                        finding["cwe"] = PLUGIN_CWE
                        finding["cvss"] = PLUGIN_CVSS
                        finding["owasp"] = PLUGIN_OWASP
                        return finding

    except Exception:
        pass
    return None
