"""
HTTP Parameter Pollution (HPP) Plugin v6.0.

Tests duplicate parameter handling (e.g. id=1&id=2) for server-side processing anomalies.

CWE-235 | CVSS 5.3 | OWASP A03:2021 Injection
"""

from urllib.parse import urlparse, parse_qs
from core.http_client import get
from core.response_analyzer import get_baseline, diff_responses, calculate_confidence, make_finding

PLUGIN_CWE = 235
PLUGIN_CVSS = 5.3
PLUGIN_OWASP = "A03:2021 Injection"


def test_http_param_pollution(url):
    """Inject duplicate query parameters to evaluate HTTP Parameter Pollution behavior."""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return None

        baseline = get_baseline(url, get)
        if not baseline.get("text"):
            return None

        for param in params:
            orig_val = params[param][0]
            # Construct duplicate parameter query string: param=orig_val&param=hpp_val_99
            hpp_query = f"{parsed.query}&{param}=hpp_val_99"
            crafted_url = url.split("?")[0] + "?" + hpp_query

            try:
                r = get(crafted_url)
                if r is None or r.status_code != 200:
                    continue

                sim = diff_responses(baseline.get("text", ""), r.text)

                if sim < 0.80 or "hpp_val_99" in r.text:
                    signals = {
                        "behavioral_anomaly": True,
                        "param_accepted": True,
                    }
                    confidence = calculate_confidence(signals)
                    finding = make_finding(
                        url, "HTTP Parameter Pollution (HPP)",
                        confidence=confidence, signals=signals,
                        details=f"Server processed duplicate parameter '{param}'. Response changed (similarity {sim:.2f}).",
                        severity="Low", payload=f"&{param}=hpp_val_99",
                        evidence=f"Duplicate parameter '{param}' affected application logic",
                        parameter=param,
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
