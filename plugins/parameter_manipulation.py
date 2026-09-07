"""
Parameter Manipulation Plugin v6.0.

Appends hidden and control parameters (debug, admin, test, internal) to requests and checks for altered behavior.

CWE-472 | CVSS 6.5 | OWASP A04:2021 Insecure Design
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http_client import get
from core.response_analyzer import get_baseline, diff_responses, calculate_confidence, make_finding

PLUGIN_CWE = 472
PLUGIN_CVSS = 6.5
PLUGIN_OWASP = "A04:2021 Insecure Design"

CONTROL_PARAMS = [
    ("debug", "1"),
    ("admin", "true"),
    ("test", "true"),
    ("internal", "true"),
    ("show_hidden", "1"),
    ("verbose", "1"),
]


def test_parameter_manipulation(url):
    """Inject hidden parameter flags into query string and compare with baseline."""
    try:
        baseline = get_baseline(url, get)
        if not baseline.get("text"):
            return None

        parsed = urlparse(url)
        base_params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name, param_val in CONTROL_PARAMS:
            if param_name in base_params:
                continue

            modified = {k: v[0] for k, v in base_params.items()}
            modified[param_name] = param_val
            new_query = urlencode(modified)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                r = get(test_url)
                if r is None or r.status_code != 200:
                    continue

                sim = diff_responses(baseline.get("text", ""), r.text)

                # Significant change in body indicates parameter acceptance/mode change
                if sim < 0.75 and param_name in r.text.lower():
                    signals = {
                        "param_accepted": True,
                        "behavioral_anomaly": True,
                    }
                    confidence = calculate_confidence(signals)
                    finding = make_finding(
                        url, "Hidden Parameter Manipulation",
                        confidence=confidence, signals=signals,
                        details=f"Adding hidden parameter '{param_name}={param_val}' altered application behavior (similarity {sim:.2f}).",
                        severity="Medium", payload=f"{param_name}={param_val}",
                        evidence=f"Response diff ratio: {sim:.2f}",
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
