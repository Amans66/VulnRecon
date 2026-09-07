"""
Prototype Pollution Plugin v6.0.

Injects __proto__ and constructor.prototype payloads into query parameters and JSON body inputs.

CWE-1321 | CVSS 6.1 | OWASP A03:2021 Injection
"""

import json
from core.http_client import get, post
from core.response_analyzer import get_baseline, calculate_confidence, make_finding
from core.utils import inject_into_params

PLUGIN_CWE = 1321
PLUGIN_CVSS = 6.1
PLUGIN_OWASP = "A03:2021 Injection"

POLLUTION_PAYLOADS = [
    "__proto__[polluted_key]=polluted_val",
    "constructor[prototype][polluted_key]=polluted_val",
    "__proto__.polluted_key=polluted_val",
]


def test_prototype_pollution(url):
    """Inject Prototype Pollution vectors into parameters and JSON body."""
    try:
        baseline = get_baseline(url, get)
        baseline_text = baseline.get("text_lower", "")

        for payload in POLLUTION_PAYLOADS:
            for param_name, crafted_url in inject_into_params(url, payload):
                try:
                    r = get(crafted_url)
                    if r is None or r.status_code != 200:
                        continue

                    body_lower = r.text.lower()
                    if "polluted_val" in body_lower and "polluted_val" not in baseline_text:
                        signals = {
                            "prototype_inject": True,
                            "reflection": True,
                        }
                        confidence = calculate_confidence(signals)
                        finding = make_finding(
                            url, "Prototype Pollution Vulnerability",
                            confidence=confidence, signals=signals,
                            details=f"Prototype pollution payload reflected via '{param_name}'.",
                            severity="Medium", payload=payload,
                            evidence="Injected prototype key reflected in response",
                            parameter=param_name,
                        )
                        if finding:
                            finding["cwe"] = PLUGIN_CWE
                            finding["cvss"] = PLUGIN_CVSS
                            finding["owasp"] = PLUGIN_OWASP
                            return finding
                except Exception:
                    continue

        # Test JSON body prototype pollution
        json_payload = {"__proto__": {"polluted_json": "true"}}
        try:
            r = post(url, json=json_payload)
            if r and r.status_code == 200 and "polluted_json" in r.text.lower() and "polluted_json" not in baseline_text:
                signals = {"prototype_inject": True}
                confidence = calculate_confidence(signals)
                finding = make_finding(
                    url, "Prototype Pollution Vulnerability",
                    confidence=confidence, signals=signals,
                    details="Prototype pollution payload reflected via JSON POST body.",
                    severity="Medium", payload=json.dumps(json_payload),
                    evidence="JSON __proto__ injection reflected in response body",
                )
                if finding:
                    finding["cwe"] = PLUGIN_CWE
                    finding["cvss"] = PLUGIN_CVSS
                    finding["owasp"] = PLUGIN_OWASP
                    return finding
        except Exception:
            pass

    except Exception:
        pass
    return None
