"""
Server-Side Template Injection (SSTI) Detection Plugin v6.0.

Tests for template injection by injecting mathematical expressions
into parameters and checking if the server evaluates them.

CWE-1336 | CVSS 9.8 | OWASP A03:2021 Injection
"""

from core.http_client import get
from core.response_analyzer import (
    get_baseline, detect_waf_block, calculate_confidence, make_finding,
)
from core.utils import inject_into_params

PLUGIN_CWE = 1336
PLUGIN_CVSS = 9.8
PLUGIN_OWASP = "A03:2021 Injection"

# Template expression → expected result if evaluated
SSTI_PROBES = [
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "Freemarker/Velocity/EL"),
    ("<%=7*7%>", "49", "ERB/EJS"),
    ("#{7*7}", "49", "Ruby/Java EL"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
    ("${{7*7}}", "49", "Thymeleaf"),
    ("{7*7}", "49", "Smarty"),
]

# Template error strings
SSTI_ERRORS = [
    "templateerror", "template syntax error", "jinja2.exceptions",
    "twig_error", "freemarker.core", "velocity",
    "org.apache.velocity", "javax.el", "expressionerror",
    "smarty", "mako.exceptions", "undefinedvariable",
    "templatenotfound", "render error",
]


def test_ssti(url):
    """Test for Server-Side Template Injection."""
    try:
        baseline = get_baseline(url, get)
        baseline_text = baseline.get("text_lower", "")

        for payload, expected, engine in SSTI_PROBES:
            for param_name, crafted_url in inject_into_params(url, payload):
                try:
                    r = get(crafted_url)
                    if r is None:
                        continue
                    blocked, _ = detect_waf_block(r)
                    if blocked:
                        continue

                    body = r.text
                    body_lower = body.lower()
                    signals = {}

                    # Primary: check if expression was evaluated
                    if expected in body and expected not in baseline.get("text", ""):
                        signals["math_eval"] = True
                        signals["template_eval"] = True

                    # Secondary: check for template errors
                    for err in SSTI_ERRORS:
                        if err in body_lower and err not in baseline_text:
                            signals["error_string"] = True
                            break

                    if signals.get("math_eval") or signals.get("template_eval"):
                        confidence = calculate_confidence(signals)
                        finding = make_finding(
                            url, "Server-Side Template Injection (SSTI)",
                            confidence=confidence, signals=signals,
                            details=f"Template expression evaluated by {engine} engine via '{param_name}'",
                            severity="Critical", payload=payload,
                            evidence=f"Payload '{payload}' produced '{expected}' in response",
                            parameter=param_name,
                        )
                        if finding:
                            finding["cwe"] = PLUGIN_CWE
                            finding["cvss"] = PLUGIN_CVSS
                            finding["owasp"] = PLUGIN_OWASP
                            return finding

                    elif signals.get("error_string"):
                        confidence = calculate_confidence(signals)
                        finding = make_finding(
                            url, "Server-Side Template Injection (SSTI)",
                            confidence=confidence, signals=signals,
                            details=f"Template error triggered via '{param_name}' — possible {engine}",
                            severity="High", payload=payload,
                            evidence="Template engine error in response",
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
