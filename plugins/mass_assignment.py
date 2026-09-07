"""
Mass Assignment Security Plugin v6.0.

Tests for mass assignment / parameter binding vulnerabilities by injecting high-privilege
parameters (e.g., admin, role, is_admin) into form POST requests.

CWE-915 | CVSS 6.5 | OWASP A01:2021 Broken Access Control
"""

from core.http_client import post
from core.response_analyzer import calculate_confidence, make_finding
from core.utils import get_forms, submit_form

PLUGIN_CWE = 915
PLUGIN_CVSS = 6.5
PLUGIN_OWASP = "A01:2021 Broken Access Control"

EXTRA_PARAMS = [
    ("admin", "true"),
    ("is_admin", "true"),
    ("role", "admin"),
    ("user_role", "administrator"),
    ("privilege", "super"),
    ("superuser", "true"),
]


def test_mass_assignment(url):
    """Test forms for mass assignment parameter binding issues."""
    try:
        forms = get_forms(url)
        if not forms:
            return None

        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            if method != "post":
                continue

            for param_name, param_val in EXTRA_PARAMS:
                try:
                    # Submit base form and add extra parameter payload
                    r = submit_form(form, url, "test")
                    if r is None:
                        continue

                    # Now inject extra parameter
                    data = {}
                    for tag in form.find_all(["input", "textarea"]):
                        name = tag.get("name")
                        if name:
                            data[name] = "test"
                    data[param_name] = param_val

                    r_injected = post(url, data=data)
                    if r_injected is None:
                        continue

                    body_lower = r_injected.text.lower()
                    # Check if response reflects parameter or doesn't reject it with 400
                    if r_injected.status_code == 200 and (param_name in body_lower or param_val in body_lower):
                        signals = {
                            "param_accepted": True,
                            "behavioral_anomaly": True,
                        }
                        confidence = calculate_confidence(signals)
                        finding = make_finding(
                            url, "Mass Assignment Vulnerability",
                            confidence=confidence, signals=signals,
                            details=f"Form action '{action}' accepted administrative parameter '{param_name}={param_val}'.",
                            severity="Medium", payload=f"{param_name}={param_val}",
                            evidence=f"Parameter {param_name} accepted with HTTP 200",
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
