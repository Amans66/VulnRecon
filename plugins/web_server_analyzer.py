"""
Nikto-Inspired Modular Web Server & Configuration Matcher Plugin v6.0.

Provides compound matching (BODY, HEADER, COOKIE, STATUS) across common
web-server vulnerabilities, dangerous HTTP methods, exposed backup files,
and administrative endpoints.

Classifies outputs as: Observation, Potential Finding, or Confirmed Finding.

CWE-16 | CVSS 5.3 | OWASP A05:2021 Security Misconfiguration
"""

from urllib.parse import urlparse
from core.http_client import get, head, session, DEFAULT_TIMEOUT
from core.response_analyzer import diff_responses, calculate_confidence, make_finding
from core.utils import get_wildcard_body

PLUGIN_CWE = 16
PLUGIN_CVSS = 5.3
PLUGIN_OWASP = "A05:2021 Security Misconfiguration"

# Nikto-Style Server Matcher Rules
# Format: (path, method, match_conditions, title, severity, classification)
NIKTO_RULES = [
    (
        "/index.php.bak", "GET",
        {"STATUS": 200, "BODY": ["<?php", "DB_PASSWORD", "mysql_connect", "define("]},
        "Exposed PHP Source Code Backup File", "High", "Confirmed Finding"
    ),
    (
        "/index.html~", "GET",
        {"STATUS": 200, "BODY": ["<!DOCTYPE", "<html"]},
        "Exposed Text Editor Backup File (~)", "Low", "Potential Finding"
    ),
    (
        "/.DS_Store", "GET",
        {"STATUS": 200, "BODY": ["Bud1"]},
        "Exposed macOS Directory Store (.DS_Store)", "Medium", "Confirmed Finding"
    ),
    (
        "/server-status", "GET",
        {"STATUS": 200, "BODY": ["Apache Server Status", "Server Version"]},
        "Exposed Apache Server Status Page", "Medium", "Confirmed Finding"
    ),
    (
        "/phpinfo.php", "GET",
        {"STATUS": 200, "BODY": ["phpinfo()", "System ", "Build Date"]},
        "Exposed PHPInfo Configuration Page", "Medium", "Confirmed Finding"
    ),
    (
        "/elmah.axd", "GET",
        {"STATUS": 200, "BODY": ["Error Log for", "ELMAH"]},
        "Exposed ASP.NET ELMAH Error Log", "High", "Confirmed Finding"
    ),
]


def test_web_server_analyzer(url):
    """Run Nikto-style web server configuration and exposed file matcher rules."""
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None  # Host-only plugin

    base = url.rstrip("/")
    wildcard_body = get_wildcard_body(base)
    findings = []

    # 1. Dangerous HTTP Methods Test (TRACE, OPTIONS)
    try:
        r_opt = session.options(base, timeout=DEFAULT_TIMEOUT)
        if r_opt and r_opt.status_code == 200:
            allow_header = r_opt.headers.get("Allow", "") or r_opt.headers.get("Public", "")
            if "TRACE" in allow_header.upper():
                signals = {"missing_protection": True}
                f = make_finding(
                    base, "Dangerous HTTP Method Enabled (TRACE)",
                    confidence=90, signals=signals,
                    details="HTTP TRACE method enabled — potential Cross-Site Tracing (XST) vulnerability.",
                    severity="Medium", payload="OPTIONS / TRACE",
                    evidence=f"Allow Header: {allow_header}",
                )
                if f:
                    f["cwe"] = 693
                    f["cvss"] = 5.3
                    f["owasp"] = PLUGIN_OWASP
                    f["classification"] = "Confirmed Finding"
                    findings.append(f)
    except Exception:
        pass

    # 2. Nikto Compound Matcher Rules
    for path, method, conds, title, severity, classification in NIKTO_RULES:
        target_url = f"{base}{path}"
        try:
            r = get(target_url, timeout=DEFAULT_TIMEOUT)
            if r is None:
                continue

            # Check STATUS condition
            if "STATUS" in conds and r.status_code != conds["STATUS"]:
                continue

            body = r.text

            # Filter soft-404s
            if wildcard_body and diff_responses(body, wildcard_body) > 0.90:
                continue

            # Check BODY conditions
            body_match = True
            if "BODY" in conds:
                body_match = any(pattern.lower() in body.lower() for pattern in conds["BODY"])

            if body_match:
                signals = {"config_exposure": True}
                confidence = 90 if classification == "Confirmed Finding" else 65

                f = make_finding(
                    target_url, title,
                    confidence=confidence, signals=signals,
                    details=f"Nikto server matcher rule '{title}' triggered at '{path}'. Classification: {classification}.",
                    severity=severity, payload=path,
                    evidence=f"HTTP {r.status_code} response matched rule patterns.",
                )
                if f:
                    f["cwe"] = PLUGIN_CWE
                    f["cvss"] = PLUGIN_CVSS
                    f["owasp"] = PLUGIN_OWASP
                    f["classification"] = classification
                    findings.append(f)
        except Exception:
            continue

    if not findings:
        return None
    return findings if len(findings) > 1 else findings[0]
