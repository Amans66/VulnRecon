"""
Forced Browsing Detection Plugin v6.0.

Tests common administrative and restricted paths for unauthorized access.
Filters out soft-404 responses using wildcard body comparison.

CWE-425 | CVSS 7.5 | OWASP A01:2021 Broken Access Control
"""

from urllib.parse import urlparse
from core.http_client import get, DEFAULT_TIMEOUT
from core.response_analyzer import diff_responses, calculate_confidence, make_finding
from core.utils import get_wildcard_body

PLUGIN_CWE = 425
PLUGIN_CVSS = 7.5
PLUGIN_OWASP = "A01:2021 Broken Access Control"

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/admin/login",
    "/dashboard", "/dashboard/", "/manage", "/management",
    "/panel", "/cpanel", "/controlpanel",
    "/api/admin", "/api/v1/admin", "/api/internal",
    "/debug", "/debug/", "/console", "/console/",
    "/phpmyadmin", "/pma", "/adminer",
    "/wp-admin", "/wp-login.php",
    "/server-status", "/server-info",
    "/_debug", "/_admin", "/__admin",
    "/elmah.axd", "/trace.axd",
    "/actuator", "/actuator/health", "/actuator/env",
    "/swagger-ui.html", "/api-docs", "/swagger.json",
    "/graphql", "/graphiql",
    "/metrics", "/health", "/status",
    "/.well-known/", "/info", "/phpinfo.php",
]

# Indicators that a page contains real admin/management content
ADMIN_INDICATORS = [
    "dashboard", "admin panel", "management console",
    "control panel", "administration", "settings",
    "configuration", "user management", "log out",
    "sign out", "swagger", "api documentation",
    "actuator", "health check", "phpinfo()",
    "server status", "debug toolbar",
]


def test_forced_browsing(url):
    """Test for unauthorized access to admin/restricted paths."""
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None  # Host-only plugin

    base = url.rstrip("/")
    wildcard_body = get_wildcard_body(base)

    try:
        for path in ADMIN_PATHS:
            test_url = f"{base}{path}"
            try:
                r = get(test_url, timeout=DEFAULT_TIMEOUT)
                if r is None or r.status_code != 200:
                    continue

                body = r.text
                body_lower = body.lower()

                # Filter soft-404s
                if wildcard_body:
                    sim = diff_responses(body, wildcard_body)
                    if sim > 0.90:
                        continue

                # Skip very small responses (likely empty/error)
                if len(body) < 200:
                    continue

                # Check for admin content indicators
                indicators_found = [
                    ind for ind in ADMIN_INDICATORS
                    if ind in body_lower
                ]

                if indicators_found:
                    signals = {
                        "forced_access": True,
                        "admin_access": True,
                    }
                    if len(indicators_found) >= 2:
                        signals["multi_signal"] = True

                    confidence = calculate_confidence(signals)
                    finding = make_finding(
                        url, "Forced Browsing — Admin Access",
                        confidence=confidence, signals=signals,
                        details=f"Admin/restricted path '{path}' accessible without authentication",
                        severity="High", payload=path,
                        evidence=f"Admin indicators found: {', '.join(indicators_found[:5])}",
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
