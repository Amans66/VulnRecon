"""
Cookie Security Flags Plugin v6.0.

Analyzes Set-Cookie headers for missing security flags (HttpOnly, Secure, SameSite).

CWE-614 | CVSS 5.3 | OWASP A05:2021 Security Misconfiguration
"""

from urllib.parse import urlparse
from core.http_client import get
from core.response_analyzer import calculate_confidence, make_finding
from core.deep_analyzer import CookieAnalyzer

PLUGIN_CWE = 614
PLUGIN_CVSS = 5.3
PLUGIN_OWASP = "A05:2021 Security Misconfiguration"


def test_cookie_security(url):
    """Analyze HTTP response headers for missing cookie security attributes."""
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None  # Host-only plugin

    try:
        r = get(url)
        if r is None:
            return None

        # Gather set-cookie headers
        set_cookies = []
        if hasattr(r, "raw") and hasattr(r.raw, "headers"):
            for key, val in r.raw.headers.items():
                if key.lower() == "set-cookie":
                    set_cookies.append(val)

        if not set_cookies and "set-cookie" in r.headers:
            set_cookies.append(r.headers["set-cookie"])

        if not set_cookies:
            return None

        analyzer = CookieAnalyzer(set_cookies, final_url=r.url)
        issues = analyzer.analyze()

        if issues:
            signals = {
                "cookie_manipulation": True,
                "missing_protection": True,
            }
            confidence = calculate_confidence(signals)
            issue_summary = [f"{i['cookie']}: {', '.join(i['issues'])}" for i in issues]

            finding = make_finding(
                url, "Insecure Cookie Configuration",
                confidence=confidence, signals=signals,
                details=f"Session cookies missing security attributes: {'; '.join(issue_summary)}",
                severity="Medium", payload="Set-Cookie Header Analysis",
                evidence=f"Cookies with missing security flags: {len(issues)}",
            )
            if finding:
                finding["cwe"] = PLUGIN_CWE
                finding["cvss"] = PLUGIN_CVSS
                finding["owasp"] = PLUGIN_OWASP
                return finding

    except Exception:
        pass
    return None
