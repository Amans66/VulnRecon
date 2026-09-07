"""
Open Redirect Plugin v6.0.

Expanded open redirect testing with parameter discovery and external domain payloads.

CWE-601 | CVSS 6.1 | OWASP A01:2021 Broken Access Control
"""

from urllib.parse import urlparse, parse_qs
from core.http_client import get
from core.response_analyzer import calculate_confidence, make_finding
from core.utils import inject_into_params

PLUGIN_CWE = 601
PLUGIN_CVSS = 6.1
PLUGIN_OWASP = "A01:2021 Broken Access Control"

REDIRECT_PARAMS = [
    "url", "redirect", "next", "return", "return_to", "goto",
    "dest", "destination", "out", "target", "r", "u",
]

REDIRECT_PAYLOADS = [
    "https://example.com",
    "//example.com",
    "/\\example.com",
    "https:example.com",
]


def test_open_redirect(url):
    """Test parameters for unvalidated open redirect vulnerability."""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        target_params = [p for p in params if any(rp in p.lower() for rp in REDIRECT_PARAMS)]
        if not target_params:
            target_params = list(params.keys()) if params else REDIRECT_PARAMS[:4]

        for param in target_params:
            for payload in REDIRECT_PAYLOADS:
                for param_name, crafted_url in inject_into_params(url, payload):
                    if param_name != param:
                        continue

                    try:
                        r = get(crafted_url, allow_redirects=False)
                        if r is None:
                            continue

                        location = r.headers.get("Location", "")
                        if r.status_code in (301, 302, 303, 307, 308) and "example.com" in location:
                            signals = {
                                "redirect_control": True,
                                "verified": True,
                            }
                            confidence = calculate_confidence(signals)
                            finding = make_finding(
                                url, "Open Redirect Vulnerability",
                                confidence=confidence, signals=signals,
                                details=f"Unvalidated open redirect via parameter '{param_name}' pointing to external URL.",
                                severity="Medium", payload=payload,
                                evidence=f"HTTP {r.status_code} Redirect Location header: {location}",
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
