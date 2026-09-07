"""
Broken Authentication Detection Plugin v5.0.

Checks for unauthenticated access to protected admin/management paths
and looks for missing security headers on authentication endpoints.

Uses wildcard/soft-404 detection with confidence scoring to avoid
false positives on servers with catch-all routing (e.g. Next.js, SPAs).
"""

from urllib.parse import urljoin, urlparse
from core.http_client import get, DEFAULT_TIMEOUT
from core.config import ScannerConfig
from core.response_analyzer import make_finding, calculate_confidence, diff_responses
from core.utils import get_wildcard_body

PROTECTED_PATHS = [
    "/admin", "/admin/", "/administrator",
    "/dashboard", "/panel", "/manage",
    "/wp-admin", "/phpmyadmin",
    "/api/admin", "/api/users",
    "/console", "/debug",
]


def test_broken_authentication(url):
    # Host-only: only run on root URLs, skip deep crawled paths
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None

    base = url.rstrip("/")

    # Get wildcard body for soft-404 detection
    wildcard_body = get_wildcard_body(base)

    findings = []

    for path in PROTECTED_PATHS:
        test_url = urljoin(base + "/", path.lstrip("/"))
        try:
            r = get(test_url, allow_redirects=False, timeout=DEFAULT_TIMEOUT)

            # 200 without redirect = no auth gate
            if r.status_code == 200:
                # Soft-404 check: skip if response looks like the wildcard page
                if wildcard_body and diff_responses(r.text, wildcard_body) > 0.95:
                    continue

                text_lower = r.text.lower()
                signals = {"missing_protection": True}
                
                # Heuristic: if the page contains admin-like content
                admin_hints = ["admin", "dashboard", "manage", "panel", "settings", "control"]
                matched_hints = [hint for hint in admin_hints if hint in text_lower]
                
                if matched_hints:
                    signals["reflection_context"] = True
                    if len(matched_hints) > 1:
                        signals["multi_signal"] = True
                        
                    confidence = calculate_confidence(signals)
                    
                    if confidence >= ScannerConfig.CONFIDENCE_PROBABLE:
                        f = make_finding(
                            url, "Broken Authentication",
                            confidence=confidence, signals=signals,
                            details=f"Unauthenticated 200 OK at {test_url}",
                            severity="Critical", payload=path,
                            evidence=f"Keywords found: {', '.join(matched_hints)}",
                        )
                        if f: findings.append(f)
                        # Don't return early; there may be multiple broken paths
        except Exception:
            continue

    if not findings:
        return None
    if len(findings) == 1:
        return findings[0]
    return findings
