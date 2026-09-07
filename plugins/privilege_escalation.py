"""
Privilege Escalation Detection Plugin v5.0.

Tests admin-level actions from unauthenticated context and checks for
parameter-based role manipulation.

Uses wildcard/soft-404 detection and baseline comparison with confidence
scoring to avoid false positives on servers with catch-all routing.
"""

from urllib.parse import urlparse
from core.http_client import get, DEFAULT_TIMEOUT
from core.config import ScannerConfig
from core.response_analyzer import make_finding, diff_responses, calculate_confidence, get_baseline
from core.utils import get_wildcard_body

ESCALATION_PATHS = [
    "/admin/users", "/api/admin", "/api/v1/admin",
    "/admin/settings", "/manage/users", "/administrator",
    "/admin/dashboard", "/_admin", "/sysadmin"
]


def test_privilege_escalation(url):
    # Host-only: only run on root URLs, skip deep crawled paths
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None

    base = url.rstrip("/")

    # Get wildcard body for soft-404 detection
    wildcard_body = get_wildcard_body(base)
    
    # Get baseline response for the root URL
    baseline = get_baseline(base, get)

    # ── Path-based escalation checks ──
    for path in ESCALATION_PATHS:
        test_url = f"{base}{path}"
        try:
            r = get(test_url, allow_redirects=False, timeout=DEFAULT_TIMEOUT)
            if r.status_code == 200 and len(r.text) > 100:
                # Soft-404 check: skip if response looks like the wildcard page
                if wildcard_body and diff_responses(r.text, wildcard_body) > 0.95:
                    continue

                signals = {
                    "missing_protection": True,
                    "multi_signal": True,
                }
                
                # Check if it actually looks like an admin panel
                text_lower = r.text.lower()
                if "admin" in text_lower and ("dashboard" in text_lower or "users" in text_lower or "settings" in text_lower):
                    signals["reflection_context"] = True
                    
                confidence = calculate_confidence(signals)
                
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    return make_finding(
                        url, "Privilege Escalation (Path Bypass)",
                        confidence=confidence, signals=signals,
                        details=f"Admin endpoint accessible without authentication: {path}",
                        severity="Critical", payload=path,
                        evidence="Status 200 OK without redirect",
                    )
        except Exception:
            continue

    # ── Role parameter manipulation checks ──
    role_urls = [
        f"{base}?role=admin", f"{base}?admin=true",
        f"{base}?is_admin=1", f"{base}?access_level=admin",
        f"{base}?privilege=admin", f"{base}?group=1"
    ]
    
    for test_url in role_urls:
        try:
            r = get(test_url, allow_redirects=False, timeout=DEFAULT_TIMEOUT)
            if r.status_code == 200:
                text_lower = r.text.lower()

                # Check if the response differs meaningfully from baseline
                # If it's the same page, the role param had no effect
                if diff_responses(text_lower, baseline["text_lower"]) > 0.95:
                    continue

                signals = {
                    "behavioral_anomaly": True,
                    "response_diff": True,
                }

                if "admin" in text_lower and "dashboard" in text_lower and "dashboard" not in baseline["text_lower"]:
                    signals["reflection_context"] = True
                    signals["multi_signal"] = True
                    
                confidence = calculate_confidence(signals)
                
                # We need fairly high confidence here since many params just break the page or cause slight diffs
                if confidence >= ScannerConfig.CONFIDENCE_PROBABLE:
                    return make_finding(
                        url, "Privilege Escalation (Parameter Manipulation)",
                        confidence=confidence, signals=signals,
                        details=f"Role manipulation possible via query parameter",
                        severity="Critical", payload=test_url.replace(base, ""),
                        evidence="Response changed meaningfully with admin parameters",
                    )
        except Exception:
            continue
            
    return None
