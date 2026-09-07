"""
Missing Function Level Access Control Detection Plugin v5.0.

Tests restricted API/admin paths for unauthenticated access.
Uses wildcard/soft-404 detection with confidence scoring to avoid false positives.
"""

from urllib.parse import urlparse
from core.http_client import session, DEFAULT_TIMEOUT
from core.config import ScannerConfig
from core.response_analyzer import make_finding, diff_responses, calculate_confidence
from core.utils import get_wildcard_body

SENSITIVE_PATHS = [
    "/api/users", "/api/config", "/api/debug",
    "/api/v1/users", "/api/v1/settings",
    "/admin/api", "/internal/status",
    "/graphql", "/api/graphql",
    "/swagger.json", "/api-docs", "/openapi.json",
    "/metrics", "/actuator", "/actuator/env",
    "/server-status"
]


def test_missing_function_level_access(url):
    # Host-only: only run on root URLs, skip deep crawled paths
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None

    base = url.rstrip("/")
    wildcard_body = get_wildcard_body(base)
    findings = []

    for path in SENSITIVE_PATHS:
        test_url = f"{base}{path}"
        try:
            r = session.get(test_url, allow_redirects=False, timeout=DEFAULT_TIMEOUT, verify=False)
            
            if r.status_code == 200 and len(r.text) > 50:
                # Soft-404 check: skip if response looks like the wildcard page
                if wildcard_body and diff_responses(r.text, wildcard_body) > 0.95:
                    continue

                signals = {"missing_protection": True}
                
                # Exclude HTML error pages; APIs should return JSON/XML/text
                if "<html" not in r.text[:200].lower():
                    signals["config_exposure"] = True
                    signals["multi_signal"] = True
                    
                    confidence = calculate_confidence(signals)
                    
                    if confidence >= ScannerConfig.CONFIDENCE_PROBABLE:
                        f = make_finding(
                            url, "Missing Function Level Access Control",
                            confidence=confidence, signals=signals,
                            details=f"API/Internal endpoint accessible without authentication: {path}",
                            severity="High" if "actuator/env" in path or "users" in path else "Medium",
                            payload=path,
                            evidence="HTTP 200 OK with non-HTML content",
                        )
                        if f: findings.append(f)
        except Exception:
            continue
            
    if not findings:
        return None
    if len(findings) == 1:
        return findings[0]
    return findings
