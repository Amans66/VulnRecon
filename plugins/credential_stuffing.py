"""
Credential Stuffing Risk Detection Plugin v5.0.

Checks login endpoints for the absence of rate-limiting,
CAPTCHA, and account lockout mechanisms.

Uses wildcard/soft-404 detection and multi-signal confidence scoring
to avoid false positives on servers with catch-all routing.
"""

from urllib.parse import urlparse
from core.http_client import session, DEFAULT_TIMEOUT
from core.config import ScannerConfig
from core.response_analyzer import make_finding, calculate_confidence, diff_responses
from core.utils import get_wildcard_body

LOGIN_PATHS = [
    "/login", "/signin", "/user/login", "/auth/login", 
    "/account/login", "/wp-login.php", "/admin", "/administrator"
]


def test_credential_stuffing(url):
    # Host-only: only run on root URLs, skip deep crawled paths
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None

    base = url.rstrip("/")
    wildcard_body = get_wildcard_body(base)
    findings = []

    for path in LOGIN_PATHS:
        test_url = f"{base}{path}"
        try:
            r = session.get(test_url, allow_redirects=True, timeout=DEFAULT_TIMEOUT, verify=False)
            if r.status_code != 200:
                continue

            # Soft-404 check: skip if response looks like the wildcard page
            if wildcard_body and diff_responses(r.text, wildcard_body) > 0.95:
                continue

            text_lower = r.text.lower()

            # Check for protective mechanisms
            has_captcha    = "captcha" in text_lower or "recaptcha" in text_lower or "hcaptcha" in text_lower
            has_rate_limit = "rate limit" in text_lower or "too many" in text_lower
            has_lockout    = "locked" in text_lower or "lockout" in text_lower

            if not has_captcha and not has_rate_limit and not has_lockout:
                # Confirm it's actually a login page
                login_hints = ["password", "username", "email", "sign in", "log in"]
                matched_hints = [hint for hint in login_hints if hint in text_lower]
                
                if matched_hints:
                    signals = {
                        "missing_protection": True,
                        "reflection_context": True,
                    }
                    if len(matched_hints) > 1:
                        signals["multi_signal"] = True
                        
                    confidence = calculate_confidence(signals)
                    
                    if confidence >= ScannerConfig.CONFIDENCE_PROBABLE:
                        f = make_finding(
                            url, "Credential Stuffing Risk",
                            confidence=confidence, signals=signals,
                            details=f"Login page lacks CAPTCHA, rate-limiting, or lockout mechanisms.",
                            severity="Medium", payload=path,
                            evidence=f"Login keywords found ({', '.join(matched_hints)}) but no protection indicators detected.",
                        )
                        if f: findings.append(f)
        except Exception:
            continue

    if not findings:
        return None
    if len(findings) == 1:
        return findings[0]
    return findings
