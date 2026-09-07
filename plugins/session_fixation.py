"""
Session Fixation Detection Plugin v5.0.

Tests if the server accepts and uses attacker-supplied session IDs.
Uses confidence scoring and only alerts on cookies that appear to be session IDs.
"""

from urllib.parse import urlparse
from core.http_client import session, DEFAULT_TIMEOUT
from core.config import ScannerConfig
from core.response_analyzer import make_finding, calculate_confidence

# Common names for session cookies
SESSION_COOKIE_NAMES = [
    "session", "sessid", "phpsessid", "jsessionid",
    "aspsessionid", "asp.net_sessionid", "auth", "token", "_sid"
]

def _is_session_cookie(cookie_name):
    """Determine if a cookie is likely a session/auth cookie."""
    name_lower = cookie_name.lower()
    return any(s_name in name_lower for s_name in SESSION_COOKIE_NAMES)


def test_session_fixation(url):
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None

    try:
        # Get initial cookies 
        r1 = session.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
        original_cookies = dict(r1.cookies)

        if not original_cookies:
            return None

        findings = []

        # Try to fixate each session cookie
        for cookie_name in original_cookies:
            if not _is_session_cookie(cookie_name):
                continue
                
            fabricated = {cookie_name: "FIXATED_SESSION_VALUE_12345"}
            
            # Request with fabricated cookie
            r2 = session.get(url, cookies=fabricated, timeout=DEFAULT_TIMEOUT, verify=False, allow_redirects=False)

            # Check if the server explicitly set our fabricated value back to us via Set-Cookie
            # (which means it accepted it as a valid new session to "fix" into the browser)
            r2_cookies = dict(r2.cookies)
            
            if r2_cookies.get(cookie_name) == "FIXATED_SESSION_VALUE_12345":
                signals = {
                    "behavioral_anomaly": True,
                    "missing_protection": True,
                    "multi_signal": True,
                }
                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_PROBABLE:
                    f = make_finding(
                        url, "Session Fixation",
                        confidence=confidence, signals=signals,
                        details=f"Server explicitly accepted and re-set attacker-supplied session ID for '{cookie_name}'",
                        severity="High", payload=f"{cookie_name}=FIXATED_SESSION_VALUE_12345",
                        evidence=f"Server Set-Cookie echoed the fixated value back.",
                    )
                    if f: findings.append(f)
                    continue

            # Also check if a follow-up request with fabricated cookie succeeds
            # without generating a new session (implicitly accepting the fixated one)
            r3 = session.get(url, cookies=fabricated, timeout=DEFAULT_TIMEOUT, verify=False)
            r3_cookies = dict(r3.cookies)
            
            if cookie_name not in r3_cookies:
                # Server didn't issue a new session cookie to replace our fake one
                signals = {
                    "missing_protection": True
                }
                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    f = make_finding(
                        url, "Session Fixation (Implicit Accept)",
                        confidence=confidence, signals=signals,
                        details=f"Server did not regenerate session cookie '{cookie_name}' after fixation attempt",
                        severity="Medium", payload=f"{cookie_name}=FIXATED_SESSION_VALUE_12345",
                        evidence="Server processed request without issuing a Set-Cookie to override the fake ID.",
                    )
                    if f: findings.append(f)

        if not findings:
            return None
        if len(findings) == 1:
            return findings[0]
        return findings

    except Exception:
        pass

    return None
