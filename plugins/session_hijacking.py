"""
Session Hijacking Risk Detection Plugin v5.0.

Checks cookie security flags: HttpOnly, Secure, SameSite.
Missing flags increase session hijacking risk.

Properly inspects ALL Set-Cookie headers and checks Secure
against the final redirected URL scheme (not the initial URL).
Now only alerts on cookies that appear to be Session IDs.
"""

import re
from urllib.parse import urlparse
from core.http_client import session, DEFAULT_TIMEOUT
from core.config import ScannerConfig
from core.response_analyzer import make_finding, calculate_confidence

# Common names for session cookies
SESSION_COOKIE_NAMES = [
    "session", "sessid", "phpsessid", "jsessionid",
    "aspsessionid", "asp.net_sessionid", "csrftoken",
    "auth", "token", "jwt", "_sid"
]

def _is_session_cookie(cookie_name):
    """Determine if a cookie is likely a session/auth cookie."""
    name_lower = cookie_name.lower()
    return any(s_name in name_lower for s_name in SESSION_COOKIE_NAMES)

def test_session_hijacking(url):
    try:
        r = session.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
        final_scheme = urlparse(r.url).scheme  # Use final URL after redirects

        # Ensure we get all cookies, not just the first one
        all_cookies = []
        try:
            for key, val in r.raw.headers.items():
                if key.lower() == "set-cookie":
                    all_cookies.append(val)
        except Exception:
            sc = r.headers.get("Set-Cookie", "")
            if sc:
                all_cookies = [sc]

        if not all_cookies:
            return None

        findings = []

        for cookie_str in all_cookies:
            cookie_parts = [p.strip() for p in cookie_str.split(";")]
            if not cookie_parts:
                continue
                
            # First part is "Name=Value"
            name_val = cookie_parts[0]
            if "=" not in name_val:
                continue
                
            cookie_name = name_val.split("=", 1)[0]
            
            # Only flag session-like cookies, not tracking/analytics cookies
            if not _is_session_cookie(cookie_name):
                continue
                
            cookie_lower = cookie_str.lower()
            issues = []
            
            if "httponly" not in cookie_lower:
                issues.append("missing HttpOnly")
            if final_scheme == "https" and "secure" not in cookie_lower:
                issues.append("missing Secure flag")
            if "samesite" not in cookie_lower:
                issues.append("missing SameSite")
            elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                issues.append("SameSite=None without Secure")

            if issues:
                signals = {
                    "missing_protection": True,
                    "header_indicator": True,
                }
                if len(issues) > 1:
                    signals["multi_signal"] = True
                    
                confidence = calculate_confidence(signals)
                
                if confidence >= ScannerConfig.CONFIDENCE_PROBABLE:
                    # Severity mapping
                    severity = "High"
                    if "missing HttpOnly" in issues and "missing Secure flag" not in issues:
                        severity = "Medium"
                        
                    f = make_finding(
                        url, "Session Hijacking Risk (Insecure Cookie)",
                        confidence=confidence, signals=signals,
                        details=f"Session cookie '{cookie_name}' has missing security flags: {', '.join(issues)}",
                        severity=severity, payload=cookie_name,
                        evidence=cookie_str[:80] + ("..." if len(cookie_str) > 80 else ""),
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
