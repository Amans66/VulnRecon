"""
Unvalidated Redirects and Forwards Plugin v5.0.

Tests if URL parameters or paths can be manipulated to redirect users to external,
attacker-controlled domains.
"""

from urllib.parse import urlparse, urlunparse
from core.http_client import get, DEFAULT_TIMEOUT
from core.config import ScannerConfig
from core.response_analyzer import make_finding, calculate_confidence
from core.utils import inject_into_params


# Bypasses for open redirects
PAYLOADS = [
    "https://evil.com",
    "//evil.com",          # Protocol-relative
    "\\/\\/evil.com",      # Escaped slashes
    "https:evil.com",      # Missing slashes
    "https://evil.com%2F%2E%2E", # URL encoded bypass
]

REDIRECT_PARAMS = [
    "next", "url", "target", "return", "return_to", "returnUrl",
    "redirect", "redirect_uri", "continue", "destination", "goto", "out"
]


def test_unvalidated_redirects(url):
    parsed = urlparse(url)
    if not parsed.query:
        return None

    for payload in PAYLOADS:
        for param, crafted_url in inject_into_params(url, payload):
            # Prioritize known redirect parameters, skip others unless aggressive mode
            is_redirect_param = any(p in param.lower() for p in REDIRECT_PARAMS)
            if not is_redirect_param and ScannerConfig.INTENSITY < 3:
                continue

            try:
                # Disable redirects to check the Location header directly
                r = get(crafted_url, allow_redirects=False)
                
                if r.status_code in [301, 302, 303, 307, 308]:
                    location = r.headers.get("Location", "")
                    
                    if "evil.com" in location:
                        signals = {
                            "redirect_control": True,
                            "reflection": True,
                        }
                        # Higher confidence if it's a known redirect param
                        base_conf = 85 if is_redirect_param else 75
                        confidence = min(100, base_conf + calculate_confidence(signals) // 3)
                        
                        return make_finding(
                            url, "Unvalidated Redirects and Forwards",
                            confidence=confidence, signals=signals,
                            details=f"Param '{param}' redirects to arbitrary external domain",
                            severity="Medium", payload=payload,
                            evidence=f"Location: {location}", parameter=param,
                        )
                        
                # Check meta refresh in HTML
                if r.status_code == 200 and "text/html" in r.headers.get("Content-Type", ""):
                    if f'content="0;url={payload}"' in r.text.lower() or f"window.location='{payload}'" in r.text:
                        signals = {
                            "redirect_control": True,
                            "reflection_context": True,
                        }
                        return make_finding(
                            url, "Unvalidated Redirects (JS/Meta)",
                            confidence=80, signals=signals,
                            details=f"Param '{param}' sets JS/Meta redirect to external domain",
                            severity="Medium", payload=payload, parameter=param,
                        )
            except Exception:
                continue

    return None
