"""
Clickjacking detection plugin.

Checks for proper frame protection via X-Frame-Options and CSP frame-ancestors.
Notes:
- ALLOW-FROM is deprecated and only worked in IE/Edge Legacy.
- Only DENY and SAMEORIGIN are valid X-Frame-Options values.
- CSP frame-ancestors supersedes X-Frame-Options.
- frame-ancestors * is NOT protective (allows any origin to frame the page).

Confidence scoring:
- No X-Frame-Options AND no CSP frame-ancestors = 85% confidence
- One protection present but weak = 50% confidence
"""

import re
from urllib.parse import urlparse
from core.http_client import get
from core.response_analyzer import make_finding


def _parse_frame_ancestors(csp_header):
    """
    Extract frame-ancestors directive value from CSP header.
    Returns (has_directive: bool, is_restrictive: bool, value: str)
    """
    # Find frame-ancestors directive
    match = re.search(r"frame-ancestors\s+([^;]+)", csp_header, re.IGNORECASE)
    if not match:
        return False, False, ""

    value = match.group(1).strip()
    sources = value.split()

    # Wildcard '*' means any origin can frame — NOT protective
    if "*" in sources:
        return True, False, value

    # Check for restrictive values
    restrictive_values = {"'none'", "'self'"}
    if any(s.lower() in restrictive_values for s in sources):
        return True, True, value

    # If it lists specific domains, it's partially restrictive
    if sources:
        return True, True, value

    return True, False, value


def test_clickjacking(url):
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None

    try:
        r = get(url)
        headers = r.headers
        content_type = headers.get("Content-Type", "").lower()

        if "text/html" not in content_type:
            return None

        # Check X-Frame-Options — only DENY and SAMEORIGIN are valid
        xfo = headers.get("X-Frame-Options", "").strip().upper()
        has_valid_xfo = xfo in ("DENY", "SAMEORIGIN")
        has_deprecated_xfo = xfo.startswith("ALLOW-FROM")

        # Check CSP frame-ancestors
        csp = headers.get("Content-Security-Policy", "")
        has_fa_directive, fa_is_restrictive, fa_value = _parse_frame_ancestors(csp)

        # Case 1: No protection at all
        if not has_valid_xfo and not has_deprecated_xfo and not has_fa_directive:
            signals = {"missing_protection": True, "header_indicator": True}
            return make_finding(
                url, "Clickjacking",
                confidence=85,
                signals=signals,
                details="Missing frame protection (no valid X-Frame-Options or CSP frame-ancestors)",
                severity="Medium",
                evidence="No X-Frame-Options header; No CSP frame-ancestors directive",
            )

        # Case 2: frame-ancestors present but wildcard (*)
        if has_fa_directive and not fa_is_restrictive:
            signals = {"missing_protection": True}
            detail = f"CSP frame-ancestors is set to '{fa_value}' which allows framing by any origin"
            if has_deprecated_xfo:
                detail += f"; X-Frame-Options uses deprecated ALLOW-FROM"
            return make_finding(
                url, "Clickjacking",
                confidence=50,
                signals=signals,
                details=detail,
                severity="Medium",
                evidence=f"frame-ancestors: {fa_value}",
            )

        # Case 3: Deprecated ALLOW-FROM without restrictive CSP fallback
        if has_deprecated_xfo and not (has_fa_directive and fa_is_restrictive):
            signals = {"missing_protection": True}
            return make_finding(
                url, "Clickjacking",
                confidence=50,
                signals=signals,
                details="X-Frame-Options uses deprecated ALLOW-FROM (unsupported in Chrome/Firefox/Edge); no CSP frame-ancestors fallback",
                severity="Medium",
                evidence=f"X-Frame-Options: {xfo}",
            )

    except Exception:
        pass
    return None
