"""
CSRF (Cross-Site Request Forgery) detection plugin.

Checks POST forms for the absence of anti-CSRF tokens.
Also checks for SameSite cookie attributes which provide CSRF protection.
SameSite=None is NOT protective and is treated as absent.

Confidence scoring:
- No token + state-changing form = 80% confidence
- Token present but weak (short, predictable) = 50% confidence

Also checks for CSRF tokens in custom headers (meta tags for JS frameworks).
"""

import re
from core.http_client import get
from core.utils import get_forms
from core.response_analyzer import make_finding

CSRF_TOKEN_NAMES = [
    "csrf", "csrftoken", "csrf_token", "_csrf", "xsrf",
    "xsrf_token", "_token", "authenticity_token", "anti_csrf",
    "__requestverificationtoken",
]

# Meta tag names that carry CSRF tokens for AJAX frameworks
CSRF_META_NAMES = [
    "csrf-token", "csrf-param", "_csrf_token", "xsrf-token",
]

# Minimum acceptable token length/entropy
MIN_TOKEN_LENGTH = 16


def _has_samesite_protection(response):
    """
    Check if the site uses SameSite=Strict or SameSite=Lax cookies.
    SameSite=None is NOT protective.
    """
    try:
        set_cookie_raw = ""
        for key, val in response.raw.headers.items():
            if key.lower() == "set-cookie":
                set_cookie_raw += val.lower() + " "

        if not set_cookie_raw:
            return False

        # SameSite=None is explicitly NOT protective
        # Only Strict and Lax provide CSRF protection
        has_strict = "samesite=strict" in set_cookie_raw
        has_lax = "samesite=lax" in set_cookie_raw

        return has_strict or has_lax
    except Exception:
        return False


def _has_csrf_meta_tag(html_text):
    """Check if page has a CSRF token in meta tags (common in Rails, Laravel, etc.)."""
    text_lower = html_text.lower()
    for meta_name in CSRF_META_NAMES:
        # <meta name="csrf-token" content="...">
        if f'name="{meta_name}"' in text_lower or f"name='{meta_name}'" in text_lower:
            return True
    return False


def _check_token_strength(token_value):
    """
    Check if a CSRF token value is strong enough.
    Returns True if weak, False if adequate.
    """
    if not token_value:
        return True  # No value = weak

    if len(token_value) < MIN_TOKEN_LENGTH:
        return True  # Too short

    # Check for predictable patterns
    if token_value.isdigit():
        return True  # Numeric only = predictable

    if token_value.lower() in ("true", "false", "1", "0", "yes", "no"):
        return True  # Boolean = predictable

    return False  # Token seems adequate


def test_csrf(url):
    forms = get_forms(url)
    if not forms:
        return None

    # Check SameSite cookie protection
    try:
        r = get(url)
        if _has_samesite_protection(r):
            return None

        # Check for CSRF meta tags (used by JS frameworks like Rails/Angular)
        has_meta_csrf = _has_csrf_meta_tag(r.text)
    except Exception:
        has_meta_csrf = False

    findings = []

    for form in forms:
        method = form.get("method", "get").lower()
        if method != "post":
            continue

        # Skip forms that look like search/newsletter (not state-changing)
        action = (form.get("action") or "").lower()
        if any(safe in action for safe in ["search", "subscribe", "newsletter", "contact", "query"]):
            continue

        # Check for hidden CSRF token fields
        hidden_inputs = form.find_all("input", {"type": "hidden"})
        token_found = False
        token_weak = False
        for inp in hidden_inputs:
            name = (inp.get("name") or "").lower()
            if any(tok in name for tok in CSRF_TOKEN_NAMES):
                token_found = True
                token_value = inp.get("value", "")
                if _check_token_strength(token_value):
                    token_weak = True
                break

        form_action = form.get("action", url)

        if not token_found and not has_meta_csrf:
            # No CSRF protection at all
            signals = {
                "missing_protection": True,
                "multi_signal": True,
            }
            f = make_finding(
                url, "CSRF",
                confidence=80,
                signals=signals,
                details=f"POST form action='{form_action}' has no anti-CSRF token and no SameSite cookie protection",
                severity="Medium",
                evidence=f"Form method=POST action='{form_action}'",
            )
            if f:
                findings.append(f)
        elif token_weak:
            # Token exists but is weak
            signals = {
                "missing_protection": True,
            }
            f = make_finding(
                url, "CSRF",
                confidence=50,
                signals=signals,
                details=f"POST form action='{form_action}' has a CSRF token but it appears weak (short or predictable)",
                severity="Low",
                evidence=f"Form method=POST action='{form_action}'",
            )
            if f:
                findings.append(f)

    if not findings:
        return None
    if len(findings) == 1:
        return findings[0]
    return findings
