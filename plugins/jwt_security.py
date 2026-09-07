"""
JWT Security Analysis Plugin v6.0.

Detects JWT tokens in responses and cookies, then analyzes them
for security weaknesses (algorithm, expiry, sensitive data exposure).

CWE-347 | CVSS 7.5 | OWASP A07:2021 Auth Failures
"""

import re
import json
import base64
from urllib.parse import urlparse
from core.http_client import get
from core.response_analyzer import calculate_confidence, make_finding

PLUGIN_CWE = 347
PLUGIN_CVSS = 7.5
PLUGIN_OWASP = "A07:2021 Identification and Authentication Failures"

JWT_PATTERN = re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+')

SENSITIVE_CLAIMS = [
    "password", "passwd", "secret", "private_key", "credit_card",
    "ssn", "social_security", "api_key", "api_secret",
]


def _decode_jwt_part(part):
    """Base64url-decode a JWT part."""
    try:
        padding = 4 - len(part) % 4
        if padding != 4:
            part += '=' * padding
        decoded = base64.urlsafe_b64decode(part)
        return json.loads(decoded)
    except Exception:
        return None


def _analyze_jwt(token):
    """Analyze a JWT token for security issues."""
    parts = token.split('.')
    if len(parts) != 3:
        return None

    header = _decode_jwt_part(parts[0])
    payload = _decode_jwt_part(parts[1])

    if not header or not payload:
        return None

    issues = []

    # Check algorithm
    alg = header.get("alg", "").lower()
    if alg == "none":
        issues.append("Algorithm set to 'none' — signature bypass possible")
    elif alg in ("hs256", "hs384", "hs512"):
        issues.append(f"Uses symmetric algorithm '{alg}' — vulnerable to brute force if weak secret")

    # Check for missing expiry
    if "exp" not in payload:
        issues.append("Missing 'exp' claim — token never expires")

    # Check for sensitive data in payload
    for key in payload:
        if key.lower() in SENSITIVE_CLAIMS:
            issues.append(f"Sensitive claim '{key}' found in JWT payload")

    # Check for weak key ID
    if "kid" in header:
        kid = str(header["kid"])
        if kid in ("1", "0", "key1", "default"):
            issues.append(f"Weak/default key ID: '{kid}'")

    return {
        "header": header,
        "payload_claims": list(payload.keys()),
        "issues": issues,
        "alg": header.get("alg", "unknown"),
    }


def test_jwt_security(url):
    """Detect and analyze JWT tokens for security weaknesses."""
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None  # Host-only

    try:
        r = get(url)
        if r is None:
            return None

        # Search for JWT in response body
        tokens = JWT_PATTERN.findall(r.text)

        # Search in cookies
        for cookie in r.cookies:
            cookie_val = str(cookie.value)
            tokens.extend(JWT_PATTERN.findall(cookie_val))

        # Search in response headers
        for header_val in r.headers.values():
            tokens.extend(JWT_PATTERN.findall(str(header_val)))

        # Deduplicate
        tokens = list(set(tokens))

        if not tokens:
            return None

        # Analyze each token
        all_issues = []
        for token in tokens[:5]:  # Max 5 tokens
            analysis = _analyze_jwt(token)
            if analysis and analysis["issues"]:
                all_issues.extend(analysis["issues"])

        if not all_issues:
            return None

        signals = {"jwt_weakness": True}
        if any("none" in issue.lower() for issue in all_issues):
            signals["auth_bypass"] = True
        if any("sensitive" in issue.lower() for issue in all_issues):
            signals["data_leak"] = True
        if len(all_issues) >= 2:
            signals["multi_signal"] = True

        confidence = calculate_confidence(signals)
        severity = "Critical" if signals.get("auth_bypass") else "High" if signals.get("data_leak") else "Medium"

        finding = make_finding(
            url, "JWT Security Weakness",
            confidence=confidence, signals=signals,
            details=f"JWT token issues: {'; '.join(all_issues[:5])}",
            severity=severity,
            payload=tokens[0][:20] + "...",
            evidence=f"Found {len(tokens)} JWT token(s) with {len(all_issues)} issue(s)",
        )
        if finding:
            finding["cwe"] = PLUGIN_CWE
            finding["cvss"] = PLUGIN_CVSS
            finding["owasp"] = PLUGIN_OWASP
            return finding

    except Exception:
        pass
    return None
