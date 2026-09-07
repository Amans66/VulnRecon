"""
Sensitive Data Exposure detection plugin.

Scans response bodies for exposed credentials, API keys, and secrets.
Uses tight patterns with word boundary assertions to avoid matching
substrings in URLs, base64 blobs, or HTML form elements.

Reports ALL matches with individual confidence scores.
"""

import re
from core.http_client import get
from core.response_analyzer import make_finding

SENSITIVE_PATTERNS = [
    # PEM private keys — definitive, no false positive risk
    (
        re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
        "Private key (PEM) exposed in page source",
        "Critical",
        95,
    ),
    # AWS Access Key IDs — must be standalone token
    (
        re.compile(r"(?<![A-Za-z0-9/+=])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9/+=])"),
        "AWS Access Key ID exposed",
        "Critical",
        90,
    ),
    # AWS Secret Access Key (40 base64-like chars after specific key names)
    (
        re.compile(
            r"""(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""",
        ),
        "AWS Secret Access Key exposed",
        "Critical",
        90,
    ),
    # Stripe Live Secret Key
    (
        re.compile(r"(?<![A-Za-z0-9])sk_live_[A-Za-z0-9]{24,}(?![A-Za-z0-9])"),
        "Stripe Live Secret Key exposed",
        "Critical",
        95,
    ),
    # Stripe Live Publishable Key (lower severity — publishable but still notable)
    (
        re.compile(r"(?<![A-Za-z0-9])pk_live_[A-Za-z0-9]{24,}(?![A-Za-z0-9])"),
        "Stripe Live Publishable Key exposed",
        "Medium",
        70,
    ),
    # JWT Token (three base64url segments)
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "JWT token exposed in page source",
        "High",
        85,
    ),
    # Firebase credentials (API key or project config)
    (
        re.compile(
            r"""(?:firebase|FIREBASE)[A-Za-z_]*(?:api[_-]?key|apiKey)\s*[:=]\s*['"]([A-Za-z0-9_-]{20,})['"]""",
            re.IGNORECASE,
        ),
        "Firebase API key exposed",
        "High",
        80,
    ),
    # Firebase config object pattern
    (
        re.compile(r"firebaseConfig\s*=\s*\{[^}]*apiKey\s*:\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        "Firebase configuration object exposed in source",
        "High",
        85,
    ),
    # Heroku API Key
    (
        re.compile(
            r"""(?:HEROKU_API_KEY|heroku_api_key)\s*[:=]\s*['"]?([a-f0-9-]{36,})['"]?""",
            re.IGNORECASE,
        ),
        "Heroku API Key exposed",
        "Critical",
        90,
    ),
    # Azure Connection String
    (
        re.compile(
            r"(?:DefaultEndpointsProtocol|AccountName|AccountKey|EndpointSuffix)\s*=\s*[^;\s]{5,}",
            re.IGNORECASE,
        ),
        "Azure connection string exposed",
        "Critical",
        85,
    ),
    # Generic API key patterns in code/config context (key = "value")
    (
        re.compile(
            r"""(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"][a-zA-Z0-9/+=]{20,}['"]""",
            re.IGNORECASE,
        ),
        "API key/secret exposed in page source",
        "High",
        80,
    ),
    # Hardcoded password in config/source (not HTML form elements)
    (
        re.compile(
            r"""(?:password|passwd|pwd)\s*[:=]\s*['"]([a-zA-Z0-9!@#$%^&*_.]{6,})['"]""",
            re.IGNORECASE,
        ),
        "Hardcoded password exposed in source",
        "High",
        60,
    ),
    # Database connection strings
    (
        re.compile(
            r"""(?:mysql|postgres|mongodb|redis)://[a-zA-Z0-9_]+:[^\s@]+@""",
            re.IGNORECASE,
        ),
        "Database connection string with credentials exposed",
        "Critical",
        90,
    ),
    # Google API Key (AIza prefix, 35+ chars)
    (
        re.compile(r"(?<![A-Za-z0-9])AIza[A-Za-z0-9_-]{35,}(?![A-Za-z0-9])"),
        "Google API Key exposed",
        "High",
        80,
    ),
    # GitHub Personal Access Token
    (
        re.compile(r"(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{36}(?![A-Za-z0-9])"),
        "GitHub Personal Access Token exposed",
        "Critical",
        95,
    ),
    # GitHub OAuth Token
    (
        re.compile(r"(?<![A-Za-z0-9])gho_[A-Za-z0-9]{36}(?![A-Za-z0-9])"),
        "GitHub OAuth Token exposed",
        "Critical",
        95,
    ),
    # Slack webhook
    (
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        "Slack Webhook URL exposed",
        "High",
        90,
    ),
    # Slack Bot Token
    (
        re.compile(r"(?<![A-Za-z0-9])xoxb-[0-9]{10,}-[A-Za-z0-9]{20,}"),
        "Slack Bot Token exposed",
        "Critical",
        90,
    ),
    # Mailgun API Key
    (
        re.compile(r"(?<![A-Za-z0-9])key-[A-Za-z0-9]{32}(?![A-Za-z0-9])"),
        "Mailgun API Key exposed",
        "High",
        80,
    ),
    # Twilio Account SID / Auth Token
    (
        re.compile(r"(?<![A-Za-z0-9])AC[a-f0-9]{32}(?![A-Za-z0-9])"),
        "Twilio Account SID exposed",
        "High",
        80,
    ),
    # SendGrid API Key
    (
        re.compile(r"(?<![A-Za-z0-9])SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9])"),
        "SendGrid API Key exposed",
        "Critical",
        90,
    ),
    # Square Access Token
    (
        re.compile(r"(?<![A-Za-z0-9])sq0atp-[A-Za-z0-9_-]{22}(?![A-Za-z0-9])"),
        "Square Access Token exposed",
        "Critical",
        90,
    ),
]

HTML_EXCLUSIONS = [
    "password", "passwd", "text", "hidden", "submit", "button",
    "email", "search", "url", "tel", "number",
]


def _is_in_html_tag(text, match_start):
    """Check if the match position is inside an HTML tag attribute."""
    preceding = text[max(0, match_start - 200):match_start]
    last_lt = preceding.rfind("<")
    last_gt = preceding.rfind(">")
    return last_lt > last_gt


def test_sensitive_data_exposure(url):
    findings = []

    try:
        r = get(url)
        text = r.text

        # Skip binary/non-text responses
        content_type = r.headers.get("Content-Type", "")
        if "text" not in content_type and "json" not in content_type and "javascript" not in content_type:
            return None

        # Skip very large responses (likely JS bundles, media, etc.)
        if len(text) > 500000:
            return None

        for pattern, description, severity, base_confidence in SENSITIVE_PATTERNS:
            for match in pattern.finditer(text):
                # Skip if inside an HTML tag (form elements, input attributes)
                if _is_in_html_tag(text, match.start()):
                    continue

                # For password pattern, check the captured value isn't a common HTML keyword
                if "password" in description.lower():
                    groups = match.groups()
                    if groups and groups[0].lower() in HTML_EXCLUSIONS:
                        continue

                matched_text = match.group()[:80]

                signals = {
                    "config_exposure": True,
                    "reflection": True,
                }

                # Boost confidence if match is in a non-HTML context
                # (e.g., JSON response, raw config, JS source)
                if "json" in content_type:
                    signals["multi_signal"] = True
                    confidence = min(base_confidence + 5, 100)
                else:
                    confidence = base_confidence

                finding = make_finding(
                    url, "Sensitive Data Exposure",
                    confidence=confidence,
                    signals=signals,
                    details=description,
                    severity=severity,
                    payload=matched_text,
                    evidence=matched_text,
                )
                if finding:
                    findings.append(finding)

    except Exception:
        pass

    if not findings:
        return None

    # Return all findings — the scanner framework handles multiple results
    if len(findings) == 1:
        return findings[0]
    return findings
