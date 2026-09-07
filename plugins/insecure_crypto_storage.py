"""
Insecure Cryptographic Storage Detection Plugin v5.0.

Checks for exposed sensitive files (configs/keys) and insecure transport indicators.
Uses wildcard/soft-404 detection to avoid false positives.
"""

from urllib.parse import urljoin, urlparse
from core.http_client import session, DEFAULT_TIMEOUT
from core.config import ScannerConfig
from core.response_analyzer import make_finding, diff_responses, calculate_confidence
from core.utils import get_wildcard_body

# Files that should never be publicly accessible
SENSITIVE_FILES = [
    "/.env", "/config.php", "/wp-config.php", "/database.yml",
    "/config/database.yml", "/settings.py", "/config.json",
    "/credentials.json", "/.git/config", "/backup.sql",
    "/dump.sql", "/.htpasswd", "/id_rsa", "/private.key"
]

def test_insecure_crypto_storage(url):
    # Host-only: only run on root URLs, skip deep crawled paths
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None

    base = url.rstrip("/")
    wildcard_body = get_wildcard_body(base)
    findings = []

    # Check if the site uses HTTPS (Basic transport layer check)
    if parsed.scheme == "http":
        signals = {"missing_protection": True}
        confidence = calculate_confidence(signals)
        f = make_finding(
            url, "Insecure Transport (HTTP)",
            confidence=confidence, signals=signals,
            details="The site is served over unencrypted HTTP, exposing data to interception.",
            severity="Medium", payload="http://",
        )
        if f: findings.append(f)

    # Check for exposed config files
    for path in SENSITIVE_FILES:
        test_url = urljoin(base + "/", path.lstrip("/"))
        try:
            r = session.get(test_url, timeout=DEFAULT_TIMEOUT, verify=False, allow_redirects=False)
            
            if r.status_code == 200 and len(r.text) > 20:
                # Soft-404 check: skip if response looks like the wildcard page
                if wildcard_body and diff_responses(r.text, wildcard_body) > 0.95:
                    continue

                # Heuristic: these files shouldn't serve HTML pages
                if "<html" not in r.text[:500].lower():
                    signals = {
                        "config_exposure": True,
                        "file_content": True,
                        "multi_signal": True
                    }
                    confidence = calculate_confidence(signals)
                    
                    if confidence >= ScannerConfig.CONFIDENCE_PROBABLE:
                        f = make_finding(
                            url, "Insecure Storage / Exposed Sensitive File",
                            confidence=confidence, signals=signals,
                            details=f"Sensitive file exposed: {path}",
                            severity="High", payload=path,
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
