"""
Secrets Exposure Plugin v6.0.

Scans common path locations for exposed secrets, configuration files, environment variables,
and source control directories, filtering soft-404s via wildcard comparison.

CWE-200 | CVSS 7.5 | OWASP A02:2021 Cryptographic Failures
"""

from urllib.parse import urlparse
from core.http_client import get, DEFAULT_TIMEOUT
from core.response_analyzer import diff_responses, calculate_confidence, make_finding
from core.utils import get_wildcard_body

PLUGIN_CWE = 200
PLUGIN_CVSS = 7.5
PLUGIN_OWASP = "A02:2021 Cryptographic Failures"

SECRET_PATHS = [
    ("/.env", ["DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "SECRET_KEY", "APP_KEY"]),
    ("/.git/config", ["[core]", "repositoryformatversion", "url ="]),
    ("/.git/HEAD", ["refs/heads/"]),
    ("/config.json", ["password", "secret", "database"]),
    ("/wp-config.php.bak", ["DB_PASSWORD", "DB_USER"]),
    ("/.aws/credentials", ["aws_secret_access_key"]),
    ("/server.key", ["-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----"]),
    ("/id_rsa", ["-----BEGIN RSA PRIVATE KEY-----"]),
]


def test_secrets_exposure(url):
    """Scan root host for exposed sensitive configuration files and keys."""
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None  # Host-only plugin

    base = url.rstrip("/")
    wildcard_body = get_wildcard_body(base)

    try:
        for path, indicators in SECRET_PATHS:
            target_url = f"{base}{path}"
            try:
                r = get(target_url, timeout=DEFAULT_TIMEOUT)
                if r is None or r.status_code != 200:
                    continue

                body = r.text

                # Filter soft-404s
                if wildcard_body:
                    sim = diff_responses(body, wildcard_body)
                    if sim > 0.90:
                        continue

                matches = [ind for ind in indicators if ind in body]
                if matches:
                    signals = {
                        "secret_found": True,
                        "config_exposure": True,
                        "data_leak": True,
                    }
                    confidence = calculate_confidence(signals)
                    finding = make_finding(
                        url, "Exposed Sensitive File / Secrets",
                        confidence=confidence, signals=signals,
                        details=f"Sensitive file exposed publicly at '{path}' containing secrets/config keywords.",
                        severity="High", payload=path,
                        evidence=f"Matched indicators in {path}: {', '.join(matches)}",
                    )
                    if finding:
                        finding["cwe"] = PLUGIN_CWE
                        finding["cvss"] = PLUGIN_CVSS
                        finding["owasp"] = PLUGIN_OWASP
                        return finding

            except Exception:
                continue
    except Exception:
        pass
    return None
