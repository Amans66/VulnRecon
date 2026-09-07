"""
Directory and File Fuzzing Plugin v5.0.

Scans common hidden directories and files with proper wildcard detection.
Only reports endpoints that return genuinely different content from the
server's default error/catch-all page. Returns individual findings.
"""

from urllib.parse import urlparse
from core.http_client import session, DEFAULT_TIMEOUT
from core.config import ScannerConfig
from core.response_analyzer import make_finding, calculate_confidence, diff_responses
from core.utils import get_wildcard_profile, get_wildcard_body

# High-value targets often missed by crawling
WORDLIST = [
    # Admin panels
    "/admin", "/administrator", "/wp-admin", "/dashboard", "/cpanel",
    "/admin/login", "/wp-login.php", "/web-console", "/_admin",
    # Version Control & Dev files
    "/.git/", "/.git/HEAD", "/.git/config", "/.svn/entries", "/.env", "/.DS_Store",
    "/phpinfo.php", "/info.php", "/.hg", "/.idea/workspace.xml",
    # Backups
    "/backup.zip", "/backup.sql", "/db.sql", "/dump.sql", "/site.zip",
    "/backup.tar.gz", "/www.zip", "/db_backup.sql", "/database.sqlite",
    # Config & Secrets
    "/config.php", "/wp-config.php", "/wp-config.php.bak",
    "/docker-compose.yml", "/credentials.json", "/web.config",
    "/.aws/credentials", "/.ssh/id_rsa", "/private.key", "/settings.py",
    # APIs & Docs
    "/swagger-ui.html", "/api-docs", "/swagger.json", "/openapi.json",
    "/graphql", "/graphiql", "/server-status"
]


def test_dir_fuzzer(url):
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None

    base_url = f"{parsed.scheme}://{parsed.netloc}"
    wildcard = get_wildcard_profile(base_url)
    wildcard_body = get_wildcard_body(base_url)

    findings = []

    for path in WORDLIST:
        test_url = f"{base_url}{path}"
        try:
            r = session.get(test_url, allow_redirects=False, timeout=4, verify=False)

            # Skip if it matches the wildcard profile (soft-404)
            if wildcard and r.status_code == wildcard["status_code"]:
                # Redirect-based wildcard: skip if redirect goes to same place
                if r.status_code in [301, 302, 307, 308]:
                    if r.headers.get("Location", "") == wildcard.get("location", ""):
                        continue
                # Body-based wildcard: skip if content looks the same
                elif wildcard_body and r.status_code == 200:
                    sim = diff_responses(r.text, wildcard_body)
                    if sim > 0.90:
                        continue

            # Only report 200 OK (actually accessible) — skip 401/403
            # because many servers return 403 for ALL non-existent paths
            if r.status_code == 200:
                # Skip custom 404 pages that return 200
                text_lower = r.text.lower()
                if "404" in text_lower and "not found" in text_lower:
                    continue
                # Skip empty or tiny responses (likely error stubs)
                if len(r.text.strip()) < 50:
                    continue

                signals = {
                    "status_change": True,
                    "file_content": True
                }
                
                # Determine severity based on file extension/type
                severity = "Low"
                if any(ext in path for ext in [".sql", ".env", ".key", ".rsa", "credentials", "config"]):
                    severity = "High"
                elif any(ext in path for ext in [".zip", ".tar.gz", "admin", "dashboard", ".git"]):
                    severity = "Medium"
                    
                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_PROBABLE:
                    f = make_finding(
                        url, f"Hidden Directory/File Found ({path})",
                        confidence=confidence, signals=signals,
                        details=f"Discovered accessible endpoint at {path} returning HTTP 200 OK.",
                        severity=severity, payload=path,
                        evidence=f"HTTP 200 OK. Content length: {len(r.text)} bytes.",
                    )
                    if f: findings.append(f)

        except Exception:
            continue

    if not findings:
        return None
    if len(findings) == 1:
        return findings[0]
    return findings
