"""
Security Misconfiguration Plugin v5.0.

Tests for missing security headers, detailed error pages, default pages,
and exposed configuration files across the entire domain.
"""

from urllib.parse import urlparse, urljoin
from core.http_client import session, DEFAULT_TIMEOUT
from core.response_analyzer import make_finding
from core.deep_analyzer import HeaderSecurityScorer


def test_security_misconfiguration(url):
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None

    base_url = f"{parsed.scheme}://{parsed.netloc}"
    findings = []

    # 1. Header Security Scoring
    try:
        r = session.get(base_url, timeout=DEFAULT_TIMEOUT, verify=False)
        scorer = HeaderSecurityScorer(r.headers)
        result = scorer.analyze()
        
        if result["grade"] in ["C", "D", "F"]:
            missing = ", ".join(result["missing_headers"][:3]) + ("..." if len(result["missing_headers"]) > 3 else "")
            
            f = make_finding(
                base_url, "Security Misconfiguration (Headers)",
                confidence=85,
                signals={"missing_protection": True, "header_indicator": True},
                details=f"Header Security Grade: {result['grade']} ({result['score']}/{result['max_score']}). Missing critical headers: {missing}.",
                severity="Medium" if result["grade"] == "C" else "High",
                evidence=f"Grade: {result['grade']}. Issues: {', '.join(result['issues'][:2])}",
            )
            if f: findings.append(f)
            
        if result["dangerous_headers"]:
            f = make_finding(
                base_url, "Information Disclosure (Headers)",
                confidence=90,
                signals={"config_exposure": True, "header_indicator": True},
                details=f"Server exposes technology details in headers: {', '.join(result['dangerous_headers'])}",
                severity="Low",
                evidence=f"Dangerous headers: {', '.join(result['dangerous_headers'])}",
            )
            if f: findings.append(f)
            
    except Exception:
        pass

    # 2. Exposed Config Files (Root level)
    config_paths = [
        "/.git/config", "/.env", "/docker-compose.yml", "/phpinfo.php",
        "/server-status", "/WEB-INF/web.xml"
    ]
    
    for path in config_paths:
        try:
            target = urljoin(base_url, path)
            r = session.get(target, timeout=DEFAULT_TIMEOUT, verify=False, allow_redirects=False)
            
            if r.status_code == 200:
                is_hit = False
                
                # Verify it's actually the file and not a soft-404
                if ".git/config" in path and "[core]" in r.text: is_hit = True
                elif ".env" in path and ("=" in r.text and "<html" not in r.text[:100].lower()): is_hit = True
                elif "docker-compose" in path and "version:" in r.text: is_hit = True
                elif "phpinfo" in path and "<title>phpinfo()</title>" in r.text: is_hit = True
                elif "server-status" in path and "Apache Status" in r.text: is_hit = True
                elif "web.xml" in path and "<web-app" in r.text: is_hit = True
                
                if is_hit:
                    f = make_finding(
                        target, "Security Misconfiguration (Exposed File)",
                        confidence=95,
                        signals={"config_exposure": True, "file_content": True},
                        details=f"Sensitive configuration file exposed at {path}",
                        severity="High" if ".env" in path or ".git" in path else "Medium",
                        payload=path,
                    )
                    if f: findings.append(f)
        except Exception:
            continue

    if not findings:
        return None
    if len(findings) == 1:
        return findings[0]
    return findings
