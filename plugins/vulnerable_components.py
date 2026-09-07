"""
Vulnerable Components Detection Plugin v5.0.

Checks response headers and HTML bodies (for JS libraries) to detect
known vulnerable or end-of-life (EOL) software versions.
"""

import re
from core.http_client import session, DEFAULT_TIMEOUT
from core.response_analyzer import make_finding

# Extended patterns for headers
HEADER_VULNERABLE = {
    "apache/2.2": "Apache 2.2.x is EOL (Critical vulnerabilities)",
    "apache/2.4.49": "Apache 2.4.49 is vulnerable to CVE-2021-41773 (Path Traversal/RCE)",
    "apache/2.4.50": "Apache 2.4.50 is vulnerable to CVE-2021-42013 (Path Traversal/RCE)",
    "apache/tomcat/7": "Tomcat 7.x is EOL",
    "apache/tomcat/8.0": "Tomcat 8.0.x is EOL",
    "nginx/1.0": "Nginx 1.0.x is heavily outdated",
    "php/5.": "PHP 5.x is EOL and highly vulnerable",
    "php/7.0": "PHP 7.0.x is EOL",
    "php/7.1": "PHP 7.1.x is EOL",
    "php/7.2": "PHP 7.2.x is EOL",
    "php/7.3": "PHP 7.3.x is EOL",
    "php/7.4": "PHP 7.4.x is EOL",
    "php/8.0": "PHP 8.0.x is EOL",
    "iis/6": "IIS 6 is EOL (Windows Server 2003)",
    "iis/7": "IIS 7 is EOL (Windows Server 2008)",
    "iis/8": "IIS 8 is EOL",
    "openssl/1.0": "OpenSSL 1.0.x is EOL",
    "openssl/1.1.0": "OpenSSL 1.1.0 is EOL",
}

# Regex patterns to detect JS libraries in HTML body
JS_LIB_PATTERNS = [
    # jQuery
    (re.compile(r'jquery[^\w]*([12]\.[0-9]+\.[0-9]+)\.(?:min\.)?js', re.I), "jQuery", "3.6.0"),
    (re.compile(r'jquery[/-]([12]\.[0-9]+\.[0-9]+)', re.I), "jQuery", "3.6.0"),
    # Angular
    (re.compile(r'angular[^\w]*([1]\.[0-9]+\.[0-9]+)', re.I), "AngularJS", "1.8.3"),
    # React
    (re.compile(r'react(?:-dom)?[@/](0\.[0-9]+|1[0-5]\.[0-9]+)', re.I), "React", "16.0.0"),
    # Vue
    (re.compile(r'vue[@/]([1]\.[0-9]+|2\.[0-5]\.[0-9]+)', re.I), "Vue", "2.6.0"),
    # Bootstrap
    (re.compile(r'bootstrap[/-]([123]\.[0-9]+\.[0-9]+)', re.I), "Bootstrap", "4.0.0"),
]


def _parse_version(v_str):
    """Simple version parser for comparison."""
    try:
        parts = [int(p) for p in re.findall(r'\d+', v_str)]
        return tuple(parts)
    except Exception:
        return (0, 0, 0)


def test_vulnerable_components(url):
    findings = []
    
    try:
        r = session.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
        headers = r.headers
        server = headers.get("Server", "").lower()
        powered = headers.get("X-Powered-By", "").lower()
        combined = f"{server} {powered}"
        
        # ── 1. Check Headers ──
        for pattern, desc in HEADER_VULNERABLE.items():
            if pattern in combined:
                signals = {
                    "version_vuln": True,
                    "header_indicator": True,
                }
                severity = "High" if "CVE-" in desc or "EOL" in desc else "Medium"
                
                f = make_finding(
                    url, "Vulnerable / Outdated Component",
                    confidence=90, signals=signals,
                    details=f"{desc}",
                    severity=severity, payload=pattern,
                    evidence=f"Detected: {combined.strip()}",
                )
                if f: findings.append(f)

        # ── 2. Check JavaScript Libraries in HTML ──
        if "text/html" in headers.get("Content-Type", "").lower():
            text = r.text
            found_libs = {}
            
            for pattern, lib_name, safe_version in JS_LIB_PATTERNS:
                for match in pattern.finditer(text):
                    version = match.group(1)
                    v_tuple = _parse_version(version)
                    safe_tuple = _parse_version(safe_version)
                    
                    if v_tuple and v_tuple < safe_tuple:
                        found_libs[lib_name] = version
            
            for lib_name, version in found_libs.items():
                signals = {
                    "version_vuln": True,
                    "file_content": True,
                }
                f = make_finding(
                    url, f"Outdated Frontend Library ({lib_name})",
                    confidence=85, signals=signals,
                    details=f"Detected outdated {lib_name} version {version} (known safe >= {safe_version})",
                    severity="Medium", payload=lib_name,
                    evidence=f"{lib_name} {version} included in HTML",
                )
                if f: findings.append(f)
                
    except Exception:
        pass

    if not findings:
        return None
    if len(findings) == 1:
        return findings[0]
    return findings
