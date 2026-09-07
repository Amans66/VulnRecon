"""
HTTP Verb Tampering Detection Plugin v5.0.

Tests if sensitive endpoints accept unconventional methods
(like HEAD, OPTIONS, PUT, DELETE, TRACE) leading to access control bypass
or unintended behavior.
"""

from core.http_client import session, DEFAULT_TIMEOUT
from core.config import ScannerConfig
from core.response_analyzer import make_finding, calculate_confidence

# Methods to test
DANGEROUS_VERBS = ["PUT", "DELETE", "TRACE", "TRACK", "OPTIONS"]


def test_http_verbs(url):
    findings = []
    
    try:
        # Check standard GET baseline
        r_get = session.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
        baseline_status = r_get.status_code
        
        # Only test if the GET request implies a restriction (e.g. 401, 403, 405)
        # OR if we want to aggressively look for enabled dangerous methods on public pages
        
        for verb in DANGEROUS_VERBS:
            try:
                r_test = session.request(verb, url, timeout=DEFAULT_TIMEOUT, verify=False)
                
                # Case 1: TRACE/TRACK method enabled (XST risk)
                if verb in ["TRACE", "TRACK"] and r_test.status_code == 200:
                    if "TRACE /" in r_test.text or "TRACK /" in r_test.text:
                        signals = {
                            "missing_protection": True,
                            "reflection": True,
                        }
                        f = make_finding(
                            url, f"HTTP {verb} Method Enabled",
                            confidence=90, signals=signals,
                            details=f"The {verb} method is enabled, which can lead to Cross-Site Tracing (XST) if combined with XSS.",
                            severity="Medium", payload=verb,
                        )
                        if f: findings.append(f)
                        
                # Case 2: PUT/DELETE method enabled unexpectedly
                elif verb in ["PUT", "DELETE"] and r_test.status_code in [200, 201, 204]:
                    signals = {"missing_protection": True}
                    f = make_finding(
                        url, f"Dangerous HTTP Method: {verb}",
                        confidence=70, signals=signals,
                        details=f"The {verb} method returned {r_test.status_code}, indicating it might be allowed.",
                        severity="Medium", payload=verb,
                    )
                    if f: findings.append(f)
                    
                # Case 3: Verb Tampering Authentication Bypass
                # If GET was forbidden (403/401) but an obscure verb was allowed (200)
                elif baseline_status in [401, 403] and r_test.status_code == 200:
                    signals = {
                        "missing_protection": True,
                        "behavioral_anomaly": True,
                        "multi_signal": True,
                    }
                    f = make_finding(
                        url, "Authentication Bypass via HTTP Verb Tampering",
                        confidence=85, signals=signals,
                        details=f"GET returned {baseline_status}, but {verb} returned 200 OK. This indicates an access control bypass.",
                        severity="High", payload=verb, evidence=f"GET:{baseline_status} vs {verb}:{r_test.status_code}",
                    )
                    if f: findings.append(f)

            except Exception:
                continue

    except Exception:
        pass

    if not findings:
        return None
    if len(findings) == 1:
        return findings[0]
    return findings
