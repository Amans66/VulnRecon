"""
Buffer Overflow Detection Plugin v5.0.

Sends oversized inputs and checks for server crashes (500 errors, connection drops).
Uses baseline comparison to avoid flagging servers that already return 500.
Now detects connection resets natively as a strong crash indicator.
"""

import requests
from core.http_client import session, DEFAULT_TIMEOUT
from core.config import ScannerConfig
from core.response_analyzer import (
    get_baseline, diff_responses, detect_waf_block,
    calculate_confidence, make_finding,
)
from core.utils import inject_into_params

OVERFLOW_SIZES = [1000, 5000, 10000, 50000]
OVERFLOW_PATTERNS = [
    lambda size: "A" * size,
    lambda size: "%s" * (size // 2),     # Format string
    lambda size: "\x00" * (size // 4),   # Null bytes
    lambda size: str(2**31) * (size // 10),  # Integer overflow
    lambda size: "%x" * (size // 2),     # Hex format string
]


def test_buffer_overflow(url):
    baseline = get_baseline(url, session.get)

    # Skip if baseline already returns 500 or times out
    if baseline.get("status_code", 0) >= 500 or baseline.get("status_code") is None:
        return None

    findings = []

    for size in OVERFLOW_SIZES:
        for pattern_func in OVERFLOW_PATTERNS:
            payload = pattern_func(size)
            for param, crafted_url in inject_into_params(url, payload):
                try:
                    r = session.get(crafted_url, timeout=DEFAULT_TIMEOUT, verify=False)

                    waf_blocked, _ = detect_waf_block(r)
                    if waf_blocked:
                        continue

                    signals = {}
                    evidence = ""

                    # Must get 500+ AND baseline was NOT 500+
                    if r.status_code >= 500:
                        signals["status_change"] = True
                        evidence = f"HTTP {r.status_code}"

                        # Check for crash indicators NOT in baseline
                        crash_indicators = [
                            "segmentation fault", "buffer overflow",
                            "stack smashing", "core dump",
                            "out of memory", "heap corruption",
                            "access violation", "fatal error",
                        ]
                        for ind in crash_indicators:
                            if ind in r.text.lower() and ind not in baseline.get("text_lower", ""):
                                signals["error_string"] = True
                                evidence = ind
                                break

                        # Only consider response_diff when we have a 500
                        signals["response_diff"] = diff_responses(baseline.get("text", ""), r.text) < ScannerConfig.DIFF_THRESHOLD

                        confidence = calculate_confidence(signals)
                        if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                            f = make_finding(
                                url, "Buffer Overflow / Memory Corruption", confidence, signals,
                                details=f"{evidence} with {size}-byte payload in param '{param}'",
                                severity="Critical", payload=f"[{size} bytes]",
                                evidence=evidence, parameter=param,
                            )
                            if f: findings.append(f)

                except requests.exceptions.ConnectionError as e:
                    # Connection reset/drop could indicate a hard crash (segfault)
                    if "Connection reset by peer" in str(e) or "Remote end closed connection" in str(e):
                        signals = {
                            "behavioral_anomaly": True,
                            "multi_signal": True, # Connection drop is a strong signal compared to a 500
                        }
                        confidence = calculate_confidence(signals)
                        
                        # Extra verification: Check if server is still alive
                        # If it's dead, it's a confirmed DoS
                        server_dead = False
                        try:
                            session.get(url, timeout=3, verify=False)
                        except Exception:
                            server_dead = True
                            
                        if server_dead:
                            signals["verified"] = True
                            confidence = 100
                            
                        if confidence >= ScannerConfig.CONFIDENCE_PROBABLE:
                            f = make_finding(
                                url, "Buffer Overflow (Crash/DoS)", confidence, signals,
                                details=f"Connection dropped/reset with {size}-byte payload in param '{param}'. " + 
                                        ("Server remains unresponsive (Confirmed DoS)." if server_dead else "Server recovered."),
                                severity="Critical", payload=f"[{size} bytes]",
                                evidence="Connection reset by peer / Service crash", parameter=param,
                            )
                            if f: findings.append(f)
                except Exception:
                    continue

    if not findings:
        return None
    if len(findings) == 1:
        return findings[0]
    return findings
