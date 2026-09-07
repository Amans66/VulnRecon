"""
Remote File Inclusion (RFI) Scanner — Industrial-Grade Detection v5.0.

Injects known external URLs and checks if the response contains
content from those URLs (proving server-side inclusion).
Expanded payloads to cover protocol variations and wrappers.
"""

from core.http_client import get, DEFAULT_TIMEOUT
from core.config import ScannerConfig
from core.response_analyzer import (
    get_baseline, diff_responses, detect_waf_block,
    calculate_confidence, make_finding,
)
from core.utils import inject_into_params

RFI_PAYLOADS = [
    # Basic HTTP
    ("http://www.google.com/robots.txt", ["user-agent:", "disallow:", "sitemap:"]),
    ("https://www.google.com/robots.txt", ["user-agent:", "disallow:", "sitemap:"]),
    
    # Bypass patterns
    ("//www.google.com/robots.txt", ["user-agent:", "disallow:", "sitemap:"]),
    ("////www.google.com/robots.txt", ["user-agent:", "disallow:", "sitemap:"]),
    ("https:\\/\\/www.google.com/robots.txt", ["user-agent:", "disallow:", "sitemap:"]),
    
    # PHP specific
    ("php://filter/read=convert.base64-encode/resource=http://www.google.com/robots.txt", ["VXNlci1hZ2Vud"]),
    
    # Data URIs
    ("data://text/plain;base64,PD9waHAgZWNobyAnUkZJX1RFU1RfQ09ORklSTUVEJzsgPz4=", ["RFI_TEST_CONFIRMED"]),
    ("data:text/plain,RFI_TEST_CONFIRMED_PLAIN", ["RFI_TEST_CONFIRMED_PLAIN"]),
]


def test_rfi(url):
    baseline = get_baseline(url, get)

    for payload, indicators in RFI_PAYLOADS:
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

                if not signals.get("file_content"):
                    continue

                signals["response_diff"] = diff_responses(baseline["text"], r.text) < ScannerConfig.DIFF_THRESHOLD
                signals["content_length"] = abs(len(r.text) - baseline["content_length"]) > 200

                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    return make_finding(
                        url, "Remote File Inclusion (RFI)", confidence, signals,
                        details=f"External content '{evidence}' via param '{param}'",
                        severity="Critical", payload=payload,
                        evidence=evidence, parameter=param,
                    )
            except Exception:
                continue

    return None