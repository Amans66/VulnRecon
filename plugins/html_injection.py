"""
HTML Injection Detection Plugin v5.0.
Uses canary-based detection with baseline comparison to confirm tags are actually rendered,
not just reflected or entity-encoded.
"""

from core.http_client import get, DEFAULT_TIMEOUT
from core.config import ScannerConfig
from core.response_analyzer import (
    get_baseline, diff_responses, detect_waf_block,
    calculate_confidence, make_finding,
)
from core.utils import inject_into_params

CANARY = "HTMLINJ7k9x"

PAYLOADS = [
    f"<b>{CANARY}</b>",
    f"<i>{CANARY}</i>",
    f"<u>{CANARY}</u>",
    f"<h1>{CANARY}</h1>",
    f"<marquee>{CANARY}</marquee>",
    f'<a href="https://evil.com">{CANARY}</a>',
    f'<img src=x alt="{CANARY}">',
    f'<div style="font-size:100px;">{CANARY}</div>',
]


def test_html_injection(url):
    baseline = get_baseline(url, get)

    for payload in PAYLOADS:
        for param, crafted_url in inject_into_params(url, payload):
            try:
                r = get(crafted_url, timeout=DEFAULT_TIMEOUT)
                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                ct = r.headers.get("Content-Type", "").lower()
                if "text/html" not in ct:
                    continue

                # Canary must be reflected AND payload must be rendered (not encoded)
                if CANARY not in r.text:
                    continue
                if payload not in r.text:
                    continue
                if payload in baseline["text"]:
                    continue

                signals = {
                    "reflection": True,
                    "response_diff": diff_responses(baseline["text"], r.text) < 0.95,
                }

                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    return make_finding(
                        url, "HTML Injection", confidence, signals,
                        details=f"HTML tag rendered successfully via param '{param}'",
                        severity="Medium", payload=payload,
                        evidence=payload[:50], parameter=param,
                    )
            except Exception:
                continue

    return None