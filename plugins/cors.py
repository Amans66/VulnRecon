"""
CORS Misconfiguration Plugin.

Tests CORS policy by:
1. Sending an evil Origin in a GET request and checking if it's reflected.
2. Checking if ACAO is wildcard (*) with dangerous methods.
3. Checking if Allow-Credentials is used with wildcard or reflected origin.
4. Testing null origin bypass.
5. Testing subdomain-based origin bypass (evil.target.com).

Follows OWASP CORS testing guidelines.
Uses core.http_client and modern make_finding confidence scoring.
"""

from urllib.parse import urlparse
from core.http_client import get, session, DEFAULT_TIMEOUT
from core.response_analyzer import make_finding


def test_cors(url):
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None

    target_domain = parsed.netloc.split(":")[0]
    findings = []

    evil_origin = "https://evil-cors-tester.com"

    try:
        # ── Test 1: Reflected arbitrary origin ──
        r = get(url, headers={"Origin": evil_origin}, allow_redirects=True)

        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        acam = r.headers.get("Access-Control-Allow-Methods", "")

        # Critical: Server reflects arbitrary origin with credentials
        if acao == evil_origin:
            if acac == "true":
                signals = {
                    "header_reflection": True,
                    "missing_protection": True,
                    "multi_signal": True,
                }
                f = make_finding(
                    url, "CORS Misconfiguration",
                    confidence=90,
                    signals=signals,
                    details="Server reflects arbitrary Origin with Allow-Credentials: true — allows cross-origin data theft",
                    severity="Critical",
                    payload=f"Origin: {evil_origin}",
                    evidence=f"ACAO: {acao} | ACAC: {acac}",
                )
                if f:
                    findings.append(f)
            else:
                signals = {
                    "header_reflection": True,
                    "missing_protection": True,
                }
                f = make_finding(
                    url, "CORS Misconfiguration",
                    confidence=75,
                    signals=signals,
                    details="Server reflects arbitrary Origin headers in ACAO (no credentials)",
                    severity="High",
                    payload=f"Origin: {evil_origin}",
                    evidence=f"ACAO: {acao}",
                )
                if f:
                    findings.append(f)

        # Medium: Wildcard ACAO (*)
        if acao == "*":
            if acac == "true":
                signals = {"missing_protection": True, "multi_signal": True}
                f = make_finding(
                    url, "CORS Misconfiguration",
                    confidence=70,
                    signals=signals,
                    details="Wildcard ACAO (*) with Allow-Credentials: true (spec violation, browser-dependent)",
                    severity="High",
                    payload=f"Origin: {evil_origin}",
                    evidence=f"ACAO: * | ACAC: true",
                )
                if f:
                    findings.append(f)
            elif acam:
                dangerous = [m.strip().upper() for m in acam.split(",")]
                write_methods = {"PUT", "DELETE", "PATCH"}
                if write_methods & set(dangerous):
                    signals = {"missing_protection": True}
                    f = make_finding(
                        url, "CORS Misconfiguration",
                        confidence=60,
                        signals=signals,
                        details=f"Wildcard ACAO (*) with dangerous methods allowed: {acam}",
                        severity="Medium",
                        payload=f"ACAO: * | Methods: {acam}",
                    )
                    if f:
                        findings.append(f)
    except Exception:
        pass

    # ── Test 2: Null origin bypass ──
    try:
        r = get(url, headers={"Origin": "null"}, allow_redirects=True)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "null":
            confidence = 85 if acac == "true" else 65
            severity = "High" if acac == "true" else "Medium"
            cred_note = " with Allow-Credentials: true" if acac == "true" else ""
            signals = {"header_reflection": True, "missing_protection": True}
            f = make_finding(
                url, "CORS Misconfiguration",
                confidence=confidence,
                signals=signals,
                details=f"Server reflects 'null' Origin{cred_note} — exploitable via sandboxed iframes",
                severity=severity,
                payload="Origin: null",
                evidence=f"ACAO: null | ACAC: {acac}",
            )
            if f:
                findings.append(f)
    except Exception:
        pass

    # ── Test 3: Subdomain-based origin bypass (evil.target.com) ──
    try:
        evil_subdomain = f"https://evil.{target_domain}"
        r = get(url, headers={"Origin": evil_subdomain}, allow_redirects=True)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == evil_subdomain:
            confidence = 80 if acac == "true" else 60
            severity = "High" if acac == "true" else "Medium"
            cred_note = " with credentials" if acac == "true" else ""
            signals = {"header_reflection": True, "missing_protection": True}
            f = make_finding(
                url, "CORS Misconfiguration",
                confidence=confidence,
                signals=signals,
                details=f"Server accepts subdomain-based origin bypass{cred_note} — attacker can exploit via evil.{target_domain}",
                severity=severity,
                payload=f"Origin: {evil_subdomain}",
                evidence=f"ACAO: {acao} | ACAC: {acac}",
            )
            if f:
                findings.append(f)
    except Exception:
        pass

    # ── Test 4: OPTIONS preflight with evil origin ──
    try:
        headers = {
            "Origin": evil_origin,
            "Access-Control-Request-Method": "PUT",
        }
        r = session.options(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)

        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == evil_origin:
            confidence = 75 if acac == "true" else 60
            severity = "High" if acac == "true" else "Medium"
            cred_note = " with Allow-Credentials" if acac == "true" else ""
            signals = {"header_reflection": True, "missing_protection": True}
            f = make_finding(
                url, "CORS Misconfiguration",
                confidence=confidence,
                signals=signals,
                details=f"Preflight reflects arbitrary Origin{cred_note}",
                severity=severity,
                payload=f"Origin: {evil_origin}",
                evidence=f"Preflight ACAO: {acao}",
            )
            if f:
                findings.append(f)
    except Exception:
        pass

    if not findings:
        return None
    if len(findings) == 1:
        return findings[0]
    return findings
