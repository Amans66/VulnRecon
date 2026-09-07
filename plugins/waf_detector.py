"""
WAF (Web Application Firewall) Detection Plugin v5.0.

Detects common WAFs by inspecting headers and injecting a known
malicious payload to see if the server blocks it.
Uses confidence scoring to indicate presence of a WAF.
"""

from urllib.parse import urlparse
from core.http_client import session, DEFAULT_TIMEOUT
from core.response_analyzer import make_finding

WAF_SIGNATURES = {
    "Cloudflare":           ["cf-ray", "cloudflare"],
    "Akamai":               ["x-akamai-transformed", "akamai-origin-hop"],
    "AWS WAF":              ["x-amzn-waf-", "awswaf"],
    "Azure WAF":            ["azure", "x-ms-request-id"],
    "Imperva / Incapsula":  ["x-iinfo", "incap_ses", "visid_incap"],
    "F5 BIG-IP":            ["bigipserver", "bigip"],
    "Sucuri":               ["x-sucuri-id", "sucuri/cloudproxy"],
    "Wordfence":            ["wordfence"],
    "ModSecurity":          ["mod_security"],
}


def test_waf_detector(url):
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None

    detected_wafs = set()
    signals = {}

    try:
        # Step 1: Passive Header Inspection
        r = session.get(url, timeout=DEFAULT_TIMEOUT, verify=False)

        headers_str = "\n".join([f"{k}: {v}".lower() for k, v in r.headers.items()])
        server = r.headers.get("Server", "").lower()

        for waf_name, signatures in WAF_SIGNATURES.items():
            if any(sig in headers_str or sig in server for sig in signatures):
                detected_wafs.add(waf_name)
                signals["header_indicator"] = True

        # Step 2: Active Detection (Triggering a block)
        blatant_payload = "<script>alert(1)</script> UNION SELECT 1,2,3--"
        test_url = f"{url}?q={blatant_payload}"

        r_active = session.get(test_url, timeout=DEFAULT_TIMEOUT, verify=False)

        if r_active.status_code in [403, 406, 429]:
            signals["status_change"] = True
            
            # Check response body for specific WAF branding
            body = r_active.text.lower()
            if "cloudflare" in body:
                detected_wafs.add("Cloudflare")
            elif "imperva" in body or "incapsula" in body:
                detected_wafs.add("Imperva / Incapsula")
            elif "wordfence" in body:
                detected_wafs.add("Wordfence")
            elif "mod_security" in body:
                detected_wafs.add("ModSecurity")
            elif "aws waf" in body:
                detected_wafs.add("AWS WAF")
            else:
                detected_wafs.add("Generic WAF / IPS (Active Block)")

        if detected_wafs:
            confidence = 90 if "header_indicator" in signals and "status_change" in signals else 75
            
            return make_finding(
                url, "Web Application Firewall (WAF) Detected",
                confidence=confidence, signals=signals,
                details=f"Target is protected by: {', '.join(detected_wafs)}",
                severity="Low",
                payload="Passive headers + Active malicious payload (<script>alert(1)</script>)",
                evidence=f"Detected signatures for: {', '.join(detected_wafs)}",
            )
            
    except Exception:
        pass

    return None
