"""
Header Injection / CRLF Injection Detection Plugin v5.0.

Tests if user input is reflected in response headers (enabling CRLF injection,
HTTP response splitting, or cross-site scripting).
"""

from urllib.parse import urlparse
from core.http_client import get, session, DEFAULT_TIMEOUT
from core.config import ScannerConfig
from core.response_analyzer import make_finding, calculate_confidence
from core.utils import inject_into_params


# CRLF injection payloads
PAYLOADS = [
    ("\r\nInjected-Header: 1", "Injected-Header"),
    ("%0d%0aInjected-Header: 1", "Injected-Header"),
    ("%E5%98%8A%E5%98%8DInjected-Header: 1", "Injected-Header"),
]


def test_header_injection(url):
    parsed = urlparse(url)
    if not parsed.query:
        return None

    for payload, expected_header in PAYLOADS:
        for param, crafted_url in inject_into_params(url, payload):
            try:
                # We need to look at raw headers, but requests handles them as a dict.
                # If CRLF succeeds, "Injected-Header" will appear as a key.
                r = get(crafted_url, allow_redirects=False)
                
                # Check if injected header was successfully added
                headers_lower = {k.lower(): v for k, v in r.headers.items()}
                
                if expected_header.lower() in headers_lower:
                    signals = {
                        "crlf_injection": True,
                        "header_reflection": True,
                        "multi_signal": True,
                    }
                    confidence = calculate_confidence(signals)
                    
                    if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                        return make_finding(
                            url, "HTTP Header / CRLF Injection", confidence, signals,
                            details=f"CRLF payload in param '{param}' injected a new HTTP header '{expected_header}'",
                            severity="High", payload=payload,
                            evidence=f"Header {expected_header} found in response", parameter=param,
                        )
                        
            except Exception:
                continue

    return None
