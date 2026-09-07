"""
IDOR (Insecure Direct Object Reference) Detection Plugin v5.0.

Tests sequential ID enumeration on common endpoints to detect
access control failures.

Uses wildcard/soft-404 detection and response differential analysis
with confidence scoring to avoid false positives.
"""

from urllib.parse import urlparse
from core.http_client import get, DEFAULT_TIMEOUT
from core.config import ScannerConfig
from core.response_analyzer import make_finding, diff_responses, calculate_confidence
from core.utils import get_wildcard_body

PATHS = [
    "/user/{id}",
    "/api/user/{id}",
    "/profile/{id}",
    "/account/{id}",
    "/order/{id}",
    "/api/order/{id}",
    "/invoice/{id}",
    "/document/{id}",
]


def test_idor(url):
    # Host-only: only run on root URLs, skip deep crawled paths
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None

    base = url.rstrip("/")

    # Get wildcard body for soft-404 detection
    wildcard_body = get_wildcard_body(base)
    
    for path_template in PATHS:
        responses = {}
        bodies = {}
        for test_id in [1, 2, 999]:
            path = path_template.replace("{id}", str(test_id))
            test_url = f"{base}{path}"
            try:
                r = get(test_url, timeout=DEFAULT_TIMEOUT)
                responses[test_id] = (r.status_code, len(r.text))
                bodies[test_id] = r.text
            except Exception:
                responses[test_id] = (None, 0)
                bodies[test_id] = ""

        # If multiple IDs return 200 with different content, possible IDOR
        ok_responses = {k: v for k, v in responses.items() if v[0] == 200}
        if len(ok_responses) >= 2:
            # Check if ALL responses look like the wildcard soft-404 page
            if wildcard_body:
                all_match_wildcard = all(
                    diff_responses(bodies[k], wildcard_body) > 0.95
                    for k in ok_responses
                )
                if all_match_wildcard:
                    continue  # All responses are just soft-404 pages

            sizes = [v[1] for v in ok_responses.values()]
            # If content sizes differ, data is actually changing per ID
            if max(sizes) - min(sizes) > 50:
                # Extra verification: check that responses differ from EACH OTHER
                # (not just in size, but in content — rules out template variations)
                ok_keys = list(ok_responses.keys())
                inter_similarity = diff_responses(
                    bodies[ok_keys[0]], bodies[ok_keys[1]]
                )
                
                # If responses are nearly identical to each other, it's likely
                # the same template with minor dynamic elements, not real IDOR
                if inter_similarity > 0.95:
                    continue

                signals = {
                    "response_diff": True,
                    "behavioral_anomaly": True,
                    "multi_signal": True,
                }
                
                confidence = calculate_confidence(signals)
                
                if confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
                    return make_finding(
                        url, "Insecure Direct Object Reference (IDOR)",
                        confidence=confidence, signals=signals,
                        details=f"Sequential IDs return different valid data at {path_template}",
                        severity="High", payload=path_template,
                        evidence=f"IDs 1, 2 returned HTTP 200 with differing content (sim: {inter_similarity:.2f})",
                    )

    return None
