"""
Response Analyzer — Multi-signal vulnerability detection engine.

Provides:
  - Response diffing with normalization (strips CSRF tokens, timestamps, etc.)
  - Confidence scoring from multiple detection signals
  - WAF/rate-limit detection
  - Executable context detection for XSS reflection validation
  - Baseline response caching

This is the CORE of the scanner's false-positive elimination.
Every plugin should use this module instead of raw string matching.
"""

import re
import math
import threading
import difflib
from urllib.parse import urlparse
from core.config import ScannerConfig


# ── Response Normalization ──────────────────────────────────────────────

# Patterns to strip before diffing (these change on every request)
_DYNAMIC_PATTERNS = [
    # CSRF tokens
    re.compile(r'name=["\']?csrf[^"\']*["\']?\s+value=["\'][^"\']+["\']', re.I),
    re.compile(r'name=["\']?_token["\']?\s+value=["\'][^"\']+["\']', re.I),
    re.compile(r'name=["\']?authenticity_token["\']?\s+value=["\'][^"\']+["\']', re.I),
    # Session IDs in HTML
    re.compile(r'(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|csrftoken)\s*=\s*[a-zA-Z0-9_-]+', re.I),
    # Timestamps (ISO, Unix, human-readable)
    re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'),
    re.compile(r'\b\d{10,13}\b'),  # Unix timestamps
    # Random nonces / hashes
    re.compile(r'nonce=["\'][a-f0-9]{8,}["\']', re.I),
    re.compile(r'[a-f0-9]{32,64}'),  # MD5/SHA hashes
    # Cache-busting query params
    re.compile(r'[?&]_=\d+'),
    re.compile(r'[?&]v=\d+'),
    # Ad content / tracking pixels
    re.compile(r'<script[^>]*(?:google|facebook|analytics|gtag|pixel)[^>]*>.*?</script>', re.I | re.S),
]


def normalize_response(text):
    """
    Strip dynamic fields from response text for accurate comparison.
    Removes CSRF tokens, session IDs, timestamps, nonces, ad scripts.
    """
    result = text
    for pattern in _DYNAMIC_PATTERNS:
        result = pattern.sub("", result)
    # Normalize whitespace
    result = re.sub(r'\s+', ' ', result).strip()
    return result


# ── Response Diffing ────────────────────────────────────────────────────

def diff_responses(baseline_text, injected_text):
    """
    Compute similarity ratio between baseline and injected responses.
    Returns float 0.0 (completely different) to 1.0 (identical).
    Uses normalized text to eliminate dynamic content noise.
    """
    norm_base = normalize_response(baseline_text)
    norm_inject = normalize_response(injected_text)

    if not norm_base and not norm_inject:
        return 1.0
    if not norm_base or not norm_inject:
        return 0.0

    # Use SequenceMatcher for accurate comparison
    return difflib.SequenceMatcher(None, norm_base, norm_inject).ratio()


def cosine_similarity(text1, text2):
    """Bag-of-words cosine similarity for fast large-text comparison."""
    word_pattern = re.compile(r"\w+")
    words1 = word_pattern.findall(text1.lower())
    words2 = word_pattern.findall(text2.lower())

    dict1 = {}
    for w in words1:
        dict1[w] = dict1.get(w, 0) + 1
    dict2 = {}
    for w in words2:
        dict2[w] = dict2.get(w, 0) + 1

    intersection = set(dict1.keys()) & set(dict2.keys())
    numerator = sum(dict1[x] * dict2[x] for x in intersection)
    sum1 = sum(v ** 2 for v in dict1.values())
    sum2 = sum(v ** 2 for v in dict2.values())
    denominator = math.sqrt(sum1) * math.sqrt(sum2)

    if not denominator:
        return 0.0
    return float(numerator) / denominator


# ── WAF / Rate-Limit Detection ─────────────────────────────────────────

def detect_waf_block(response):
    """
    Check if a response indicates WAF block or rate limiting.
    Returns: (is_blocked: bool, reason: str)
    """
    if response is None:
        return False, ""

    # Status code check
    if response.status_code in ScannerConfig.WAF_STATUS_CODES:
        return True, f"WAF/block status code {response.status_code}"

    # Rate limiting
    if response.status_code == 429:
        return True, "Rate limited (429)"

    # Body content check
    body_lower = response.text.lower()[:5000]  # Only check first 5KB
    for indicator in ScannerConfig.WAF_BODY_INDICATORS:
        if indicator in body_lower:
            return True, f"WAF indicator in body: '{indicator}'"

    # Header check
    headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
    for hdr in ScannerConfig.WAF_HEADERS:
        if ":" in hdr:
            key, val = hdr.split(":", 1)
            if key.strip() in headers_lower and val.strip() in headers_lower.get(key.strip(), ""):
                return True, f"WAF header: {hdr}"
        else:
            if hdr in headers_lower:
                return True, f"WAF header present: {hdr}"

    return False, ""


def is_redirect(response):
    """Check if response is a redirect (not a vulnerability indicator)."""
    if response is None:
        return True
    return response.status_code in {301, 302, 303, 307, 308}


# ── Confidence Scoring ──────────────────────────────────────────────────

def calculate_confidence(signals):
    """
    Calculate confidence score from multiple detection signals.

    Args:
        signals: dict of signal_name -> True/False/float
                 signal names should match ScannerConfig.SIGNAL_WEIGHTS keys

    Returns:
        int: confidence score 0-100

    Example:
        signals = {
            "error_string": True,
            "response_diff": True,
            "timing_anomaly": False,
        }
        # Returns: 45 (25 + 20 = 45 out of max possible)
    """
    total = 0
    max_possible = 0

    for signal_name, value in signals.items():
        weight = ScannerConfig.SIGNAL_WEIGHTS.get(signal_name, 10)
        max_possible += weight

        if isinstance(value, bool):
            if value:
                total += weight
        elif isinstance(value, (int, float)):
            total += int(weight * min(value, 1.0))

    if max_possible == 0:
        return 0

    # Scale to 0-100
    raw_score = (total / max_possible) * 100
    return min(int(raw_score), 100)


def get_confidence_label(score):
    """Return human-readable confidence label."""
    if score >= ScannerConfig.CONFIDENCE_CONFIRMED:
        return "CONFIRMED"
    elif score >= ScannerConfig.CONFIDENCE_POSSIBLE:
        return "POSSIBLE"
    else:
        return "NOISE"


# ── XSS Context Detection ──────────────────────────────────────────────

_EXECUTABLE_CONTEXTS = [
    # Inside script tag
    re.compile(r'<script[^>]*>.*?PAYLOAD.*?</script>', re.I | re.S),
    # Event handler attribute
    re.compile(r'on\w+\s*=\s*["\'].*?PAYLOAD', re.I),
    # Inside an href with javascript:
    re.compile(r'href\s*=\s*["\']javascript:.*?PAYLOAD', re.I),
    # Unquoted attribute value
    re.compile(r'<[^>]+\s+\w+\s*=\s*PAYLOAD', re.I),
    # Direct HTML body (not inside a comment or CDATA)
    re.compile(r'(?<!<!--\s)PAYLOAD(?!\s*-->)', re.I),
]

_NON_EXECUTABLE_CONTEXTS = [
    # Inside HTML comment
    re.compile(r'<!--.*?PAYLOAD.*?-->', re.I | re.S),
    # Inside a <textarea> or <title>
    re.compile(r'<(?:textarea|title)[^>]*>.*?PAYLOAD.*?</(?:textarea|title)>', re.I | re.S),
    # Inside an attribute value that is properly quoted and HTML-encoded
    re.compile(r'value\s*=\s*["\'][^"\']*?(&lt;|&gt;|&amp;).*?PAYLOAD', re.I),
]


def is_in_executable_context(payload, response_text):
    """
    Check if a reflected XSS payload is in an executable HTML context.
    Returns True if the payload could actually execute (not just reflected in a safe context).
    """
    if payload not in response_text:
        return False

    # Check if it's in a non-executable context first
    for pattern in _NON_EXECUTABLE_CONTEXTS:
        check_pattern = re.compile(pattern.pattern.replace("PAYLOAD", re.escape(payload)), pattern.flags)
        if check_pattern.search(response_text):
            return False

    # Check for HTML-encoded reflection (safe)
    escaped_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
    if escaped_payload in response_text and payload not in response_text.replace(escaped_payload, ""):
        return False

    # If the raw payload is in the response and Content-Type is HTML, it's executable
    return True


# ── Baseline Cache ──────────────────────────────────────────────────────

_baseline_cache = {}
_baseline_lock = threading.Lock()


def get_baseline(url, http_get_func):
    """
    Get baseline response for a URL (cached per URL).
    Returns dict with: text, status_code, elapsed, content_length, headers
    """
    with _baseline_lock:
        if url in _baseline_cache:
            return _baseline_cache[url]

    try:
        r = http_get_func(url)
        baseline = {
            "text": r.text,
            "text_lower": r.text.lower(),
            "status_code": r.status_code,
            "elapsed": r.elapsed.total_seconds(),
            "content_length": len(r.text),
            "headers": dict(r.headers),
            "normalized": normalize_response(r.text),
        }
    except Exception:
        baseline = {
            "text": "",
            "text_lower": "",
            "status_code": 0,
            "elapsed": 1.0,
            "content_length": 0,
            "headers": {},
            "normalized": "",
        }

    with _baseline_lock:
        _baseline_cache[url] = baseline
    return baseline


def clear_baseline_cache():
    """Clear the baseline cache (e.g., between scans)."""
    with _baseline_lock:
        _baseline_cache.clear()


# ── Enhanced Result Builder ─────────────────────────────────────────────

def make_finding(url, vuln_type, confidence, signals, details="",
                 severity="Medium", payload="", evidence="", parameter=""):
    """
    Create a standardized finding dict with confidence scoring.
    Only returns the finding if confidence meets the POSSIBLE threshold.
    Returns None for noise-level findings.
    """
    label = get_confidence_label(confidence)

    if confidence < ScannerConfig.CONFIDENCE_POSSIBLE:
        return None  # Skip noise

    signal_names = [k for k, v in signals.items() if v]

    return {
        "url": url,
        "vuln": vuln_type,
        "status": label,
        "details": details,
        "severity": severity,
        "payload": payload,
        "confidence": confidence,
        "signals": signal_names,
        "evidence": evidence[:200] if evidence else "",
        "parameter": parameter,
    }
