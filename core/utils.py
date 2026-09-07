"""
Utility helpers shared across all plugins.
Includes advanced detection helpers: wildcard profiles, cosine text similarity, and baselines.
"""

from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from core.http_client import get
import math
import re
import uuid
import threading

def make_result(url, vuln_name, status="Vulnerable", details="", severity="Medium", payload=""):
    """
    Standardised vulnerability result dict.
    Every plugin MUST return this format or None.
    """
    return {
        "url":      url,
        "vuln":     vuln_name,
        "status":   status,
        "details":  details,
        "severity": severity,
        "payload":  payload,
    }


def get_forms(url):
    """Return all <form> elements on the page."""
    try:
        soup = BeautifulSoup(get(url).text, "html.parser")
        return soup.find_all("form")
    except Exception:
        return []


def extract_params(url):
    """Return a dict of query-string parameters."""
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


# Common parameters that dynamic web pages often accept
COMMON_PROBE_PARAMS = ["id", "page", "file", "url", "q", "query", "search", "category", "name", "user", "item", "action"]

def inject_into_params(url, payload):
    """
    Yield (param_name, crafted_url) for each query-string parameter
    with its value replaced by `payload`.

    If the URL has NO existing query parameters, probe with common
    parameter names to discover hidden inputs.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if params:
        # Inject into existing parameters
        for param in params:
            modified = {k: v[0] for k, v in params.items()}
            modified[param] = payload
            new_query = urlencode(modified)
            new_url = urlunparse(parsed._replace(query=new_query))
            yield param, new_url
    else:
        # Smart probe: try common parameter names
        for param in COMMON_PROBE_PARAMS:
            new_query = urlencode({param: payload})
            new_url = urlunparse(parsed._replace(query=new_query))
            yield param, new_url


def submit_form(form, url, payload):
    """Fill every text-like input with `payload` and submit the form."""
    from core.http_client import post as http_post

    action = form.get("action")
    post_url = urljoin(url, action)
    method   = form.get("method", "get").lower()
    data = {}

    for tag in form.find_all(["input", "textarea"]):
        name = tag.get("name")
        if not name:
            continue
        input_type = tag.get("type", "text").lower()
        if input_type in ("text", "search", "url", "email", "tel", "hidden", ""):
            data[name] = payload
        elif input_type == "password":
            data[name] = payload
        else:
            data[name] = tag.get("value", "test")

    if method == "post":
        return http_post(post_url, data=data)
    else:
        return get(post_url, params=data)


# ── Dynamic Wildcard Profiling ──────────────────────────────────────────
_wildcard_cache = {}
_wildcard_lock = threading.Lock()

def get_wildcard_profile(base_url):
    """
    Query a non-existent UUID path on the host to profile dynamic soft-404s/redirects.
    """
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    
    with _wildcard_lock:
        if root in _wildcard_cache:
            return _wildcard_cache[root]

    random_path = f"/{uuid.uuid4().hex}"
    test_url = f"{root}{random_path}"
    
    try:
        r = get(test_url, allow_redirects=False, timeout=5)
        profile = {
            "status_code": r.status_code,
            "length": len(r.text),
            "location": r.headers.get("Location", "")
        }
    except Exception:
        profile = None

    with _wildcard_lock:
        _wildcard_cache[root] = profile
    return profile


_wildcard_body_cache = {}
_wildcard_body_lock = threading.Lock()

def get_wildcard_body(base_url):
    """
    Fetch the response body for a random UUID path on the host.
    Used by plugins to compare candidate responses against soft-404 content.
    Cached per root origin.
    """
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    with _wildcard_body_lock:
        if root in _wildcard_body_cache:
            return _wildcard_body_cache[root]

    random_path = f"/{uuid.uuid4().hex}"
    test_url = f"{root}{random_path}"

    try:
        r = get(test_url, allow_redirects=True, timeout=5)
        body = r.text
    except Exception:
        body = ""

    with _wildcard_body_lock:
        _wildcard_body_cache[root] = body
    return body


# ── Cosine Text Similarity ───────────────────────────────────────────────
def get_cosine_similarity(text1, text2):
    """Computes basic bag-of-words Cosine Similarity between two text blocks."""
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
    numerator = sum([dict1[x] * dict2[x] for x in intersection])

    sum1 = sum([dict1[x]**2 for x in dict1.keys()])
    sum2 = sum([dict2[x]**2 for x in dict2.keys()])
    denominator = math.sqrt(sum1) * math.sqrt(sum2)

    if not denominator:
        return 0.0
    return float(numerator) / denominator


# ── Baseline Response Helper ─────────────────────────────────────────────
_baseline_cache = {}
_baseline_lock = threading.Lock()

def get_baseline_text(url):
    """Returns the baseline (unmodified) response body in lowercase, cached per URL."""
    with _baseline_lock:
        if url in _baseline_cache:
            return _baseline_cache[url]

    try:
        text = get(url).text.lower()
    except Exception:
        text = ""

    with _baseline_lock:
        _baseline_cache[url] = text
    return text

