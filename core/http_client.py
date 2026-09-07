"""
Shared HTTP client for all scanner plugins.

Uses a single requests.Session with connection pooling (HTTPAdapter),
automatic retries, a realistic User-Agent to avoid WAF blocks,
and thread-safe response caching for passive scans.
"""

import requests
import random
import threading
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from core.config import ScannerConfig

# ── Configuration ──────────────────────────────────────────────────────
DEFAULT_TIMEOUT = 8          # seconds
MAX_RETRIES     = 2
BACKOFF_FACTOR  = 0.3        # 0s, 0.3s, 0.6s between retries
POOL_CONNECTIONS = 50        # simultaneous host connections
POOL_MAXSIZE     = 50        # max pooled connections

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"
]

# Thread-safe global response cache
_response_cache = {}
_cache_lock = threading.Lock()

# ── Build session ──────────────────────────────────────────────────────
_retry_strategy = Retry(
    total=MAX_RETRIES,
    backoff_factor=BACKOFF_FACTOR,
    status_forcelist=[429, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "POST", "OPTIONS"],
)

_adapter = HTTPAdapter(
    max_retries=_retry_strategy,
    pool_connections=POOL_CONNECTIONS,
    pool_maxsize=POOL_MAXSIZE,
)

session = requests.Session()
session.mount("http://",  _adapter)
session.mount("https://", _adapter)
session.trust_env = False
session.headers.update({
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
})
session.verify = ScannerConfig.SSL_VERIFY

# Suppress InsecureRequestWarning from urllib3
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def configure_session(verify=None):
    """Update the shared session's TLS verification behavior."""
    if verify is None:
        verify = ScannerConfig.SSL_VERIFY
    session.verify = bool(verify)
    return session.verify


def _get_headers(kwargs):
    headers = kwargs.pop("headers", {})
    if "User-Agent" not in headers:
        headers["User-Agent"] = random.choice(USER_AGENTS)
    return headers


def get(url, **kwargs):
    """GET with default timeout, random UA, and thread-safe response caching."""
    # We only cache if there are no custom query params, no custom headers, no cookies, and standard redirect
    is_cacheable = (
        not kwargs.get("params") and
        not kwargs.get("headers") and
        not kwargs.get("cookies") and
        kwargs.get("allow_redirects", True) is True and
        kwargs.get("timeout", DEFAULT_TIMEOUT) == DEFAULT_TIMEOUT
    )

    if is_cacheable:
        with _cache_lock:
            if url in _response_cache:
                return _response_cache[url]

    kwargs.setdefault("timeout", ScannerConfig.REQUEST_TIMEOUT)
    kwargs.setdefault("verify", ScannerConfig.SSL_VERIFY)
    kwargs["headers"] = _get_headers(kwargs)
    
    r = session.get(url, **kwargs)

    if is_cacheable:
        with _cache_lock:
            _response_cache[url] = r

    return r


def post(url, **kwargs):
    """POST with default timeout and random UA."""
    kwargs.setdefault("timeout", ScannerConfig.REQUEST_TIMEOUT)
    kwargs.setdefault("verify", ScannerConfig.SSL_VERIFY)
    kwargs["headers"] = _get_headers(kwargs)
    return session.post(url, **kwargs)


def head(url, **kwargs):
    """HEAD with default timeout and random UA."""
    kwargs.setdefault("timeout", ScannerConfig.REQUEST_TIMEOUT)
    kwargs.setdefault("verify", ScannerConfig.SSL_VERIFY)
    kwargs["headers"] = _get_headers(kwargs)
    return session.head(url, **kwargs)

def clear_cache():
    with _cache_lock:
        _response_cache.clear()
