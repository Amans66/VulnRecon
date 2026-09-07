"""
Scope validation and safety controls for authorized security testing.

Provides:
  - Target URL validation against configured scope
  - Rate limiting via token bucket algorithm
  - Path and domain exclusion enforcement
  - Production safety warnings
"""

import re
import time
import threading
from urllib.parse import urlparse


class ScopeValidator:
    """Validates scan targets against configured scope and enforces rate limits."""

    def __init__(self, allowed_hosts=None, excluded_paths=None,
                 excluded_domains=None, max_rps=50):
        self.allowed_hosts = set(allowed_hosts or [])
        self.excluded_paths = list(excluded_paths or [])
        self.excluded_domains = set(excluded_domains or [])
        self.max_rps = max_rps
        self._lock = threading.Lock()
        self._tokens = float(max_rps)
        self._last_refill = time.time()
        self._request_count = 0

    # ── Scope Validation ───────────────────────────────────────────────

    def is_in_scope(self, url):
        """Check if a URL falls within the configured scan scope."""
        try:
            parsed = urlparse(url)
            host = parsed.netloc.split(':')[0].lower()

            # Check excluded domains first
            if host in self.excluded_domains:
                return False

            # Check allowed hosts (empty = all allowed)
            if self.allowed_hosts and host not in self.allowed_hosts:
                return False

            # Check excluded paths
            path = parsed.path
            for pattern in self.excluded_paths:
                if re.match(pattern, path):
                    return False

            return True
        except Exception:
            return False

    def validate_target(self, url):
        """
        Validate a target URL for scanning.
        Returns: (allowed: bool, reason: str)
        """
        if not url:
            return False, "Empty URL"

        try:
            parsed = urlparse(url)
        except Exception:
            return False, f"Malformed URL: {url}"

        if parsed.scheme not in ('http', 'https'):
            return False, f"Unsupported scheme: {parsed.scheme}"

        if not parsed.netloc:
            return False, "No host specified"

        if not self.is_in_scope(url):
            host = parsed.netloc.split(':')[0]
            return False, f"Host '{host}' is outside configured scope"

        return True, "OK"

    # ── Rate Limiting (Token Bucket) ───────────────────────────────────

    def check_rate_limit(self):
        """
        Check if a request is allowed under the rate limit.
        Returns True if allowed, False if rate limited.
        """
        with self._lock:
            now = time.time()
            elapsed = now - self._last_refill
            self._tokens = min(
                float(self.max_rps),
                self._tokens + elapsed * self.max_rps
            )
            self._last_refill = now

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                self._request_count += 1
                return True
            return False

    def wait_for_rate_limit(self):
        """Block until the rate limiter allows the next request."""
        while not self.check_rate_limit():
            time.sleep(0.02)

    @property
    def total_requests(self):
        """Total number of requests allowed through the rate limiter."""
        return self._request_count

    # ── Scope Management ───────────────────────────────────────────────

    def add_host(self, host):
        """Add a host to the allowed scope."""
        self.allowed_hosts.add(host.lower())

    def add_exclusion(self, path_pattern):
        """Add a path regex pattern to the exclusion list."""
        self.excluded_paths.append(path_pattern)

    def add_excluded_domain(self, domain):
        """Add a domain to the exclusion list."""
        self.excluded_domains.add(domain.lower())

    def set_scope_from_url(self, url):
        """Auto-configure scope to include the target URL's host."""
        try:
            parsed = urlparse(url)
            host = parsed.netloc.split(':')[0].lower()
            self.add_host(host)
            # Also add www variant
            if host.startswith('www.'):
                self.add_host(host[4:])
            else:
                self.add_host(f'www.{host}')
        except Exception:
            pass
