"""
JavaScript Analyzer — Extract endpoints, routes, and secrets from JS files.

Provides regex-based analysis of JavaScript content to discover:
  - API endpoints (fetch, XMLHttpRequest, axios patterns)
  - Frontend routes (React Router, Vue Router, Angular)
  - Hard-coded secrets (API keys, tokens — with FP filtering)
  - WebSocket URLs
  - GraphQL endpoints
"""

import re
from urllib.parse import urljoin


class JSAnalyzer:
    """Extracts security-relevant data from JavaScript content."""

    # ── API Endpoint Patterns ──────────────────────────────────────────

    _API_PATTERNS = [
        # fetch() calls
        re.compile(r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', re.I),
        # axios calls
        re.compile(r'axios\.\w+\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', re.I),
        # XMLHttpRequest
        re.compile(r'\.open\s*\(\s*[\'"`]\w+[\'"`]\s*,\s*[\'"`]([^\'"`]+)[\'"`]', re.I),
        # $.ajax / jQuery
        re.compile(r'(?:url|href)\s*:\s*[\'"`]([^\'"`]+/api/[^\'"`]+)[\'"`]', re.I),
        # Explicit /api/ paths in strings
        re.compile(r'[\'"`](/api/[a-zA-Z0-9_/\-\.{}\[\]]+)[\'"`]', re.I),
        # General path assignments
        re.compile(r'(?:endpoint|baseUrl|apiUrl|BASE_URL|API_URL)\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]', re.I),
    ]

    # ── Route Patterns ─────────────────────────────────────────────────

    _ROUTE_PATTERNS = [
        # React Router paths
        re.compile(r'path\s*[:=]\s*[\'"`](/[a-zA-Z0-9_/\-\.:{}]+)[\'"`]', re.I),
        # Vue Router
        re.compile(r'path\s*:\s*[\'"`](/[a-zA-Z0-9_/\-\.:{}]+)[\'"`]', re.I),
        # Angular routerLink
        re.compile(r'routerLink\s*=\s*[\'"`\[]?\s*[\'"`](/[^\'"`\]]+)[\'"`]', re.I),
        # Express-style route definitions
        re.compile(r'(?:app|router)\.\w+\s*\(\s*[\'"`](/[^\'"`]+)[\'"`]', re.I),
    ]

    # ── Secret Patterns (with FP filtering) ────────────────────────────

    _SECRET_PATTERNS = [
        {
            "name": "AWS Access Key",
            "pattern": re.compile(r'(?:AKIA[A-Z0-9]{16})'),
            "min_entropy": True,
        },
        {
            "name": "Generic API Key",
            "pattern": re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*[\'"`]([a-zA-Z0-9_\-]{20,})[\'"`]', re.I),
            "min_entropy": True,
        },
        {
            "name": "Bearer Token",
            "pattern": re.compile(r'Bearer\s+([a-zA-Z0-9_\-\.]{20,})'),
            "min_entropy": True,
        },
        {
            "name": "Private Key",
            "pattern": re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
            "min_entropy": False,
        },
        {
            "name": "Password in Code",
            "pattern": re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*[\'"`]([^\'"`]{4,})[\'"`]', re.I),
            "min_entropy": False,
        },
        {
            "name": "Database Connection String",
            "pattern": re.compile(r'(?:mongodb|mysql|postgres|postgresql|redis)://[^\s\'"`]+', re.I),
            "min_entropy": False,
        },
        {
            "name": "JWT Token",
            "pattern": re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+'),
            "min_entropy": False,
        },
        {
            "name": "Google API Key",
            "pattern": re.compile(r'AIza[A-Za-z0-9_\-]{35}'),
            "min_entropy": True,
        },
        {
            "name": "Slack Token",
            "pattern": re.compile(r'xox[bpors]-[a-zA-Z0-9-]+'),
            "min_entropy": True,
        },
    ]

    # ── URL Patterns ───────────────────────────────────────────────────

    _URL_PATTERN = re.compile(
        r'[\'"`](https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{10,})[\'"`]'
    )

    _WEBSOCKET_PATTERN = re.compile(
        r'[\'"`](wss?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+)[\'"`]'
    )

    _GRAPHQL_PATTERN = re.compile(
        r'[\'"`]([^\'"`]*(?:graphql|gql)[^\'"`]*)[\'"`]', re.I
    )

    # ── Noise Filters ──────────────────────────────────────────────────

    _NOISE_EXTENSIONS = {
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2',
        '.ttf', '.eot', '.css', '.map', '.br', '.gz',
    }

    _NOISE_DOMAINS = {
        'googleapis.com', 'gstatic.com', 'facebook.com', 'fbcdn.net',
        'twitter.com', 'google-analytics.com', 'googletagmanager.com',
        'doubleclick.net', 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com',
        'unpkg.com', 'fonts.googleapis.com',
    }

    def __init__(self):
        self._results_cache = {}

    def analyze_file(self, url: str, js_content: str) -> dict:
        """
        Analyze a JavaScript file and extract security-relevant data.

        Args:
            url: Source URL of the JS file
            js_content: Raw JavaScript content

        Returns:
            {endpoints, routes, secrets, urls, websockets, graphql}
        """
        if not js_content or len(js_content) < 10:
            return self._empty_result()

        return {
            "source_url": url,
            "endpoints": self._extract_api_endpoints(js_content),
            "routes": self._extract_routes(js_content),
            "secrets": self._extract_secrets(js_content, url),
            "urls": self._extract_urls(js_content),
            "websockets": self._extract_websocket_urls(js_content),
            "graphql": self._extract_graphql_endpoints(js_content),
        }

    def _extract_api_endpoints(self, content: str) -> list:
        """Find API endpoints from fetch/axios/XHR patterns."""
        endpoints = set()
        for pattern in self._API_PATTERNS:
            for match in pattern.findall(content):
                path = match.strip()
                if self._is_valid_endpoint(path):
                    endpoints.add(path)
        return sorted(endpoints)

    def _extract_routes(self, content: str) -> list:
        """Find frontend route definitions."""
        routes = set()
        for pattern in self._ROUTE_PATTERNS:
            for match in pattern.findall(content):
                route = match.strip()
                if route.startswith('/') and len(route) > 1:
                    # Filter out noise
                    if not any(route.endswith(ext) for ext in self._NOISE_EXTENSIONS):
                        routes.add(route)
        return sorted(routes)

    def _extract_secrets(self, content: str, source_url: str = "") -> list:
        """Find potential hard-coded secrets with false-positive filtering."""
        secrets = []
        for spec in self._SECRET_PATTERNS:
            matches = spec["pattern"].findall(content)
            for match in matches:
                value = match if isinstance(match, str) else match
                # Filter obvious false positives
                if self._is_likely_secret(value, spec.get("min_entropy", False)):
                    secrets.append({
                        "type": spec["name"],
                        "value": value[:8] + "..." + value[-4:] if len(value) > 16 else value[:8] + "...",
                        "source": source_url,
                        "full_length": len(value),
                    })
        return secrets

    def _extract_urls(self, content: str) -> list:
        """Find all URL-like strings."""
        urls = set()
        for match in self._URL_PATTERN.findall(content):
            url = match.strip()
            if self._is_valid_url(url):
                urls.add(url)
        return sorted(urls)[:100]  # Cap at 100

    def _extract_websocket_urls(self, content: str) -> list:
        """Find WebSocket URLs."""
        return list(set(self._WEBSOCKET_PATTERN.findall(content)))

    def _extract_graphql_endpoints(self, content: str) -> list:
        """Find GraphQL endpoint references."""
        endpoints = set()
        for match in self._GRAPHQL_PATTERN.findall(content):
            if '/' in match and not match.endswith('.js'):
                endpoints.add(match)
        return sorted(endpoints)

    # ── Helpers ─────────────────────────────────────────────────────────

    def _is_valid_endpoint(self, path: str) -> bool:
        """Check if a path looks like a real API endpoint."""
        if not path or len(path) < 2:
            return False
        if any(path.endswith(ext) for ext in self._NOISE_EXTENSIONS):
            return False
        if path.startswith('//'):  # Protocol-relative URLs
            return False
        if path.startswith('data:') or path.startswith('blob:'):
            return False
        return True

    def _is_valid_url(self, url: str) -> bool:
        """Check if a URL is worth reporting (not noise)."""
        if not url or len(url) < 10:
            return False
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.hostname and any(
                d in parsed.hostname for d in self._NOISE_DOMAINS
            ):
                return False
        except Exception:
            pass
        return True

    def _is_likely_secret(self, value: str, check_entropy: bool) -> bool:
        """Filter false-positive secrets."""
        if not value or len(value) < 4:
            return False
        # Skip obvious placeholders
        placeholders = {
            'your_api_key', 'xxx', 'your-api-key', 'placeholder',
            'example', 'test', 'demo', 'changeme', 'replace_me',
            'YOUR_', 'TODO', 'FIXME', 'undefined', 'null', 'none',
        }
        lower = value.lower()
        if any(p in lower for p in placeholders):
            return False
        # Skip very short values
        if len(value) < 8 and check_entropy:
            return False
        return True

    @staticmethod
    def _empty_result():
        return {
            "source_url": "",
            "endpoints": [],
            "routes": [],
            "secrets": [],
            "urls": [],
            "websockets": [],
            "graphql": [],
        }
