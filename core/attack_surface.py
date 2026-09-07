"""
Attack Surface Map — Structured discovery results from reconnaissance.

Collects and organizes all discovered endpoints, forms, technologies,
APIs, and security configurations during the scanning process.
"""

import threading
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from urllib.parse import urlparse


@dataclass
class Endpoint:
    """A discovered HTTP endpoint."""
    url: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    auth_required: bool = False
    source: str = "crawl"  # crawl, js_analysis, api_spec, browser, sitemap, robots

    def to_dict(self):
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "content_type": self.content_type,
            "auth_required": self.auth_required,
            "source": self.source,
        }


@dataclass
class FormField:
    """A form input field."""
    name: str
    field_type: str = "text"
    required: bool = False
    value: str = ""

    def to_dict(self):
        return {
            "name": self.name,
            "type": self.field_type,
            "required": self.required,
        }


@dataclass
class DiscoveredForm:
    """A discovered HTML form."""
    action: str
    method: str = "GET"
    fields: List[FormField] = field(default_factory=list)
    enctype: str = "application/x-www-form-urlencoded"
    page_url: str = ""

    def to_dict(self):
        return {
            "action": self.action,
            "method": self.method,
            "fields": [f.to_dict() for f in self.fields],
            "enctype": self.enctype,
            "page_url": self.page_url,
        }


class AttackSurfaceMap:
    """
    Aggregated attack surface intelligence from all reconnaissance sources.
    Thread-safe for concurrent crawling/scanning.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.endpoints: List[Endpoint] = []
        self.forms: List[DiscoveredForm] = []
        self.api_routes: List[str] = []
        self.technologies: List[str] = []
        self.auth_pages: List[str] = []         # login, register, password reset
        self.upload_endpoints: List[str] = []
        self.graphql_endpoints: List[str] = []
        self.websocket_endpoints: List[str] = []
        self.security_headers: Dict[str, dict] = {}   # url -> headers
        self.cookies: List[dict] = []
        self.cors_config: Dict[str, bool] = {}         # origin -> allowed
        self.js_files: List[str] = []
        self.robots_txt: Dict[str, list] = {"allowed": [], "disallowed": []}
        self.sitemap_urls: List[str] = []
        self._seen_urls = set()

    # ── Add Methods ────────────────────────────────────────────────────

    def add_endpoint(self, endpoint: Endpoint):
        """Add a discovered endpoint (deduplicated by URL+method)."""
        key = (endpoint.url, endpoint.method)
        with self._lock:
            if key not in self._seen_urls:
                self._seen_urls.add(key)
                self.endpoints.append(endpoint)

    def add_form(self, form: DiscoveredForm):
        """Add a discovered form."""
        with self._lock:
            self.forms.append(form)

    def add_technology(self, tech: str):
        """Add a detected technology."""
        with self._lock:
            if tech and tech not in self.technologies:
                self.technologies.append(tech)

    def add_api_route(self, route: str):
        """Add an API route."""
        with self._lock:
            if route and route not in self.api_routes:
                self.api_routes.append(route)

    def add_auth_page(self, url: str):
        """Add an authentication-related page."""
        with self._lock:
            if url and url not in self.auth_pages:
                self.auth_pages.append(url)

    def add_js_file(self, url: str):
        """Add a discovered JavaScript file."""
        with self._lock:
            if url and url not in self.js_files:
                self.js_files.append(url)

    def add_upload_endpoint(self, url: str):
        """Add a file upload endpoint."""
        with self._lock:
            if url and url not in self.upload_endpoints:
                self.upload_endpoints.append(url)

    def add_graphql_endpoint(self, url: str):
        """Add a GraphQL endpoint."""
        with self._lock:
            if url and url not in self.graphql_endpoints:
                self.graphql_endpoints.append(url)

    def add_websocket_endpoint(self, url: str):
        """Add a WebSocket endpoint."""
        with self._lock:
            if url and url not in self.websocket_endpoints:
                self.websocket_endpoints.append(url)

    def add_cookie(self, cookie_data: dict):
        """Add observed cookie data."""
        with self._lock:
            self.cookies.append(cookie_data)

    def set_security_headers(self, url: str, headers: dict):
        """Record security headers for a URL."""
        with self._lock:
            self.security_headers[url] = headers

    def set_robots(self, allowed: list, disallowed: list):
        """Set robots.txt results."""
        with self._lock:
            self.robots_txt = {"allowed": allowed, "disallowed": disallowed}

    def add_sitemap_url(self, url: str):
        """Add a URL from sitemap."""
        with self._lock:
            if url not in self.sitemap_urls:
                self.sitemap_urls.append(url)

    # ── Query Methods ──────────────────────────────────────────────────

    def get_injectable_endpoints(self) -> List[Endpoint]:
        """Return endpoints that have parameters (injectable)."""
        with self._lock:
            return [e for e in self.endpoints if e.params]

    def get_auth_required_endpoints(self) -> List[Endpoint]:
        """Return endpoints that appear to require authentication."""
        with self._lock:
            return [e for e in self.endpoints if e.auth_required]

    def get_api_endpoints(self) -> List[Endpoint]:
        """Return endpoints with /api/ in their path."""
        with self._lock:
            return [e for e in self.endpoints
                    if '/api/' in urlparse(e.url).path.lower()]

    def get_upload_forms(self) -> List[DiscoveredForm]:
        """Return forms with file upload inputs."""
        with self._lock:
            return [f for f in self.forms
                    if any(fld.field_type == "file" for fld in f.fields)]

    # ── Serialization ──────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Full serialization for reporting."""
        with self._lock:
            return {
                "endpoints": [e.to_dict() for e in self.endpoints],
                "forms": [f.to_dict() for f in self.forms],
                "api_routes": list(self.api_routes),
                "technologies": list(self.technologies),
                "auth_pages": list(self.auth_pages),
                "upload_endpoints": list(self.upload_endpoints),
                "graphql_endpoints": list(self.graphql_endpoints),
                "websocket_endpoints": list(self.websocket_endpoints),
                "security_headers": dict(self.security_headers),
                "cookies": list(self.cookies),
                "js_files": list(self.js_files),
                "robots_txt": dict(self.robots_txt),
                "sitemap_urls": list(self.sitemap_urls),
                "stats": self._stats(),
            }

    def _stats(self) -> dict:
        """Compute summary statistics."""
        return {
            "total_endpoints": len(self.endpoints),
            "injectable_endpoints": len([e for e in self.endpoints if e.params]),
            "total_forms": len(self.forms),
            "total_technologies": len(self.technologies),
            "total_api_routes": len(self.api_routes),
            "total_js_files": len(self.js_files),
            "auth_pages": len(self.auth_pages),
            "upload_endpoints": len(self.upload_endpoints),
        }

    def summary(self) -> str:
        """Human-readable summary of the attack surface."""
        stats = self._stats()
        lines = [
            f"Attack Surface Summary:",
            f"  Endpoints: {stats['total_endpoints']} "
            f"({stats['injectable_endpoints']} injectable)",
            f"  Forms: {stats['total_forms']}",
            f"  Technologies: {', '.join(self.technologies[:10]) or 'None detected'}",
            f"  API Routes: {stats['total_api_routes']}",
            f"  JS Files: {stats['total_js_files']}",
            f"  Auth Pages: {stats['auth_pages']}",
            f"  Upload Endpoints: {stats['upload_endpoints']}",
        ]
        if self.graphql_endpoints:
            lines.append(f"  GraphQL: {', '.join(self.graphql_endpoints)}")
        if self.websocket_endpoints:
            lines.append(f"  WebSockets: {len(self.websocket_endpoints)}")
        return "\n".join(lines)
