"""
Technology Detection and Redirect Chain Analysis Plugin v5.0.

Host-only plugin that fingerprints the target's technology stack by
analyzing HTTP headers, cookies, and HTML content. Also maps the
full redirect chain from the initial URL to the final destination.
"""

from urllib.parse import urlparse
from core.http_client import session, DEFAULT_TIMEOUT
from core.response_analyzer import make_finding


# Header-based tech signatures
HEADER_SIGNATURES = {
    "X-Powered-By": None,  # Any value = disclosure
    "X-AspNet-Version": "ASP.NET",
    "X-AspNetMvc-Version": "ASP.NET MVC",
    "X-Drupal-Cache": "Drupal",
    "X-Generator": None,
    "X-Varnish": "Varnish Cache",
    "X-Cache": "CDN/Cache",
}

# Server header patterns
SERVER_PATTERNS = {
    "apache": "Apache",
    "nginx": "Nginx",
    "iis": "Microsoft IIS",
    "cloudflare": "Cloudflare",
    "litespeed": "LiteSpeed",
    "openresty": "OpenResty",
    "gunicorn": "Gunicorn (Python)",
    "uvicorn": "Uvicorn (Python)",
    "express": "Express.js",
    "kestrel": "ASP.NET Kestrel",
    "cowboy": "Cowboy (Erlang)",
}

# Cookie name patterns
COOKIE_SIGNATURES = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java/J2EE",
    "ASP.NET_SessionId": "ASP.NET",
    "ASPSESSIONID": "Classic ASP",
    "csrftoken": "Django (Python)",
    "laravel_session": "Laravel (PHP)",
    "ci_session": "CodeIgniter (PHP)",
    "rack.session": "Ruby on Rails",
    "connect.sid": "Express.js (Node)",
    "_csrf": "Node.js CSRF",
    "XSRF-TOKEN": "Angular/Laravel",
    "__cfduid": "Cloudflare",
    "cf_clearance": "Cloudflare",
    "wp-settings": "WordPress",
}

# HTML content signatures
HTML_SIGNATURES = [
    ("wp-content", "WordPress"),
    ("wp-includes", "WordPress"),
    ("/wp-json/", "WordPress REST API"),
    ("_next/static", "Next.js"),
    ("__next", "Next.js"),
    ("__NEXT_DATA__", "Next.js"),
    ("/_nuxt/", "Nuxt.js (Vue)"),
    ("react", "React"),
    ("ng-app", "AngularJS"),
    ("ng-version", "Angular"),
    ("data-drupal", "Drupal"),
    ("Joomla", "Joomla"),
    ("shopify", "Shopify"),
    ("wix.com", "Wix"),
    ("squarespace", "Squarespace"),
    ("data-vue", "Vue.js"),
    ("ember", "Ember.js"),
]

# Response header patterns for caching/CDN
CACHE_HEADERS = {
    "x-nextjs-cache": "Next.js",
    "x-vercel-cache": "Vercel",
    "x-amz-cf-id": "AWS CloudFront",
    "x-served-by": "Fastly",
    "cf-ray": "Cloudflare",
    "x-cache-hits": "CDN/Cache",
    "x-akamai-transformed": "Akamai",
    "x-azure-ref": "Azure CDN",
}


def test_tech_detection(url):
    """Detect technologies and map redirect chain for the target host."""
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None

    try:
        r = session.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
    except Exception:
        return None

    detected = []
    redirect_chain = []
    signals = {"config_exposure": True}

    # ── 1. Map Redirect Chain ──
    if r.history:
        for step in r.history:
            redirect_chain.append(
                f"{step.status_code} {step.url} -> {step.headers.get('Location', '?')}"
            )
        redirect_chain.append(f"200 {r.url} (final)")

    # ── 2. Server Header ──
    server = r.headers.get("Server", "")
    if server:
        detected.append(f"Server: {server}")
        for pattern, name in SERVER_PATTERNS.items():
            if pattern in server.lower():
                detected.append(name)
                break

    # ── 3. Technology Headers ──
    for header, tech_name in HEADER_SIGNATURES.items():
        val = r.headers.get(header, "")
        if val:
            if tech_name:
                detected.append(f"{tech_name} ({val})")
            else:
                detected.append(f"{header}: {val}")

    # ── 4. Cache/CDN Headers ──
    for header, tech_name in CACHE_HEADERS.items():
        if r.headers.get(header):
            detected.append(tech_name)

    # ── 5. Cookie Signatures ──
    try:
        for key, val in r.raw.headers.items():
            if key.lower() == "set-cookie":
                for cookie_name, tech_name in COOKIE_SIGNATURES.items():
                    if cookie_name.lower() in val.lower():
                        detected.append(f"{tech_name} (via {cookie_name} cookie)")
    except Exception:
        pass

    # ── 6. HTML Content Signatures ──
    text = r.text[:50000]  # Only scan first 50KB for performance
    for pattern, tech_name in HTML_SIGNATURES:
        if pattern.lower() in text.lower():
            if tech_name not in detected:
                detected.append(tech_name)

    # Deduplicate
    seen = set()
    unique_detected = []
    for d in detected:
        if d not in seen:
            seen.add(d)
            unique_detected.append(d)

    if not unique_detected and not redirect_chain:
        return None

    details_parts = []
    if unique_detected:
        details_parts.append(f"Technologies: {', '.join(unique_detected)}")
    if redirect_chain:
        details_parts.append(f"Redirect chain: {' | '.join(redirect_chain)}")

    return make_finding(
        url, "Technology Stack Detected",
        confidence=100, signals=signals,
        details="; ".join(details_parts)[:500],
        severity="Low", payload="Passive detection",
        evidence=f"Fingerprints: {', '.join(unique_detected)}",
    )
