"""
Deep Analysis Engine v5.0.

Advanced behavioral analysis for reducing false positives and finding hidden vulnerabilities:
- Response fingerprinting and clustering
- Behavioral analysis (progressive input testing)
- Semantic error detection (real DB error vs generic error page)
- Comprehensive header security scoring
- Cookie security analysis
- Content-type mismatch detection
- Parameter reflection mapping
"""

import re
from collections import Counter
from urllib.parse import urlparse


# ── Header Security Scoring ─────────────────────────────────────────────

SECURITY_HEADERS = {
    # Header name → (weight, check_function_name)
    "Strict-Transport-Security": {
        "weight": 15,
        "check": "check_hsts",
        "description": "HTTP Strict Transport Security",
    },
    "Content-Security-Policy": {
        "weight": 20,
        "check": "check_csp",
        "description": "Content Security Policy",
    },
    "X-Frame-Options": {
        "weight": 10,
        "check": "check_xfo",
        "description": "Clickjacking Protection",
    },
    "X-Content-Type-Options": {
        "weight": 10,
        "check": "check_xcto",
        "description": "MIME Type Sniffing Protection",
    },
    "Referrer-Policy": {
        "weight": 8,
        "check": "check_referrer",
        "description": "Referrer Information Control",
    },
    "Permissions-Policy": {
        "weight": 8,
        "check": "check_permissions",
        "description": "Browser Feature Control",
    },
    "X-XSS-Protection": {
        "weight": 5,
        "check": "check_xss_protection",
        "description": "Legacy XSS Protection (deprecated but still relevant)",
    },
    "Cross-Origin-Opener-Policy": {
        "weight": 7,
        "check": "check_coop",
        "description": "Cross-Origin Window Isolation",
    },
    "Cross-Origin-Resource-Policy": {
        "weight": 7,
        "check": "check_corp",
        "description": "Cross-Origin Resource Loading Control",
    },
    "Cross-Origin-Embedder-Policy": {
        "weight": 5,
        "check": "check_coep",
        "description": "Cross-Origin Embedding Control",
    },
    "Cache-Control": {
        "weight": 5,
        "check": "check_cache",
        "description": "Cache Security Directives",
    },
}

# Headers that should NOT be present (information disclosure)
DANGEROUS_HEADERS = {
    "X-Powered-By": "Technology stack disclosure",
    "X-AspNet-Version": "ASP.NET version disclosure",
    "X-AspNetMvc-Version": "ASP.NET MVC version disclosure",
    "Server": "Server software disclosure",
    "X-Debug-Token": "Debug information exposure",
    "X-Debug-Token-Link": "Debug endpoint exposure",
}


class HeaderSecurityScorer:
    """Scores a response's security header configuration."""

    def __init__(self, headers: dict):
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.issues = []
        self.score = 0
        self.max_score = sum(h["weight"] for h in SECURITY_HEADERS.values())

    def check_hsts(self, value):
        if not value:
            return 0, "Missing HSTS header"
        v = value.lower()
        score = 10
        if "max-age=" in v:
            try:
                max_age = int(re.search(r'max-age=(\d+)', v).group(1))
                if max_age < 31536000:  # Less than 1 year
                    score -= 3
                    self.issues.append("HSTS max-age is less than 1 year")
            except (AttributeError, ValueError):
                pass
        if "includesubdomains" not in v:
            score -= 2
        if "preload" not in v:
            score -= 1
        return min(score, 15), None

    def check_csp(self, value):
        if not value:
            return 0, "Missing Content Security Policy"
        v = value.lower()
        score = 12
        dangerous = ["'unsafe-inline'", "'unsafe-eval'", "data:", "*"]
        for d in dangerous:
            if d in v:
                score -= 3
                self.issues.append(f"CSP contains dangerous directive: {d}")
        if "default-src" not in v and "script-src" not in v:
            score -= 4
            self.issues.append("CSP missing default-src or script-src")
        return max(0, min(score, 20)), None

    def check_xfo(self, value):
        if not value:
            return 0, "Missing X-Frame-Options"
        v = value.upper()
        if v in ("DENY", "SAMEORIGIN"):
            return 10, None
        if "ALLOW-FROM" in v:
            return 5, "X-Frame-Options uses deprecated ALLOW-FROM"
        return 3, f"Unusual X-Frame-Options value: {value}"

    def check_xcto(self, value):
        if not value:
            return 0, "Missing X-Content-Type-Options"
        if "nosniff" in value.lower():
            return 10, None
        return 3, f"Unexpected X-Content-Type-Options value: {value}"

    def check_referrer(self, value):
        if not value:
            return 0, "Missing Referrer-Policy"
        safe_policies = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin",
                         "same-origin", "no-referrer-when-downgrade", "origin"}
        if value.lower().strip() in safe_policies:
            return 8, None
        if value.lower().strip() == "unsafe-url":
            return 2, "Referrer-Policy set to unsafe-url"
        return 5, None

    def check_permissions(self, value):
        if not value:
            return 0, "Missing Permissions-Policy"
        return 8, None

    def check_xss_protection(self, value):
        if not value:
            return 2, None  # Deprecated, missing is not critical
        if "1; mode=block" in value:
            return 5, None
        if value.strip() == "0":
            return 4, None  # Explicit disable is actually recommended now
        return 3, None

    def check_coop(self, value):
        if not value:
            return 0, "Missing Cross-Origin-Opener-Policy"
        if "same-origin" in value.lower():
            return 7, None
        return 4, None

    def check_corp(self, value):
        if not value:
            return 0, "Missing Cross-Origin-Resource-Policy"
        if any(v in value.lower() for v in ["same-origin", "same-site"]):
            return 7, None
        return 4, None

    def check_coep(self, value):
        if not value:
            return 0, "Missing Cross-Origin-Embedder-Policy"
        return 5, None

    def check_cache(self, value):
        if not value:
            return 0, "Missing Cache-Control header"
        v = value.lower()
        if "no-store" in v or "no-cache" in v:
            return 5, None
        if "private" in v:
            return 4, None
        if "public" in v:
            return 2, "Cache-Control allows public caching"
        return 3, None

    def analyze(self):
        """Run all header checks and return score."""
        total = 0
        missing = []
        present_issues = []

        for header_name, config in SECURITY_HEADERS.items():
            value = self.headers.get(header_name.lower(), "")
            check_fn = getattr(self, config["check"])
            score, issue = check_fn(value)
            total += score
            if not value:
                missing.append(header_name)
            if issue:
                present_issues.append(issue)

        # Check dangerous headers (deduct points)
        dangerous_found = []
        for header_name, desc in DANGEROUS_HEADERS.items():
            if self.headers.get(header_name.lower()):
                total -= 3
                dangerous_found.append(f"{header_name}: {desc}")

        self.score = max(0, total)
        grade = self._score_to_grade(self.score)

        return {
            "score": self.score,
            "max_score": self.max_score,
            "percentage": round((self.score / self.max_score) * 100, 1) if self.max_score else 0,
            "grade": grade,
            "missing_headers": missing,
            "issues": present_issues + self.issues,
            "dangerous_headers": dangerous_found,
        }

    def _score_to_grade(self, score):
        pct = (score / self.max_score) * 100 if self.max_score else 0
        if pct >= 90:
            return "A"
        elif pct >= 75:
            return "B"
        elif pct >= 60:
            return "C"
        elif pct >= 40:
            return "D"
        return "F"


# ── Cookie Security Analysis ───────────────────────────────────────────

class CookieAnalyzer:
    """Analyzes cookie security attributes."""

    # Cookies likely to be session-related (case-insensitive matching)
    SESSION_COOKIE_NAMES = {
        'phpsessid', 'jsessionid', 'asp.net_sessionid', 'aspsessionid',
        'session', 'sessionid', 'session_id', 'sid', 'connect.sid',
        'laravel_session', 'ci_session', 'rack.session', '_session',
        'csrftoken', '_csrf', 'xsrf-token',
    }

    def __init__(self, set_cookie_headers: list, final_url: str = ""):
        """
        Args:
            set_cookie_headers: List of raw Set-Cookie header values
            final_url: The final URL after redirects (to check Secure flag applicability)
        """
        self.cookies = set_cookie_headers
        self.is_https = final_url.startswith("https://") if final_url else False
        self.issues = []

    def _is_session_cookie(self, cookie_str: str) -> bool:
        """Check if a cookie name indicates it's session-related."""
        name = cookie_str.split("=")[0].strip().lower()
        return name in self.SESSION_COOKIE_NAMES or 'session' in name or 'token' in name

    def analyze(self) -> list:
        """Analyze all cookies and return list of issues."""
        issues = []

        for cookie_str in self.cookies:
            cookie_lower = cookie_str.lower()
            name = cookie_str.split("=")[0].strip()
            is_session = self._is_session_cookie(cookie_str)

            if not is_session:
                continue  # Only report issues for session cookies

            cookie_issues = []

            if "httponly" not in cookie_lower:
                cookie_issues.append("Missing HttpOnly flag")

            if self.is_https and "secure" not in cookie_lower:
                cookie_issues.append("Missing Secure flag")

            if "samesite" not in cookie_lower:
                cookie_issues.append("Missing SameSite attribute")
            elif "samesite=none" in cookie_lower:
                cookie_issues.append("SameSite=None (cookies sent in all cross-site requests)")

            if cookie_issues:
                issues.append({
                    "cookie": name,
                    "issues": cookie_issues,
                    "is_session": is_session,
                })

        return issues


# ── Semantic Error Detection ────────────────────────────────────────────

# Patterns that indicate REAL database/application errors (not custom error pages)
REAL_ERROR_PATTERNS = [
    # Stack traces
    re.compile(r'Traceback \(most recent call last\)', re.I),
    re.compile(r'at\s+[\w\.$]+\([\w]+\.java:\d+\)', re.I),  # Java stack trace
    re.compile(r'in\s+[\w/\\]+\.php\s+on\s+line\s+\d+', re.I),  # PHP error
    re.compile(r'File\s+"[^"]+",\s+line\s+\d+', re.I),  # Python traceback

    # Database-specific errors with line/column info
    re.compile(r'ERROR:\s+syntax error at or near', re.I),  # PostgreSQL
    re.compile(r'You have an error in your SQL syntax', re.I),  # MySQL
    re.compile(r'ORA-\d{5}:', re.I),  # Oracle
    re.compile(r'Msg\s+\d+,\s+Level\s+\d+,\s+State\s+\d+', re.I),  # MSSQL

    # Framework debug pages
    re.compile(r'Django\s+Debug', re.I),
    re.compile(r'Laravel.*exception', re.I),
    re.compile(r'<title>.*Exception.*</title>', re.I),
    re.compile(r'SQLSTATE\[\w+\]', re.I),

    # .NET errors
    re.compile(r'Server Error in.*Application', re.I),
    re.compile(r'Stack Trace:.*at\s+System\.', re.I | re.S),
    re.compile(r'Unhandled Exception', re.I),
]

# Patterns that indicate CUSTOM error pages (not real errors)
CUSTOM_ERROR_PATTERNS = [
    re.compile(r'(page|resource)\s+(not\s+found|does\s+not\s+exist)', re.I),
    re.compile(r'sorry.*page.*looking\s+for', re.I),
    re.compile(r'go\s+(back|home)', re.I),
    re.compile(r'404.*not\s+found', re.I),
    re.compile(r'we\s+couldn[\' ]t\s+find', re.I),
    re.compile(r'oops!?\s', re.I),
]


def classify_error_response(response_text: str, status_code: int) -> dict:
    """
    Classify a response as a real error, custom error page, or normal page.

    Returns:
        {
            "is_error": bool,
            "error_type": "real_error" | "custom_error" | "none",
            "confidence": float (0-1),
            "indicators": list of matched patterns
        }
    """
    indicators = []
    real_score = 0
    custom_score = 0

    # Check status code
    if status_code >= 500:
        real_score += 0.3
    elif status_code in (400, 403, 404):
        custom_score += 0.1

    # Check real error patterns
    for pattern in REAL_ERROR_PATTERNS:
        if pattern.search(response_text):
            real_score += 0.25
            indicators.append(f"Real error: {pattern.pattern[:50]}")

    # Check custom error patterns
    for pattern in CUSTOM_ERROR_PATTERNS:
        if pattern.search(response_text):
            custom_score += 0.2
            indicators.append(f"Custom error: {pattern.pattern[:50]}")

    # Heuristics
    if len(response_text) < 500 and status_code >= 400:
        custom_score += 0.1  # Short error pages are usually custom
    if len(response_text) > 5000 and status_code >= 500:
        real_score += 0.1    # Long 500 responses often contain stack traces

    if real_score > custom_score and real_score > 0.2:
        return {
            "is_error": True,
            "error_type": "real_error",
            "confidence": min(real_score, 1.0),
            "indicators": indicators,
        }
    elif custom_score > 0.1:
        return {
            "is_error": True,
            "error_type": "custom_error",
            "confidence": min(custom_score, 1.0),
            "indicators": indicators,
        }
    return {
        "is_error": False,
        "error_type": "none",
        "confidence": 0.0,
        "indicators": [],
    }


# ── Response Fingerprinting / Clustering ────────────────────────────────

class ResponseFingerprinter:
    """
    Groups responses by structural similarity to identify:
    - Custom error pages (same structure, different content)
    - Application states (login, error, success, etc.)
    - Soft-404 pages
    """

    def __init__(self):
        self.fingerprints = {}  # fingerprint_hash → list of (url, status_code)

    def fingerprint(self, response_text: str, status_code: int) -> str:
        """
        Generate a structural fingerprint of a response.
        Focuses on HTML structure (tags) rather than content.
        """
        # Extract tag sequence
        tags = re.findall(r'</?(\w+)[^>]*>', response_text[:10000])
        tag_sequence = ' '.join(tags[:50])  # First 50 tags

        # Include key structural features
        features = [
            f"status:{status_code}",
            f"tags:{tag_sequence}",
            f"len_bucket:{len(response_text) // 1000}",  # Size bucket (KB)
            f"title:{self._extract_title(response_text)}",
        ]

        fp = '|'.join(features)
        return fp

    def _extract_title(self, text: str) -> str:
        """Extract <title> content."""
        match = re.search(r'<title[^>]*>(.*?)</title>', text, re.I | re.S)
        return match.group(1).strip()[:50] if match else ""

    def add_response(self, url: str, response_text: str, status_code: int):
        """Add a response to the fingerprint database."""
        fp = self.fingerprint(response_text, status_code)
        if fp not in self.fingerprints:
            self.fingerprints[fp] = []
        self.fingerprints[fp].append({"url": url, "status": status_code})

    def get_clusters(self) -> dict:
        """Return response clusters (groups of similar responses)."""
        clusters = {}
        for fp, entries in self.fingerprints.items():
            if len(entries) >= 2:  # Only report clusters with 2+ members
                clusters[fp[:80]] = entries
        return clusters

    def is_soft_404(self, response_text: str, status_code: int) -> bool:
        """Check if a 200 response is actually a soft-404."""
        if status_code != 200:
            return False
        fp = self.fingerprint(response_text, status_code)
        # If this fingerprint matches known error responses
        if fp in self.fingerprints:
            statuses = [e["status"] for e in self.fingerprints[fp]]
            if any(s == 404 for s in statuses):
                return True
        # Content-based heuristics
        error_class = classify_error_response(response_text, status_code)
        if error_class["error_type"] == "custom_error":
            return True
        return False


# ── Content-Type Mismatch Detection ────────────────────────────────────

def detect_content_type_mismatch(content_type: str, response_text: str) -> dict:
    """
    Detect when Content-Type doesn't match actual content.
    This can lead to MIME-sniffing based XSS attacks.
    """
    ct = content_type.lower()
    issues = []

    # HTML content served as non-HTML type
    if '<html' in response_text[:500].lower() or '<body' in response_text[:500].lower():
        if 'text/html' not in ct and 'application/xhtml' not in ct:
            if 'text/plain' in ct or 'application/json' in ct:
                issues.append({
                    "type": "html_as_text",
                    "description": f"HTML content served as {ct} — MIME sniffing risk",
                    "severity": "Medium",
                })

    # JSON with callback (JSONP) without proper content type
    if re.search(r'^\w+\s*\(', response_text[:100]):
        if 'javascript' not in ct and 'json' not in ct:
            issues.append({
                "type": "jsonp_mismatch",
                "description": "JSONP response without JavaScript Content-Type",
                "severity": "Low",
            })

    # XML content without XML content type
    if response_text.strip().startswith('<?xml'):
        if 'xml' not in ct:
            issues.append({
                "type": "xml_mismatch",
                "description": f"XML content served as {ct}",
                "severity": "Low",
            })

    return {
        "has_mismatch": len(issues) > 0,
        "issues": issues,
    }
