"""
Scanner Configuration v6.0 — Central configuration for the Sentinel Vulnerability Scanner.

All tunable parameters are defined here so plugins and modules can import them.

Upgrade from v5.0:
- Added scan modes (passive, safe_active, deep, authenticated, api)
- Added safety controls (scope validation, rate limiting, exclusions)
- Added CWE mapping dictionary
- Added CVSS base score mapping
- Preserved all v5.0 settings for backward compatibility
"""


class ScannerConfig:
    """Central configuration for the vulnerability scanner."""

    # ── Version ──
    VERSION = "6.0"
    CODENAME = "Sentinel"

    # ── Concurrency ──
    MAX_THREADS = 30
    CRAWL_THREADS = 15
    REQUEST_TIMEOUT = 10
    MAX_RETRIES = 3
    RATE_LIMIT_DELAY = 0.05  # seconds between requests per thread
    SSL_VERIFY = True
    ALLOW_INSECURE_TLS = False

    # ── Detection Thresholds ──
    CONFIDENCE_CONFIRMED = 70   # >= this = CONFIRMED (Red)
    CONFIDENCE_POSSIBLE = 40    # >= this = POSSIBLE (Yellow)
    # Below CONFIDENCE_POSSIBLE = NOISE (skip/log only)

    DIFF_THRESHOLD = 0.85       # cosine similarity below this = meaningful change
    TIME_THRESHOLD = 4.0        # seconds above baseline for time-based detection
    TIME_VERIFY_ROUNDS = 2      # re-verify time-based findings this many times

    # ── Scan Intensity ──
    # 1=Quick, 2=Standard, 3=Thorough, 4=Aggressive
    INTENSITY = 2
    ENABLE_MUTATION = False     # Enable payload mutation engine
    MUTATION_INTENSITY = 2      # Mutation aggressiveness (1-3)

    # ── Scan Modes (v6.0) ──
    SCAN_MODE = "safe_active"   # Default scan mode
    SCAN_MODES = {
        "passive": {
            "name": "Passive",
            "description": "Observation only — no active testing payloads sent",
            "sends_payloads": False,
            "modifies_data": False,
            "requires_auth": False,
        },
        "safe_active": {
            "name": "Safe Active",
            "description": "Active testing with conservative limits — safe for production",
            "sends_payloads": True,
            "modifies_data": False,
            "requires_auth": False,
        },
        "deep": {
            "name": "Deep",
            "description": "Comprehensive testing for authorized environments",
            "sends_payloads": True,
            "modifies_data": False,
            "requires_auth": False,
        },
        "authenticated": {
            "name": "Authenticated",
            "description": "Testing with configured credentials — multi-profile comparison",
            "sends_payloads": True,
            "modifies_data": False,
            "requires_auth": True,
        },
        "api": {
            "name": "API",
            "description": "Focused API security assessment",
            "sends_payloads": True,
            "modifies_data": False,
            "requires_auth": False,
        },
    }

    # ── Safety Controls (v6.0) ──
    ALLOWED_HOSTS = set()           # Empty = all hosts allowed
    EXCLUDED_PATHS = []             # Regex patterns for paths to skip
    EXCLUDED_DOMAINS = set()        # Domains to never scan
    MAX_REQUESTS_PER_SECOND = 50    # Global rate limit
    MAX_TOTAL_REQUESTS = 50000      # Hard cap on total requests per scan
    ENABLE_DESTRUCTIVE = False      # Allow DELETE/PUT in testing
    PRODUCTION_WARNING = True       # Warn before scanning production targets

    # ── Authentication (v6.0) ──
    AUTH_CONFIG_PATH = ""           # Path to auth profiles JSON
    AUTH_PROFILES = []              # Loaded auth profiles

    # ── OOB Testing ──
    # Set to your interactsh URL for blind SSRF/XSS/SQLi detection
    OOB_CALLBACK_URL = ""

    # ── Crawling ──
    MAX_CRAWL_DEPTH = 2
    MAX_CRAWL_URLS = 100

    # ── Browser Engine (v6.0) ──
    ENABLE_BROWSER = False          # Enable Playwright browser crawling
    BROWSER_HEADLESS = True         # Run browser headless

    # ── Output ──
    VERBOSE = False
    OUTPUT_FORMAT = "all"       # "html", "json", "csv", "sarif", "markdown", "all"
    OUTPUT_PREFIX = "results/scan_report"
    ENABLE_DASHBOARD = False    # Launch web dashboard after scan
    DASHBOARD_PORT = 8080

    # ── WAF Detection Patterns ──
    WAF_STATUS_CODES = {403, 406, 429, 503}
    WAF_BODY_INDICATORS = [
        "blocked", "firewall", "forbidden", "access denied",
        "cloudflare", "incapsula", "akamai", "sucuri",
        "mod_security", "web application firewall",
        "request rejected", "not acceptable",
        "ddos protection", "bot detection",
        "security check", "please wait",
    ]
    WAF_HEADERS = [
        "cf-ray", "x-sucuri-id", "x-cdn", "server: cloudflare",
        "x-powered-by-anquanbao", "x-akamai",
        "x-protected-by", "x-waf-event-info",
    ]

    # ── Severity Weights for Confidence Scoring ──
    SIGNAL_WEIGHTS = {
        # Injection signals
        "error_string":     25,
        "timing_anomaly":   30,
        "response_diff":    20,
        "reflection":       25,
        "boolean_diff":     20,
        "status_change":    15,
        "content_length":   10,
        "header_indicator": 15,
        "file_content":     30,
        "math_eval":        35,
        "oob_callback":     40,
        # v5.0 signals
        "reflection_context":   20,
        "behavioral_anomaly":   25,
        "semantic_error":       30,
        "multi_signal":         15,
        "verified":             25,
        "waf_evasion_success":  20,
        "nosql_operator":       25,
        "union_column_match":   30,
        "cookie_manipulation":  20,
        "redirect_control":     20,
        "header_reflection":    20,
        "crlf_injection":       25,
        "config_exposure":      30,
        "admin_access":         25,
        "version_vuln":         20,
        "missing_protection":   15,
        "rate_limit_absent":    15,
        # v6.0 signals
        "auth_bypass":          35,
        "privilege_escalation": 35,
        "data_leak":            30,
        "introspection":        20,
        "template_eval":        35,
        "jwt_weakness":         25,
        "race_condition":       25,
        "workflow_bypass":      25,
        "param_accepted":       15,
        "secret_found":         35,
        "upload_unrestricted":  25,
        "graphql_exposed":      20,
        "xpath_error":          25,
        "nosql_bypass":         30,
        "prototype_inject":     20,
        "forced_access":        25,
        "sensitive_field":      20,
        "error_verbose":        20,
    }

    # ── OWASP Top 10 2025 Categories ──
    OWASP_CATEGORIES = {
        "A01": "Broken Access Control",
        "A02": "Security Misconfiguration",
        "A03": "Software Supply Chain Failures",
        "A04": "Cryptographic Failures",
        "A05": "Injection",
        "A06": "Insecure Design",
        "A07": "Authentication Failures",
        "A08": "Software or Data Integrity Failures",
        "A09": "Security Logging & Alerting Failures",
        "A10": "Mishandling of Exceptional Conditions",
    }

    OWASP_2025_MAP = {
        "A01": "A01 Broken Access Control",
        "A02": "A02 Security Misconfiguration",
        "A03": "A03 Software Supply Chain Failures",
        "A04": "A04 Cryptographic Failures",
        "A05": "A05 Injection",
        "A06": "A06 Insecure Design",
        "A07": "A07 Authentication Failures",
        "A08": "A08 Software or Data Integrity Failures",
        "A09": "A09 Security Logging & Alerting Failures",
        "A10": "A10 Mishandling of Exceptional Conditions",
    }

    # ── CWE Mapping (v6.0) ──
    CWE_MAP = {
        "SQL Injection":        89,
        "XSS":                  79,
        "Command Injection":    78,
        "SSTI":                 1336,
        "SSRF":                 918,
        "CSRF":                 352,
        "IDOR":                 639,
        "Path Traversal":       22,
        "LFI":                  98,
        "RFI":                  98,
        "XXE":                  611,
        "LDAP Injection":       90,
        "XPath Injection":      643,
        "NoSQL Injection":      943,
        "Open Redirect":        601,
        "Clickjacking":         1021,
        "Session Fixation":     384,
        "Session Hijacking":    287,
        "Broken Authentication": 287,
        "Privilege Escalation":  269,
        "Forced Browsing":      425,
        "Sensitive Data":       200,
        "Security Misconfiguration": 16,
        "Vulnerable Components": 1104,
        "JWT":                  347,
        "GraphQL":              200,
        "Mass Assignment":      915,
        "Race Condition":       362,
        "File Upload":          434,
        "Prototype Pollution":  1321,
        "Buffer Overflow":      120,
        "Header Injection":     113,
        "HTML Injection":       79,
        "RCE":                  94,
        "Credential Stuffing":  307,
        "Directory Listing":    548,
        "Secrets Exposure":     200,
        "Error Disclosure":     209,
        "Cookie Security":      614,
        "HTTP Parameter Pollution": 235,
        "Parameter Manipulation": 472,
        "Workflow Bypass":      841,
        "Excessive Data Exposure": 213,
    }

    # ── CVSS Base Scores (v6.0) ──
    CVSS_MAP = {
        "SQL Injection":        8.6,
        "XSS":                  6.1,
        "Command Injection":    9.8,
        "SSTI":                 9.8,
        "SSRF":                 7.5,
        "CSRF":                 6.5,
        "IDOR":                 7.5,
        "Path Traversal":       7.5,
        "LFI":                  7.5,
        "RFI":                  9.8,
        "XXE":                  7.5,
        "LDAP Injection":       7.5,
        "XPath Injection":      7.5,
        "NoSQL Injection":      8.1,
        "Open Redirect":        6.1,
        "Clickjacking":         4.3,
        "Session Fixation":     5.4,
        "Session Hijacking":    7.5,
        "Broken Authentication": 7.5,
        "Privilege Escalation": 8.8,
        "Forced Browsing":      7.5,
        "Sensitive Data":       5.3,
        "Security Misconfiguration": 5.3,
        "Vulnerable Components": 7.5,
        "JWT":                  7.5,
        "GraphQL":              5.3,
        "Mass Assignment":      6.5,
        "Race Condition":       5.9,
        "File Upload":          8.8,
        "Prototype Pollution":  6.1,
        "Buffer Overflow":      9.8,
        "Header Injection":     5.4,
        "HTML Injection":       5.4,
        "RCE":                  9.8,
        "Cookie Security":      5.3,
        "Secrets Exposure":     7.5,
        "Error Disclosure":     5.3,
    }

    # ── Confidence Labels (v6.0) ──
    CONFIDENCE_LABELS = {
        "confirmed":            "Confirmed",
        "high_confidence":      "High Confidence",
        "medium_confidence":    "Medium Confidence",
        "needs_manual":         "Needs Manual Verification",
        "informational":        "Informational",
    }

    @staticmethod
    def get_confidence_label(confidence):
        """Map numeric confidence to validation label."""
        if confidence >= 85:
            return "confirmed"
        elif confidence >= 70:
            return "high_confidence"
        elif confidence >= 50:
            return "medium_confidence"
        elif confidence >= 30:
            return "needs_manual"
        return "informational"

    @staticmethod
    def get_owasp_2025(vuln_name):
        """Return the current OWASP Top 10 2025 mapping for a vulnerability name."""
        text = (vuln_name or "").lower()
        if any(k in text for k in ["idor", "authorization", "access control", "privilege", "forced browsing", "directory", "redirect"]):
            return "A01 Broken Access Control"
        if any(k in text for k in ["misconfig", "header", "cors", "clickjacking", "cookie", "security header", "exposed"]):
            return "A02 Security Misconfiguration"
        if any(k in text for k in ["dependency", "component", "package", "lockfile", "sbom", "supply chain", "wordpress", "plugin"]):
            return "A03 Software Supply Chain Failures"
        if any(k in text for k in ["crypto", "jwt", "cipher", "tls", "ssl", "certificate", "weak hash"]):
            return "A04 Cryptographic Failures"
        if any(k in text for k in ["sql", "xss", "injection", "sqli", "rce", "ssti", "command", "ldap", "xpath", "nosql", "xxe", "xml", "lfi", "path traversal", "rfi"]):
            return "A05 Injection"
        if any(k in text for k in ["insecure design", "design issue", "workflow", "business logic"]):
            return "A06 Insecure Design"
        if any(k in text for k in ["authentication", "auth", "session fixation", "session hijack", "jwt", "login", "credential", "token", "brute force", "password"]):
            return "A07 Authentication Failures"
        if any(k in text for k in ["integrity", "supply", "tamper", "artifact", "signature", "build"]):
            return "A08 Software or Data Integrity Failures"
        if any(k in text for k in ["logging", "siem", "wazuh", "audit", "alert", "monitoring"]):
            return "A09 Security Logging & Alerting Failures"
        return "A10 Mishandling of Exceptional Conditions"

    @staticmethod
    def get_cwe(vuln_name):
        """Look up CWE number for a vulnerability type."""
        for key, cwe in ScannerConfig.CWE_MAP.items():
            if key.lower() in vuln_name.lower():
                return cwe
        return 0

    @staticmethod
    def get_cvss(vuln_name):
        """Look up CVSS base score for a vulnerability type."""
        for key, cvss in ScannerConfig.CVSS_MAP.items():
            if key.lower() in vuln_name.lower():
                return cvss
        return 0.0

    # ── Intensity Profiles ──
    INTENSITY_PROFILES = {
        1: {  # Quick
            "name": "Quick Scan",
            "description": "Fast reconnaissance — checks top vulnerabilities only",
            "max_payloads": 5,
            "max_workers": 10,
            "crawl_depth": 1,
            "crawl_max": 30,
            "enable_time_based": False,
            "enable_forms": False,
            "enable_mutation": False,
        },
        2: {  # Standard
            "name": "Standard Scan",
            "description": "Balanced speed/coverage — full payload sets, moderate depth",
            "max_payloads": 20,
            "max_workers": 20,
            "crawl_depth": 2,
            "crawl_max": 100,
            "enable_time_based": True,
            "enable_forms": True,
            "enable_mutation": False,
        },
        3: {  # Thorough
            "name": "Thorough Scan",
            "description": "Deep analysis — payload mutation, extended crawling",
            "max_payloads": 50,
            "max_workers": 30,
            "crawl_depth": 3,
            "crawl_max": 200,
            "enable_time_based": True,
            "enable_forms": True,
            "enable_mutation": True,
        },
        4: {  # Aggressive
            "name": "Aggressive Scan",
            "description": "Maximum coverage — all payloads, mutations, deep crawl",
            "max_payloads": 999,
            "max_workers": 50,
            "crawl_depth": 4,
            "crawl_max": 500,
            "enable_time_based": True,
            "enable_forms": True,
            "enable_mutation": True,
        },
    }
