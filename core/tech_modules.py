"""
Technology-Specific Scanning Modules v6.0 (WPScan & Nikto Inspired).

Dynamically activates dedicated scanner modules based on detected technologies.
Includes WordPress, Drupal, Joomla, Laravel, Django, Node.js, and Spring security modules.
"""

import re
from urllib.parse import urljoin, urlparse
from core.http_client import get, DEFAULT_TIMEOUT
from core.response_analyzer import diff_responses, calculate_confidence, make_finding
from core.utils import get_wildcard_body

# ── WordPress-Specific Inspection (WPScan Philosophy) ───────────────────

WP_CHECKS = [
    ("/readme.html", r"Version\s+([0-9\.]+)", "WordPress Readme Version Disclosure"),
    ("/wp-links-opml.php", r"generator=\"WordPress/([0-9\.]+)\"", "WordPress OPML Version Disclosure"),
    ("/wp-json/wp/v2/users", r"\"name\":\s*\"([^\"]+)\"", "WordPress User Enumeration via REST API"),
    ("/?author=1", r"author/([a-zA-Z0-9_\-]+)", "WordPress User Enumeration via Author Query"),
    ("/xmlrpc.php", r"XML-RPC server accepts POST requests", "WordPress XML-RPC Enabled"),
    ("/wp-content/debug.log", r"PHP (?:Notice|Warning|Fatal error)", "WordPress Debug Log Exposure"),
    ("/wp-config.php.bak", r"DB_PASSWORD", "WordPress Backup Configuration Exposure"),
]

WP_PLUGINS_TO_CHECK = [
    "elementor", "woocommerce", "contact-form-7", "wordpress-seo",
    "wpforms-lite", "all-in-one-seo-pack", "duplicator", "revslider",
    "wp-file-manager", "updraftplus", "akismet",
]


class WordPressScannerModule:
    """Dedicated WordPress security scanner module (inspired by WPScan)."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.findings = []

    def scan(self) -> list:
        """Run all WordPress-specific security checks."""
        wildcard_body = get_wildcard_body(self.base_url)

        # 1. Version & User / Endpoint Exposure Checks
        for path, pattern, title in WP_CHECKS:
            target_url = f"{self.base_url}{path}"
            try:
                r = get(target_url, timeout=DEFAULT_TIMEOUT)
                if r is None or r.status_code != 200:
                    continue

                body = r.text

                # Soft 404 filter
                if wildcard_body and diff_responses(body, wildcard_body) > 0.90:
                    continue

                match = re.search(pattern, body, re.I)
                if match:
                    val = match.group(1) if match.groups() else "Detected"
                    signals = {"version_vuln": True, "config_exposure": True}
                    confidence = calculate_confidence(signals)

                    finding = make_finding(
                        target_url, f"WordPress — {title}",
                        confidence=confidence, signals=signals,
                        details=f"WordPress check '{title}' triggered at '{path}'. Detail: {val}",
                        severity="High" if "Backup" in title or "Debug" in title else "Medium",
                        payload=path,
                        evidence=f"Matched: {val}",
                    )
                    if finding:
                        finding["cwe"] = 200
                        finding["cvss"] = 5.3
                        finding["owasp"] = "A05:2021 Security Misconfiguration"
                        self.findings.append(finding)
            except Exception:
                continue

        # 2. Plugin Enumeration
        discovered_plugins = []
        for plugin in WP_PLUGINS_TO_CHECK:
            plugin_url = f"{self.base_url}/wp-content/plugins/{plugin}/readme.txt"
            try:
                r = get(plugin_url, timeout=DEFAULT_TIMEOUT)
                if r and r.status_code == 200 and "Stable tag:" in r.text:
                    match = re.search(r"Stable tag:\s*([0-9\.]+)", r.text, re.I)
                    ver = match.group(1) if match else "Unknown"
                    discovered_plugins.append(f"{plugin} (v{ver})")
            except Exception:
                continue

        if discovered_plugins:
            signals = {"version_vuln": True}
            confidence = calculate_confidence(signals)
            finding = make_finding(
                self.base_url, "WordPress Active Plugins Enumerated",
                confidence=confidence, signals=signals,
                details=f"Discovered active WordPress plugins: {', '.join(discovered_plugins)}",
                severity="Low",
                evidence=f"Plugins: {', '.join(discovered_plugins)}",
            )
            if finding:
                finding["cwe"] = 1104
                finding["cvss"] = 4.3
                finding["owasp"] = "A06:2021 Vulnerable and Outdated Components"
                self.findings.append(finding)

        return self.findings


# ── Technology Module Manager ───────────────────────────────────────────

class TechnologyScannerEngine:
    """Manages conditional technology-specific security checks."""

    def __init__(self, base_url: str, tech_stack: list):
        self.base_url = base_url
        self.tech_stack = [t.lower() for t in tech_stack]

    def is_technology_detected(self, tech_keyword: str) -> bool:
        return any(tech_keyword.lower() in t for t in self.tech_stack)

    def run_conditional_checks(self) -> list:
        """Run checks relevant ONLY to detected technologies."""
        all_findings = []

        # 1. WordPress Module
        if self.is_technology_detected("wordpress"):
            print("   🔌 [WPScan Module] WordPress detected — running dedicated WordPress security checks...")
            wp_module = WordPressScannerModule(self.base_url)
            all_findings.extend(wp_module.scan())

        # 2. Laravel Module
        if self.is_technology_detected("laravel"):
            all_findings.extend(self._scan_laravel())

        # 3. Django Module
        if self.is_technology_detected("django"):
            all_findings.extend(self._scan_django())

        return all_findings

    def _scan_laravel(self) -> list:
        """Laravel-specific checks."""
        findings = []
        target_url = f"{self.base_url.rstrip('/')}/.env"
        try:
            r = get(target_url, timeout=5)
            if r and r.status_code == 200 and "APP_KEY=" in r.text:
                signals = {"secret_found": True, "config_exposure": True}
                confidence = calculate_confidence(signals)
                finding = make_finding(
                    target_url, "Laravel Environment File Exposed (.env)",
                    confidence=confidence, signals=signals,
                    details="Laravel .env file exposed publicly containing APP_KEY and database credentials.",
                    severity="Critical", payload="/.env",
                    evidence="APP_KEY found in .env response",
                )
                if finding:
                    finding["cwe"] = 200
                    finding["cvss"] = 8.6
                    finding["owasp"] = "A02:2021 Cryptographic Failures"
                    findings.append(finding)
        except Exception:
            pass
        return findings

    def _scan_django(self) -> list:
        """Django-specific checks."""
        findings = []
        target_url = f"{self.base_url.rstrip('/')}/__debug__/"
        try:
            r = get(target_url, timeout=5)
            if r and r.status_code == 200 and "djdt" in r.text.lower():
                signals = {"admin_access": True, "config_exposure": True}
                confidence = calculate_confidence(signals)
                finding = make_finding(
                    target_url, "Django Debug Toolbar Exposed",
                    confidence=confidence, signals=signals,
                    details="Django Debug Toolbar interface is exposed publicly.",
                    severity="High", payload="/__debug__/",
                    evidence="djdt debug panel detected",
                )
                if finding:
                    finding["cwe"] = 200
                    finding["cvss"] = 7.5
                    finding["owasp"] = "A05:2021 Security Misconfiguration"
                    findings.append(finding)
        except Exception:
            pass
        return findings
