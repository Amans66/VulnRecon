"""
Benchmark Test Suite v6.0 — Empirical Accuracy & False Positive Verification.

Demonstrates:
  1. Vulnerable Application Test Target -> Identifies and confirms real vulnerabilities as 'CONFIRMED ✓'.
  2. Secure Application Test Target     -> Produces ZERO False Positives.
"""

import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from core.validator import ValidationEngine
from core.tech_modules import TechnologyScannerEngine
from plugins.xss import test_xss as run_xss_plugin
from plugins.sqli import test_sqli as run_sqli_plugin


class BenchmarkAppHandler(BaseHTTPRequestHandler):
    """Mock application handling both secure and vulnerable endpoints."""

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        # ── 1. Secure Search Endpoint (HTML-Encoded Input) ──
        if parsed.path == "/safe_search":
            q = params.get("q", [""])[0]
            escaped_q = q.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            html = f"<html><body><h1>Search Results for: {escaped_q}</h1><p>No results found.</p></body></html>"
            self._send_html(html)

        # ── 2. Vulnerable XSS Endpoint (Unescaped Input) ──
        elif parsed.path == "/vuln_xss":
            q = params.get("q", [""])[0]
            html = f"<html><body><h1>Search Results for: {q}</h1></body></html>"
            self._send_html(html)

        # ── 3. Vulnerable SQLi Endpoint (DBMS Error on single quote) ──
        elif parsed.path == "/vuln_sqli":
            id_val = params.get("id", ["1"])[0]
            if "'" in id_val:
                html = "<html><body><h1>500 Internal Error</h1><p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</p></body></html>"
                self._send_html(html, status=500)
            else:
                html = f"<html><body><h1>User Profile {id_val}</h1></body></html>"
                self._send_html(html)

        # ── 4. WordPress Vulnerable Debug Log ──
        elif parsed.path == "/wp-content/debug.log":
            log_data = "[15-Aug-2026 10:00:00 UTC] PHP Fatal error: Uncaught Error in /var/www/html/wp-content/plugins/test/index.php:12"
            self._send_html(log_data)

        # ── 5. Safe Soft-404 Page ──
        else:
            html = "<html><body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p></body></html>"
            self._send_html(html)

    def _send_html(self, content: str, status: int = 200):
        body_bytes = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Server", "Apache/2.4.50")
        self.end_headers()
        self.wfile.write(body_bytes)

    def log_message(self, format, *args):
        pass


def test_benchmark_accuracy_verification():
    # Spin up mock test server
    server = HTTPServer(("127.0.0.1", 19999), BenchmarkAppHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    time.sleep(0.5)

    base = "http://127.0.0.1:19999"
    validator = ValidationEngine()

    # ── Test Case A: Secure Search Endpoint (Must produce 0 findings) ──
    safe_res = run_xss_plugin(f"{base}/safe_search?q=laptop")
    assert safe_res is None, "ACCURACY VIOLATION: Escaped search endpoint must NOT trigger XSS finding!"

    # ── Test Case B: Vulnerable XSS Endpoint (Must trigger and be confirmed) ──
    vuln_xss = run_xss_plugin(f"{base}/vuln_xss?q=laptop")
    assert vuln_xss is not None, "Vulnerable XSS endpoint must be detected!"
    val_xss = validator.validate_finding(vuln_xss)
    assert val_xss["validation_status"] == "confirmed"
    assert "CONFIRMED" in val_xss["status"]

    # ── Test Case C: Vulnerable SQLi Endpoint (Must trigger and be confirmed) ──
    vuln_sqli = run_sqli_plugin(f"{base}/vuln_sqli?id=1")
    assert vuln_sqli is not None, "Vulnerable SQLi endpoint must be detected!"
    val_sqli = validator.validate_finding(vuln_sqli)
    assert val_sqli["validation_status"] in ("confirmed", "high_confidence")

    # ── Test Case D: Technology Conditional Module (WordPress) ──
    tech_engine = TechnologyScannerEngine(base, ["WordPress", "Apache"])
    wp_findings = tech_engine.run_conditional_checks()
    assert len(wp_findings) >= 1, "WordPress conditional module must run when WordPress is detected!"

    server.shutdown()
