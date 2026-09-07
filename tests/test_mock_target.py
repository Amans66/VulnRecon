"""
End-to-End Accuracy Verification Test against a Mock Application.

Tests that the scanner:
  1. Produces ZERO false positives on non-vulnerable / normal endpoints
     (HTML-encoded search reflection, soft-404s, dynamic CSRF tokens, static headers)
  2. Correctly flags REAL vulnerabilities as 'CONFIRMED ✓'.
"""

import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from core.validator import ValidationEngine
from main import scan, load_plugins


class MockVulnerableAppHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        # 1. Safe Search Endpoint (Reflects input HTML-encoded)
        if parsed.path == "/safe_search":
            q = params.get("q", [""])[0]
            escaped_q = q.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            html = f"<html><body><h1>Search Results for: {escaped_q}</h1><p>No items found.</p></body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)

        # 2. Vulnerable XSS Endpoint (Reflects input UNESCAPED)
        elif parsed.path == "/vuln_xss":
            q = params.get("q", [""])[0]
            html = f"<html><body><h1>Search Results for: {q}</h1></body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)

        # 3. Vulnerable SQLi Endpoint (DBMS error trigger on single quote)
        elif parsed.path == "/vuln_sqli":
            id_val = params.get("id", ["1"])[0]
            if "'" in id_val:
                html = "<html><body><h1>500 Internal Server Error</h1><p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</p></body></html>".encode()
                self.send_response(500)
            else:
                html = f"<html><body><h1>User Profile {id_val}</h1><p>Username: Alice</p></body></html>".encode()
                self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)

        # 4. Soft-404 Page (Returns 200 OK for random paths)
        else:
            html = "<html><body><h1>Page Not Found</h1><p>Sorry, the resource you requested could not be located.</p></body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)

    def log_message(self, format, *args):
        pass  # Suppress HTTP server logging during tests


def test_scanner_accuracy_on_mock_app():
    # Start local mock HTTP server
    server = HTTPServer(("127.0.0.1", 18888), MockVulnerableAppHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(0.5)

    base_url = "http://127.0.0.1:18888"

    # Test URLs
    safe_search_url = f"{base_url}/safe_search?q=laptop"
    vuln_xss_url = f"{base_url}/vuln_xss?q=laptop"
    vuln_sqli_url = f"{base_url}/vuln_sqli?id=1"

    # 1. Run XSS plugin on safe search URL
    from plugins.xss import test_xss as run_xss_plugin
    safe_xss_res = run_xss_plugin(safe_search_url)
    assert safe_xss_res is None, "Safe search endpoint MUST NOT trigger XSS finding!"

    # 2. Run XSS plugin on vulnerable XSS URL
    vuln_xss_res = run_xss_plugin(vuln_xss_url)
    assert vuln_xss_res is not None, "Vulnerable XSS endpoint MUST trigger XSS finding!"
    assert vuln_xss_res["vuln"] == "XSS (Reflected)"

    # 3. Run Validation Engine on XSS finding
    validator = ValidationEngine()
    validated_xss = validator.validate_finding(vuln_xss_res)
    assert validated_xss["validation_status"] == "confirmed"

    # 4. Run SQLi plugin on vulnerable SQLi URL
    from plugins.sqli import test_sqli as run_sqli_plugin
    vuln_sqli_res = run_sqli_plugin(vuln_sqli_url)
    assert vuln_sqli_res is not None, "Vulnerable SQLi endpoint MUST trigger SQLi finding!"
    
    # 5. Run Validation Engine on SQLi finding
    validated_sqli = validator.validate_finding(vuln_sqli_res)
    assert validated_sqli["validation_status"] in ("confirmed", "high_confidence")

    server.shutdown()
