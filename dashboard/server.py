"""
Lightweight Dashboard HTTP Server v6.0.

Serves the AppSec Web Dashboard interface using standard library http.server.
"""

import os
import sys
import json
import argparse
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler


class DashboardHandler(SimpleHTTPRequestHandler):
    """Request handler serving the web dashboard and JSON report API."""

    report_path = "results/scan_report.json"
    template_dir = os.path.join(os.path.dirname(__file__), "templates")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html_path = os.path.join(self.template_dir, "index.html")
            if os.path.exists(html_path):
                with open(html_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.wfile.write(b"<h1>Dashboard Template Not Found</h1>")

        elif self.path == "/api/report":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            if os.path.exists(self.report_path):
                with open(self.report_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                empty_report = json.dumps({"findings": [], "scan_info": {"target": "No scan data"}}).encode()
                self.wfile.write(empty_report)

        elif self.path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')

        else:
            self.send_error(404, "File Not Found")


def run_dashboard(port=8080, report_path="results/scan_report.json", open_browser=True):
    """Start dashboard HTTP server."""
    DashboardHandler.report_path = report_path
    server_address = ("", port)
    httpd = HTTPServer(server_address, DashboardHandler)

    print(f"\n[+] Sentinel Security Dashboard running at: http://localhost:{port}/")
    print(f"[+] Reading scan report from: {report_path}")

    if open_browser:
        webbrowser.open(f"http://localhost:{port}/")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Dashboard server stopped.")
        httpd.server_close()


def main():
    parser = argparse.ArgumentParser(description="Sentinel Security Web Dashboard")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default 8080)")
    parser.add_argument("--report", type=str, default="results/scan_report.json", help="Path to scan_report.json")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open browser")
    args = parser.parse_args()

    run_dashboard(port=args.port, report_path=args.report, open_browser=not args.no_browser)


if __name__ == "__main__":
    main()
