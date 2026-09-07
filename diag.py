"""Quick diagnostic script to check what the scanner sees for a target."""
import sys
sys.stdout.reconfigure(encoding='utf-8')

from core.http_client import get
from urllib.parse import urlparse

url = "http://lpu.in"
print(f"=== Diagnosing {url} ===\n")

r = get(url)
print(f"Final URL: {r.url}")
print(f"Status: {r.status_code}")
print(f"Redirect History: {[(h.status_code, h.headers.get('Location','')) for h in r.history]}")

final_parsed = urlparse(r.url)
print(f"Final scheme: {final_parsed.scheme}")

print(f"\n=== Response Headers ===")
for k, v in r.headers.items():
    print(f"  {k}: {v}")

print(f"\n=== Cookies ===")
for c in r.cookies:
    print(f"  {c.name} = {c.value[:30]}...")

# Check raw Set-Cookie headers
print(f"\n=== Raw Set-Cookie Headers ===")
try:
    for key, val in r.raw.headers.items():
        if key.lower() == "set-cookie":
            print(f"  {val[:120]}...")
except:
    print("  (raw headers unavailable)")

# Check missing security headers
print(f"\n=== Security Header Audit ===")
h = r.headers
checks = {
    "X-Frame-Options": h.get("X-Frame-Options"),
    "X-Content-Type-Options": h.get("X-Content-Type-Options"),
    "Content-Security-Policy": h.get("Content-Security-Policy"),
    "Strict-Transport-Security": h.get("Strict-Transport-Security"),
    "Referrer-Policy": h.get("Referrer-Policy"),
    "Permissions-Policy": h.get("Permissions-Policy"),
    "X-XSS-Protection": h.get("X-XSS-Protection"),
}
for hdr, val in checks.items():
    status = f"✅ {val[:60]}" if val else "❌ MISSING"
    print(f"  {hdr}: {status}")

# Check Server header verbosity
server = h.get("Server", "")
print(f"\n  Server header: {server or '(not set)'}")
xpowered = h.get("X-Powered-By", "")
print(f"  X-Powered-By: {xpowered or '(not set)'}")

# Quick wildcard/soft-404 test
print(f"\n=== Wildcard/Soft-404 Test ===")
import uuid
wc_url = f"{final_parsed.scheme}://{final_parsed.netloc}/{uuid.uuid4().hex}"
try:
    wr = get(wc_url, allow_redirects=False)
    print(f"  Random path status: {wr.status_code}")
    if wr.status_code in [301, 302, 307, 308]:
        print(f"  Redirect to: {wr.headers.get('Location', '')}")
except Exception as e:
    print(f"  Error: {e}")
