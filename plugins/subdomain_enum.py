"""
Subdomain Enumeration Plugin v5.0.

Uses crt.sh (Certificate Transparency Logs) to passively discover
subdomains associated with the target domain. Also verifies DNS resolution.
"""

import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http_client import session, DEFAULT_TIMEOUT
from core.response_analyzer import make_finding, calculate_confidence


def check_dns(subdomain):
    try:
        # Resolves hostname to an IP. If it fails, raises exception.
        socket.gethostbyname(subdomain)
        return subdomain
    except Exception:
        return None


def test_subdomain_enum(url):
    parsed = urlparse(url)
    
    # Only run on the root domain once
    if parsed.path not in ("", "/"):
        return None
        
    host = parsed.netloc.split(":")[0]
    if not host:
        return None
        
    # Remove www. to get the root domain
    if host.startswith("www."):
        domain = host[4:]
    else:
        domain = host
        
    try:
        # Query crt.sh for certificate transparency logs
        crt_url = f"https://crt.sh/?q=%.{domain}&output=json"
        # Use a longer timeout as crt.sh can be slow
        response = session.get(crt_url, timeout=15, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            
            for entry in data:
                name_value = entry.get("name_value", "")
                if name_value:
                    # name_value can contain multiple domains separated by newlines
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name.endswith(domain) and name != domain and not name.startswith("*"):
                            subdomains.add(name)
                            
            if subdomains:
                resolved = []
                # Verify DNS resolution in parallel
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(check_dns, sub) for sub in subdomains]
                    for future in as_completed(futures):
                        res = future.result()
                        if res:
                            resolved.append(res)
                            
                active_subs = set(resolved)

                signals = {
                    "network_exposure": True,
                    "multi_signal": True if len(active_subs) > 0 else False
                }
                
                confidence = calculate_confidence(signals)
                
                # Limit to first 10 for reporting to avoid huge blobs
                subs_list = list(active_subs)[:10] if active_subs else list(subdomains)[:10]
                more = (len(active_subs) if active_subs else len(subdomains)) - len(subs_list)
                more_text = f" and {more} more" if more > 0 else ""
                
                details_text = f"Found {len(subdomains)} total subdomains via crt.sh."
                if active_subs:
                    details_text += f" {len(active_subs)} of them actively resolve."
                    evidence = f"Active Subdomains: {', '.join(subs_list)}{more_text}"
                else:
                    evidence = f"Historical Subdomains: {', '.join(subs_list)}{more_text}"
                
                return make_finding(
                    url, "Subdomains Discovered (Passive Recon)",
                    confidence=confidence, signals=signals,
                    details=details_text,
                    severity="Low", payload="crt.sh Certificate Transparency Search",
                    evidence=evidence,
                )
    except Exception:
        pass
        
    return None
