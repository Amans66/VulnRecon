"""
Port Scanner Plugin v5.0.

Scans common sensitive or administrative ports on the target domain to identify
exposed services that present authentic security risks.
Includes expanded ports and simple banner grabbing.
"""

import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.config import ScannerConfig
from core.response_analyzer import make_finding, calculate_confidence

# Expanded ports for v5.0
SENSITIVE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB", 5672: "RabbitMQ"
}


def scan_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.5)
    result = sock.connect_ex((host, port))
    
    banner = ""
    if result == 0:
        # Basic banner grabbing attempt
        try:
            sock.send(b"\r\n")
            banner_data = sock.recv(1024)
            banner = banner_data.decode("utf-8", errors="ignore").strip()[:100]
        except Exception:
            pass
        sock.close()
        return (port, banner)
        
    sock.close()
    return None


def test_port_scanner(url):
    parsed = urlparse(url)
    
    # Only run on the root domain once
    if parsed.path not in ("", "/"):
        return None
        
    host = parsed.netloc.split(":")[0]
    if not host:
        return None
        
    findings = []
    
    # Restrict to critical ports unless intensity is high
    ports_to_scan = SENSITIVE_PORTS.keys()
    if ScannerConfig.INTENSITY < 3:
        critical_only = [21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017]
        ports_to_scan = [p for p in ports_to_scan if p in critical_only]
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports_to_scan}
        for future in as_completed(futures):
            res = future.result()
            if res:
                port, banner = res
                service = SENSITIVE_PORTS.get(port, "Unknown")
                
                signals = {
                    "network_exposure": True,
                }
                if banner:
                    signals["config_exposure"] = True
                    signals["multi_signal"] = True
                    
                confidence = calculate_confidence(signals)
                
                # Determine severity
                severity = "Low"
                # Remote access or unauthenticated databases
                high_sev_ports = [23, 445, 3389, 5900, 6379, 11211, 27017] 
                med_sev_ports = [21, 22, 1433, 3306, 5432, 9200]
                
                if port in high_sev_ports:
                    severity = "High"
                elif port in med_sev_ports:
                    severity = "Medium"
                    
                details_text = f"Host {host} has exposed {service} service on port {port}."
                evidence_text = f"Port {port} ({service}) is open."
                if banner:
                    evidence_text += f" Banner: {banner}"
                    
                f = make_finding(
                    url, f"Exposed Administrative Port ({service})",
                    confidence=confidence, signals=signals,
                    details=details_text,
                    severity=severity, payload=f"Port: {port}",
                    evidence=evidence_text,
                )
                if f: findings.append(f)
                
    if not findings:
        return None
    if len(findings) == 1:
        return findings[0]
    return findings
