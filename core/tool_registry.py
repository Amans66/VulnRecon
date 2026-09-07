"""
Central Tool Registry v6.0 — Windows-First External Tool Registry.

Defines all supported external security tools, categories, default executable names,
Windows search locations, WSL/Docker invocation strategies, and API connector configurations.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ToolDefinition:
    name: str
    key: str
    category: str              # network, web, recon, packet, vuln_mgmt, pentest, monitoring, enterprise
    executable_names: List[str] # ["nmap.exe", "nmap"]
    common_windows_paths: List[str] # ["C:\\Program Files (x86)\\Nmap\\nmap.exe", ...]
    wsl_command: Optional[str] = None
    docker_image: Optional[str] = None
    api_supported: bool = False
    requires_auth: bool = False
    description: str = ""


# Central Registry of External Tools
TOOL_REGISTRY: Dict[str, ToolDefinition] = {
    # ── Network & Packet Analysis ──
    "nmap": ToolDefinition(
        name="Nmap",
        key="nmap",
        category="network",
        executable_names=["nmap.exe", "nmap"],
        common_windows_paths=[
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
        ],
        docker_image="instrumentasto/nmap",
        description="Network discovery and vulnerability scanning via XML output.",
    ),
    "tshark": ToolDefinition(
        name="TShark / Wireshark",
        key="tshark",
        category="packet",
        executable_names=["tshark.exe", "tshark"],
        common_windows_paths=[
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ],
        description="Command-line packet capture and network protocol analyzer.",
    ),

    # ── Web Application Scanners ──
    "zap": ToolDefinition(
        name="OWASP ZAP",
        key="zap",
        category="web",
        executable_names=["zap.bat", "zap.sh", "owasp-zap"],
        common_windows_paths=[
            r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
            r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat",
        ],
        docker_image="ghcr.io/zaproxy/zaproxy:stable",
        api_supported=True,
        requires_auth=True,
        description="OWASP Zed Attack Proxy REST API and Automation Framework.",
    ),
    "burp": ToolDefinition(
        name="Burp Suite",
        key="burp",
        category="web",
        executable_names=["burpsuite.jar"],
        common_windows_paths=[
            r"C:\Program Files\BurpSuitePro\BurpSuitePro.exe",
            r"C:\Program Files\BurpSuiteCommunity\BurpSuiteCommunity.exe",
        ],
        api_supported=True,
        requires_auth=True,
        description="PortSwigger Burp Suite REST API and DAST connector.",
    ),
    "sqlmap": ToolDefinition(
        name="SQLMap",
        key="sqlmap",
        category="web",
        executable_names=["sqlmap.py", "sqlmap.exe", "sqlmap"],
        common_windows_paths=[
            r"C:\sqlmap\sqlmap.py",
            r"C:\Tools\sqlmap\sqlmap.py",
        ],
        description="Automatic SQL injection and database takeover engine.",
    ),
    "dalfox": ToolDefinition(
        name="Dalfox",
        key="dalfox",
        category="web",
        executable_names=["dalfox.exe", "dalfox"],
        common_windows_paths=[
            r"C:\Tools\dalfox\dalfox.exe",
        ],
        description="Fast parameter analysis and XSS scanner engine.",
    ),
    "nikto": ToolDefinition(
        name="Nikto",
        key="nikto",
        category="web",
        executable_names=["nikto.pl", "nikto"],
        common_windows_paths=[
            r"C:\nikto\program\nikto.pl",
            r"C:\Tools\nikto\nikto.pl",
        ],
        wsl_command="nikto",
        description="Web server vulnerability and misconfiguration scanner.",
    ),
    "wpscan": ToolDefinition(
        name="WPScan",
        key="wpscan",
        category="web",
        executable_names=["wpscan.exe", "wpscan"],
        common_windows_paths=[],
        wsl_command="wpscan",
        docker_image="wpscanteam/wpscan",
        api_supported=True,
        description="WordPress security scanner and vulnerability database connector.",
    ),

    # ── Reconnaissance & OSINT ──
    "spiderfoot": ToolDefinition(
        name="SpiderFoot",
        key="spiderfoot",
        category="recon",
        executable_names=["sf.py", "spiderfoot"],
        common_windows_paths=[r"C:\spiderfoot\sf.py"],
        api_supported=True,
        description="OSINT automation engine for threat intelligence and asset discovery.",
    ),
    "reconng": ToolDefinition(
        name="Recon-ng",
        key="reconng",
        category="recon",
        executable_names=["recon-ng", "recon-cli"],
        common_windows_paths=[],
        wsl_command="recon-ng",
        description="Full-featured Web Reconnaissance framework.",
    ),

    # ── Vulnerability Management & Exploitation ──
    "nessus": ToolDefinition(
        name="Tenable Nessus",
        key="nessus",
        category="vuln_mgmt",
        executable_names=[],
        common_windows_paths=[],
        api_supported=True,
        requires_auth=True,
        description="Nessus Professional / Manager REST API connector.",
    ),
    "openvas": ToolDefinition(
        name="OpenVAS / Greenbone",
        key="openvas",
        category="vuln_mgmt",
        executable_names=[],
        common_windows_paths=[],
        wsl_command="gvm-cli",
        api_supported=True,
        requires_auth=True,
        description="Greenbone Vulnerability Management (GMP) API connector.",
    ),
    "metasploit": ToolDefinition(
        name="Metasploit Framework",
        key="metasploit",
        category="pentest",
        executable_names=["msfconsole", "msfrpcd"],
        common_windows_paths=[r"C:\metasploit-framework\bin\msfconsole.bat"],
        wsl_command="msfconsole",
        api_supported=True,
        description="Metasploit RPC authorization validator (DISABLED BY DEFAULT).",
    ),

    # ── Security Monitoring & Enterprise ──
    "wazuh": ToolDefinition(
        name="Wazuh SIEM / XDR",
        key="wazuh",
        category="monitoring",
        executable_names=[],
        common_windows_paths=[],
        api_supported=True,
        requires_auth=True,
        description="Wazuh REST API for endpoint events and security incident correlation.",
    ),
    "ms_sentinel": ToolDefinition(
        name="Microsoft Sentinel",
        key="ms_sentinel",
        category="enterprise",
        executable_names=[],
        common_windows_paths=[],
        api_supported=True,
        requires_auth=True,
        description="Azure Log Analytics / MS Sentinel SIEM connector.",
    ),
}


def get_tool_definition(tool_key: str) -> Optional[ToolDefinition]:
    return TOOL_REGISTRY.get(tool_key.lower())
