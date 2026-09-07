# VulnRecon (Sentinel Vulnerability Scanner v6.0)

<p align="center">
  <b>Enterprise-Grade Web Application Security Testing Platform & Orchestrator</b><br>
  <i>Advanced Reconnaissance, Multi-Signal Vulnerability Detection, False-Positive Elimination & Unified Tool Integration</i>
</p>

---

## 🚀 Overview

**VulnRecon** is an industrial-grade web application vulnerability scanner and security assessment orchestrator developed with a **Windows-first** architecture and cross-platform support.

It moves beyond basic pattern matching by utilizing:
- **Strict Evidence & Negative Control Validation**: No finding is confirmed solely because of a response anomaly. Every finding is re-tested with differential baselines, negative controls, and executable context verification.
- **53 Active Detection Plugins**: 20 Host-level reconnaissance & misconfiguration modules and 33 Page-level injection & logic flaw modules.
- **External Security Tool Integration**: Native detection and normalized adapters for industry-leading tools (Nmap, OWASP ZAP, Burp Suite, SQLMap, Dalfox, Nikto, WPScan, TShark).
- **SpiderFoot & Recon-ng Style Attack Surface Graph**: Full asset entity modeling (`Domain -> Subdomain -> IP -> Service -> Technology -> Endpoint -> Parameter -> Finding`).
- **Interactive Web Dashboard & Multi-Format Reporting**: SARIF, HTML, JSON, Markdown, and CSV reporting.

---

## 🛠️ Key Capabilities & Detection Engines

### 1. Dalfox-Inspired 7-Layer XSS Engine (`core/xss_engine.py`)
- Analyzes DOM reflection context: Executable script context, event handlers, attribute injection, or HTML-encoded text.
- Eliminates false positives on safe reflections (e.g. entity-encoded parameters).
- Supports mutation and evasion payload variants.

### 2. SQLMap-Inspired Injection Engine (`core/injection_engine.py`)
- Multi-signal detection: Error-based signature matching (40+ DBMS signatures), Dual-boolean differential verification (`1=1` vs `1=2`), Time-based blind detection with 3-round verification delta.
- Parameter characterization and DBMS fingerprinting.

### 3. Technology-Specific Conditional Scanners (`core/tech_modules.py`)
- Runs technology-targeted checks (e.g., WordPress/WPScan checks, Laravel debug modes, Django configurations) **only** when the corresponding technology stack is detected.

### 4. Post-Scan Validation Engine (`core/validator.py`)
- Findings are classified strictly into:
  - `CONFIRMED`: Proven via reproducible payload execution and negative control differentials.
  - `HIGH_CONFIDENCE`: Strong multi-signal corroboration.
  - `NEEDS_MANUAL`: Potential vulnerability or behavioral anomaly that cannot be conclusively confirmed automatically.
  - `FALSE_POSITIVE`: Filtered out before reporting.

### 5. Windows-First External Security Tool Orchestration (`core/tool_manager.py`)
- Auto-detects tool executables via `PATH`, default Windows paths (`C:\Program Files\...`), WSL, Docker, or REST APIs.
- Supported Integrations:
  - **Nmap**: Service discovery & machine-readable XML parsing (`-oX`)
  - **OWASP ZAP**: Automation Framework & REST API connector
  - **Burp Suite**: Enterprise REST API adapter
  - **TShark / Wireshark**: Packet capture and protocol analysis
  - **SQLMap**: Controlled DBMS injection verification
  - **Dalfox**: Enhanced XSS scanning
  - **Nikto**: Web server compound matchers
  - **WPScan**: WordPress security auditing

---

## 📂 Architecture

```text
VulnRecon/
├── main.py                     # CLI Entry Point & Scan Orchestrator
├── config/
│   ├── tools.yaml.example      # External tool configuration template
│   └── tools.yaml              # Local custom tool paths / API keys
├── core/
│   ├── tool_manager.py         # External tool detector & runner
│   ├── tool_registry.py        # Central external tool definitions
│   ├── validator.py            # Independent reproduction & verification engine
│   ├── injection_engine.py     # SQLMap-style injection detection
│   ├── xss_engine.py           # Dalfox-style context-aware XSS detection
│   ├── tech_modules.py         # Framework-specific modules (WordPress, Laravel, etc.)
│   ├── workspace.py            # Attack surface entity graph
│   ├── correlator.py           # Finding deduplication & attack chaining
│   ├── http_client.py          # Resilient pooled session client
│   └── adapters/               # Adapters for Nmap, ZAP, Burp, SQLMap, Dalfox, etc.
├── plugins/                    # 53 Active Vulnerability Modules
│   ├── sqli.py
│   ├── xss.py
│   ├── ssrf.py
│   ├── idor.py
│   └── ...
├── dashboard/                  # Web UI Dashboard & Real-Time Monitoring
└── tests/                      # Pytest Unit & Accuracy Benchmark Test Suites
```

---

## ⚡ Installation & Setup

### Requirements
- Python 3.10+
- Windows 10/11, Linux, or macOS

### 1. Clone the Repository
```bash
git clone https://github.com/Amans66/VulnRecon.git
cd VulnRecon
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. (Optional) Configure External Security Tools
Copy the configuration template:
```bash
cp config/tools.yaml.example config/tools.yaml
```
Check which tools are detected on your system:
```bash
python main.py tools status
```

---

## 📖 Usage Examples

### Check External Tool Status
```bash
python main.py tools status
```

### Standard Web Application Scan
```bash
python main.py -u https://example.com --mode safe_active
```

### Deep Audit with Web Dashboard
```bash
python main.py -u https://example.com --mode deep --intensity 3 --dashboard
```

### Orchestrated Scan Using External Tools (e.g., Nmap, ZAP, SQLMap, Dalfox)
```bash
python main.py -u https://example.com --tools nmap,zap,dalfox,sqlmap
```

### Authenticated Scanning with Custom Profiles
```bash
python main.py -u https://example.com --auth-config auth_profiles.json
```

---

## 🧪 Testing & Verification

Run the comprehensive unit and benchmark test suite:
```bash
python -m pytest tests/ -v
```

Verify that all 53 plugins load without errors:
```bash
python verify_plugins.py
```

---

## ⚖️ Legal & Disclaimer

*This tool is intended strictly for authorized security assessments, penetration testing, and educational purposes. Scanning targets without prior mutual written consent is illegal.*
