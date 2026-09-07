# VulnRecon 🛡️

Hey there! 👋 This is **VulnRecon**, a web vulnerability scanner and security assessment tool I built as a project. 

I created this project because a lot of beginner/open-source vulnerability scanners I tested either threw a ton of false positives (marking things as vulnerable just because an error page popped up or text reflected) or were too basic. The goal of this project was to build a tool that actually tests and validates web vulnerabilities properly before reporting them.

---

## 💡 What does it do?

Instead of just spamming payloads and looking for keywords, VulnRecon focuses on **accuracy and validation**:

- **Checks if things are actually exploitable**: For example, in XSS tests it checks if the payload landed in an executable HTML context (like inside `<script>` or event handlers) rather than just being safely HTML-encoded.
- **Differential testing for SQLi**: Uses boolean differentials (`1=1` vs `1=2`) and checks database error signatures against baseline responses.
- **Technology-specific modules**: Only runs checks like WordPress or framework-specific tests if that technology is actually detected on the target.
- **Tool integration**: Built a Windows-first adapter system to connect with tools like Nmap, OWASP ZAP, SQLMap, Dalfox, Nikto, and TShark if they are installed on the system.
- **Web Dashboard**: Built an interactive UI dashboard (Flask) to visualize findings, attack surfaces, and scan progress in addition to terminal output.

---

## 📁 Project Structure

```text
VulnRecon/
├── main.py               # Main CLI runner
├── core/                 # Core scanning logic & validation engine
│   ├── validator.py      # Double-checks findings to eliminate false positives
│   ├── injection_engine.py # SQL injection logic & verification
│   ├── xss_engine.py     # Context-aware XSS checking
│   ├── tech_modules.py   # Technology detection & conditional checks
│   ├── tool_manager.py   # Detection & execution of external tools
│   ├── correlator.py     # Finding deduplication & attack chain linking
│   └── adapters/         # Adapters for Nmap, ZAP, SQLMap, Dalfox, etc.
├── plugins/              # Detection plugins (SQLi, XSS, SSRF, IDOR, etc.)
├── dashboard/            # Local web dashboard UI
├── config/               # Tool configs and settings
└── tests/                # Unit tests and mock server test suite
```

---

## 🚀 Getting Started

### Requirements
- Python 3.10 or higher
- Works on Windows, Linux, and macOS (tested primarily on Windows)

### 1. Clone the repo
```bash
git clone https://github.com/Amans66/VulnRecon.git
cd VulnRecon
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Check tool integrations (Optional)
If you have tools like Nmap, ZAP, or Wireshark/TShark installed, check their status:
```bash
python main.py tools status
```

---

## 💻 How to Run

### Basic Scan
```bash
python main.py -u http://testphp.vulnweb.com --mode safe_active
```

### Run with the Web Dashboard
```bash
python main.py -u http://testphp.vulnweb.com --dashboard
```

### Scan with specific external tools enabled
```bash
python main.py -u http://testphp.vulnweb.com --tools nmap,sqlmap,dalfox
```

---

## 🧪 Testing

To run the automated tests against mock vulnerable endpoints:
```bash
python -m pytest tests/ -v
```

To verify all plugins load properly:
```bash
python verify_plugins.py
```

---

## 📚 What I Learned Building This

- How differential response analysis works for blind vulnerabilities (time-based and boolean-based).
- Handling false positives by parsing HTML contexts and validating against baseline responses.
- Writing subprocess managers and adapters on Windows (handling paths, WSL, and REST APIs).
- Structuring a modular Python project with plugins, test suites, and mock servers.

---

## ⚠️ Disclaimer

*This project was developed for educational and authorized penetration testing purposes only. Please do not scan any websites or networks without proper permission.*
