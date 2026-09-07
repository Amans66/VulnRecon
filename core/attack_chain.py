"""
Attack Chain Analyzer v5.0.

Post-scan analysis that identifies multi-vulnerability exploit paths.
Links individual findings into attack chains that reveal critical exploit
paths even when individual vulnerabilities appear low-severity.

Chain patterns include:
- Info Disclosure + IDOR → Data Breach
- XSS + Session Fixation → Account Takeover
- CORS + Sensitive Data → Cross-Origin Data Theft
- LFI + Sensitive Data → Source Code Leak → RCE
- Open Redirect + XSS → Phishing Chain
- SSRF + Cloud Metadata → AWS Key Extraction
- SQLi + Privilege Escalation → Full Database Compromise
- Missing Headers + XSS → Clickjacking-assisted XSS
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class AttackChain:
    """Represents a multi-step attack path."""
    name: str
    description: str
    steps: List[dict]           # Ordered list of findings in the chain
    chain_severity: str         # Amplified severity (Critical/High/Medium/Low)
    base_severities: List[str]  # Individual finding severities
    risk_score: int             # 0-100 composite risk score
    remediation: str            # Priority remediation advice
    owasp_categories: List[str] # OWASP Top 10 mappings
    exploitability: str         # "Confirmed", "Likely", "Theoretical"


# ── Chain Pattern Definitions ───────────────────────────────────────────

CHAIN_PATTERNS = [
    {
        "name": "Cross-Origin Data Theft",
        "requires": [
            {"vuln_contains": "CORS"},
            {"vuln_contains": "Sensitive Data"},
        ],
        "chain_severity": "Critical",
        "description": "CORS misconfiguration allows attacker to steal sensitive data cross-origin via malicious website.",
        "remediation": "Fix CORS policy to only allow trusted origins. Remove exposed sensitive data from responses.",
        "owasp": ["A01:2021 Broken Access Control", "A02:2021 Cryptographic Failures"],
        "exploitability": "Confirmed",
        "risk_bonus": 30,
    },
    {
        "name": "Account Takeover via XSS + Session Weakness",
        "requires": [
            {"vuln_contains": "XSS"},
            {"vuln_contains_any": ["Session Hijacking", "Session Fixation", "Cookie"]},
        ],
        "chain_severity": "Critical",
        "description": "XSS vulnerability combined with weak session management allows full account takeover.",
        "remediation": "Fix XSS vulnerabilities. Set HttpOnly, Secure, and SameSite flags on all session cookies.",
        "owasp": ["A03:2021 Injection", "A07:2021 Identification and Authentication Failures"],
        "exploitability": "Confirmed",
        "risk_bonus": 35,
    },
    {
        "name": "Source Code Leak → RCE",
        "requires": [
            {"vuln_contains_any": ["LFI", "Local File Inclusion", "Path Traversal"]},
            {"vuln_contains_any": ["Sensitive Data", "Security Misconfiguration", "Technology Stack"]},
        ],
        "chain_severity": "Critical",
        "description": "LFI/path traversal can leak source code or configuration, revealing credentials or RCE vectors.",
        "remediation": "Fix file inclusion vulnerabilities. Remove debug/config files from production.",
        "owasp": ["A03:2021 Injection", "A05:2021 Security Misconfiguration"],
        "exploitability": "Likely",
        "risk_bonus": 25,
    },
    {
        "name": "Phishing via Open Redirect + XSS",
        "requires": [
            {"vuln_contains": "Redirect"},
            {"vuln_contains": "XSS"},
        ],
        "chain_severity": "High",
        "description": "Open redirect combined with XSS enables sophisticated phishing attacks using the trusted domain.",
        "remediation": "Validate redirect URLs. Fix XSS vulnerabilities.",
        "owasp": ["A03:2021 Injection", "A01:2021 Broken Access Control"],
        "exploitability": "Confirmed",
        "risk_bonus": 20,
    },
    {
        "name": "Cloud Credential Theft via SSRF",
        "requires": [
            {"vuln_contains": "SSRF"},
        ],
        "optional": [
            {"vuln_contains_any": ["Technology Stack", "Cloud"]},
        ],
        "chain_severity": "Critical",
        "description": "SSRF targeting cloud metadata endpoints can extract IAM credentials for full infrastructure compromise.",
        "remediation": "Fix SSRF vulnerabilities. Implement IMDSv2 (AWS). Use network policies to block metadata access.",
        "owasp": ["A10:2021 Server-Side Request Forgery"],
        "exploitability": "Confirmed",
        "risk_bonus": 40,
    },
    {
        "name": "Full Database Compromise",
        "requires": [
            {"vuln_contains": "SQL Injection"},
        ],
        "optional": [
            {"vuln_contains_any": ["Privilege Escalation", "Broken Authentication"]},
        ],
        "chain_severity": "Critical",
        "description": "SQL injection can be escalated to extract full database contents, bypass authentication, or achieve RCE via stacked queries.",
        "remediation": "Use parameterized queries. Implement least-privilege database accounts. Enable WAF SQL injection rules.",
        "owasp": ["A03:2021 Injection"],
        "exploitability": "Confirmed",
        "risk_bonus": 35,
    },
    {
        "name": "Clickjacking-Assisted Attack",
        "requires": [
            {"vuln_contains_any": ["Clickjacking", "X-Frame-Options"]},
            {"vuln_contains_any": ["CSRF", "XSS", "Broken Authentication"]},
        ],
        "chain_severity": "High",
        "description": "Missing frame protection combined with CSRF/XSS enables UI redressing attacks for unauthorized actions.",
        "remediation": "Set X-Frame-Options: DENY and CSP frame-ancestors 'none'. Implement CSRF tokens.",
        "owasp": ["A01:2021 Broken Access Control", "A05:2021 Security Misconfiguration"],
        "exploitability": "Likely",
        "risk_bonus": 15,
    },
    {
        "name": "Authentication Bypass Chain",
        "requires": [
            {"vuln_contains_any": ["Broken Authentication", "Missing Function Level Access", "IDOR"]},
            {"vuln_contains_any": ["Credential Stuffing", "Privilege Escalation", "Session"]},
        ],
        "chain_severity": "Critical",
        "description": "Multiple authentication weaknesses combine to enable unauthorized access to admin functions.",
        "remediation": "Implement proper authentication, authorization, and session management across all endpoints.",
        "owasp": ["A01:2021 Broken Access Control", "A07:2021 Identification and Authentication Failures"],
        "exploitability": "Likely",
        "risk_bonus": 25,
    },
    {
        "name": "Information Disclosure → Targeted Attack",
        "requires": [
            {"vuln_contains_any": ["Technology Stack", "Sensitive Data", "Security Misconfiguration"]},
            {"vuln_contains_any": ["SQL Injection", "XSS", "RCE", "SSTI", "Command Injection"]},
        ],
        "chain_severity": "Critical",
        "description": "Exposed technology details enable attackers to craft targeted exploits with higher success rates.",
        "remediation": "Remove verbose error messages, version headers, and debug endpoints from production.",
        "owasp": ["A05:2021 Security Misconfiguration", "A03:2021 Injection"],
        "exploitability": "Likely",
        "risk_bonus": 15,
    },
    {
        "name": "Remote Code Execution Chain",
        "requires": [
            {"vuln_contains_any": ["RCE", "SSTI", "Command Injection"]},
        ],
        "optional": [
            {"vuln_contains_any": ["LFI", "SSRF", "SQL Injection"]},
        ],
        "chain_severity": "Critical",
        "description": "Remote code execution vulnerability allows full server compromise. Combined with other vulns increases attack surface.",
        "remediation": "Fix code injection vulnerabilities. Implement WAF rules. Apply principle of least privilege to application runtime.",
        "owasp": ["A03:2021 Injection"],
        "exploitability": "Confirmed",
        "risk_bonus": 45,
    },
    {
        "name": "XML External Entity → Data Exfiltration",
        "requires": [
            {"vuln_contains_any": ["XXE", "XML"]},
        ],
        "optional": [
            {"vuln_contains_any": ["SSRF", "LFI"]},
        ],
        "chain_severity": "Critical",
        "description": "XXE can be used to read internal files, perform SSRF, and exfiltrate data via out-of-band channels.",
        "remediation": "Disable DTD processing. Use JSON instead of XML where possible. Update XML parsers.",
        "owasp": ["A05:2021 Security Misconfiguration"],
        "exploitability": "Confirmed",
        "risk_bonus": 30,
    },
    {
        "name": "Header Security Weakness Amplifier",
        "requires": [
            {"vuln_contains_any": ["Security Misconfiguration", "Clickjacking", "CORS"]},
            {"severity_in": ["Medium", "Low"]},
        ],
        "min_count": 3,
        "chain_severity": "High",
        "description": "Multiple header/configuration weaknesses indicate systemic security posture issues.",
        "remediation": "Implement a comprehensive security header policy. Use security header middleware.",
        "owasp": ["A05:2021 Security Misconfiguration"],
        "exploitability": "Theoretical",
        "risk_bonus": 10,
    },
]

# ── OWASP Top 10 2025 Mapping ──────────────────────────────────────────

OWASP_MAPPING = {
    "SQL Injection":                    "A03:2021 Injection",
    "XSS":                              "A03:2021 Injection",
    "Command Injection":                "A03:2021 Injection",
    "SSTI":                             "A03:2021 Injection",
    "Template Injection":               "A03:2021 Injection",
    "RCE":                              "A03:2021 Injection",
    "LDAP Injection":                   "A03:2021 Injection",
    "HTML Injection":                   "A03:2021 Injection",
    "Header Injection":                 "A03:2021 Injection",
    "LFI":                              "A03:2021 Injection",
    "Local File Inclusion":             "A03:2021 Injection",
    "RFI":                              "A03:2021 Injection",
    "Remote File Inclusion":            "A03:2021 Injection",
    "Path Traversal":                   "A01:2021 Broken Access Control",
    "XXE":                              "A05:2021 Security Misconfiguration",
    "XML":                              "A05:2021 Security Misconfiguration",
    "SSRF":                             "A10:2021 Server-Side Request Forgery",
    "CORS":                             "A05:2021 Security Misconfiguration",
    "CSRF":                             "A01:2021 Broken Access Control",
    "Clickjacking":                     "A05:2021 Security Misconfiguration",
    "Broken Authentication":            "A07:2021 Identification and Authentication Failures",
    "Session":                          "A07:2021 Identification and Authentication Failures",
    "IDOR":                             "A01:2021 Broken Access Control",
    "Privilege Escalation":             "A01:2021 Broken Access Control",
    "Missing Function Level Access":    "A01:2021 Broken Access Control",
    "Sensitive Data":                   "A02:2021 Cryptographic Failures",
    "Insecure Crypto":                  "A02:2021 Cryptographic Failures",
    "Security Misconfiguration":        "A05:2021 Security Misconfiguration",
    "Vulnerable Components":            "A06:2021 Vulnerable and Outdated Components",
    "Technology Stack":                 "A05:2021 Security Misconfiguration",
    "Redirect":                         "A01:2021 Broken Access Control",
    "Buffer Overflow":                  "A03:2021 Injection",
    "Credential Stuffing":              "A07:2021 Identification and Authentication Failures",
    "Port":                             "A05:2021 Security Misconfiguration",
    "Subdomain":                        "A05:2021 Security Misconfiguration",
    "WAF":                              "A05:2021 Security Misconfiguration",
    "Directory":                        "A01:2021 Broken Access Control",
    "HTTP Verb":                        "A05:2021 Security Misconfiguration",
}

# ── Remediation Guidance Database ───────────────────────────────────────

REMEDIATION_DB = {
    "SQL Injection": "Use parameterized queries (prepared statements) for all database interactions. Apply input validation and implement a Web Application Firewall (WAF).",
    "XSS": "Encode all user input on output. Implement Content Security Policy (CSP) headers. Use framework-provided auto-escaping.",
    "CORS Misconfiguration": "Configure Access-Control-Allow-Origin to only trusted domains. Never reflect arbitrary Origin headers. Avoid wildcard with credentials.",
    "CSRF": "Implement anti-CSRF tokens on all state-changing forms. Use SameSite=Strict cookies. Verify Origin/Referer headers.",
    "Clickjacking": "Set X-Frame-Options: DENY header. Add CSP frame-ancestors 'none' directive.",
    "Session Hijacking": "Set HttpOnly, Secure, and SameSite flags on session cookies. Use HTTPS everywhere.",
    "Session Fixation": "Regenerate session ID after authentication. Invalidate old sessions.",
    "SSRF": "Validate and sanitize all user-supplied URLs. Block requests to internal networks and cloud metadata. Implement allowlists.",
    "LFI": "Use a whitelist of allowed files. Avoid user input in file paths. Disable dangerous PHP wrappers.",
    "RFI": "Disable remote file inclusion (allow_url_include=off in PHP). Validate file paths against allowlists.",
    "RCE": "Never pass user input to system commands. Use language-specific safe APIs. Implement strict input validation.",
    "SSTI": "Use logic-less templates. Sandbox template engines. Never pass user input directly to template evaluation.",
    "Command Injection": "Use parameterized APIs instead of shell commands. If unavoidable, strictly validate and escape all inputs.",
    "Path Traversal": "Use canonical path resolution. Validate paths against a whitelist. Chroot file access.",
    "XXE": "Disable DTD processing entirely. Use JSON instead of XML. Update XML parser libraries.",
    "LDAP Injection": "Use parameterized LDAP queries. Escape special LDAP characters in user input.",
    "HTML Injection": "HTML-encode all user output. Use Content Security Policy.",
    "Header Injection": "Validate and sanitize all user input used in HTTP headers. Block CRLF characters.",
    "Buffer Overflow": "Use memory-safe languages or frameworks. Implement input length validation.",
    "Broken Authentication": "Protect admin interfaces with strong authentication. Implement multi-factor authentication.",
    "Credential Stuffing": "Implement rate limiting, CAPTCHA, and account lockout policies on login endpoints.",
    "Security Misconfiguration": "Implement all security headers. Remove debug endpoints. Disable verbose error messages.",
    "Sensitive Data Exposure": "Remove secrets from source code. Use environment variables. Implement secret scanning in CI/CD.",
    "IDOR": "Implement proper authorization checks for all object references. Use indirect references (UUIDs).",
    "Privilege Escalation": "Implement role-based access control (RBAC). Validate permissions server-side for every request.",
    "Open Redirect": "Validate redirect URLs against an allowlist. Use relative paths only.",
    "Vulnerable Components": "Keep all dependencies updated. Use automated vulnerability scanning in CI/CD.",
}


class AttackChainAnalyzer:
    """Analyzes scan results to identify multi-vulnerability exploit paths."""

    def __init__(self, findings: List[dict]):
        self.findings = findings
        self.chains: List[AttackChain] = []

    def _finding_matches(self, finding: dict, condition: dict) -> bool:
        """Check if a finding matches a condition dict."""
        vuln = finding.get("vuln", "")

        if "vuln_contains" in condition:
            if condition["vuln_contains"].lower() not in vuln.lower():
                return False

        if "vuln_contains_any" in condition:
            if not any(kw.lower() in vuln.lower() for kw in condition["vuln_contains_any"]):
                return False

        if "severity_in" in condition:
            if finding.get("severity", "") not in condition["severity_in"]:
                return False

        return True

    def _find_matching_findings(self, condition: dict) -> List[dict]:
        """Return all findings that match a condition."""
        return [f for f in self.findings if self._finding_matches(f, condition)]

    def analyze(self) -> List[AttackChain]:
        """Run chain analysis on all findings."""
        self.chains = []

        for pattern in CHAIN_PATTERNS:
            # Check required conditions
            required_groups = []
            all_required_met = True

            for req in pattern["requires"]:
                matches = self._find_matching_findings(req)
                if not matches:
                    all_required_met = False
                    break
                required_groups.append(matches)

            if not all_required_met:
                continue

            # Check minimum count if specified
            if "min_count" in pattern:
                total_matches = sum(len(g) for g in required_groups)
                if total_matches < pattern["min_count"]:
                    continue

            # Collect all chain steps (flatten required + optional matches)
            chain_steps = []
            seen_vulns = set()
            for group in required_groups:
                for finding in group:
                    key = (finding.get("vuln"), finding.get("url"))
                    if key not in seen_vulns:
                        seen_vulns.add(key)
                        chain_steps.append(finding)

            # Add optional matches if present
            if "optional" in pattern:
                for opt in pattern["optional"]:
                    for finding in self._find_matching_findings(opt):
                        key = (finding.get("vuln"), finding.get("url"))
                        if key not in seen_vulns:
                            seen_vulns.add(key)
                            chain_steps.append(finding)

            # Calculate risk score
            base_severities = [s.get("severity", "Medium") for s in chain_steps]
            max_confidence = max((s.get("confidence", 50) for s in chain_steps), default=50)
            severity_weights = {"Critical": 40, "High": 30, "Medium": 20, "Low": 10}
            max_sev_weight = max(severity_weights.get(s, 20) for s in base_severities)
            risk_bonus = pattern.get("risk_bonus", 0)
            risk_score = min(100, max_sev_weight + (max_confidence * 0.4) + risk_bonus)

            # Determine exploitability
            confirmed_steps = sum(1 for s in chain_steps if s.get("confidence", 0) >= 70)
            if confirmed_steps >= len(pattern["requires"]):
                exploitability = "Confirmed"
            elif confirmed_steps > 0:
                exploitability = "Likely"
            else:
                exploitability = pattern.get("exploitability", "Theoretical")

            chain = AttackChain(
                name=pattern["name"],
                description=pattern["description"],
                steps=chain_steps,
                chain_severity=pattern["chain_severity"],
                base_severities=base_severities,
                risk_score=int(risk_score),
                remediation=pattern["remediation"],
                owasp_categories=pattern.get("owasp", []),
                exploitability=exploitability,
            )
            self.chains.append(chain)

        # Sort by risk score descending
        self.chains.sort(key=lambda c: c.risk_score, reverse=True)
        return self.chains

    def get_owasp_category(self, vuln_name: str) -> str:
        """Map a vulnerability name to the current OWASP Top 10 2025 taxonomy."""
        for keyword, category in OWASP_MAPPING.items():
            if keyword.lower() in vuln_name.lower():
                return category
        return "A02 Security Misconfiguration"

    def get_remediation(self, vuln_name: str) -> str:
        """Get remediation guidance for a vulnerability type."""
        for keyword, advice in REMEDIATION_DB.items():
            if keyword.lower() in vuln_name.lower():
                return advice
        return "Review and fix the identified vulnerability according to security best practices."

    def get_risk_grade(self) -> str:
        """
        Calculate overall risk grade (A-F) based on all findings and chains.

        A = No significant findings
        B = Only low-severity informational findings
        C = Medium-severity findings, no confirmed critical chains
        D = High-severity confirmed findings or critical chains
        F = Multiple critical findings with confirmed exploit chains
        """
        if not self.findings:
            return "A"

        has_critical = any(f.get("severity") == "Critical" and f.get("confidence", 0) >= 70 for f in self.findings)
        has_high = any(f.get("severity") == "High" and f.get("confidence", 0) >= 70 for f in self.findings)
        has_medium = any(f.get("severity") == "Medium" for f in self.findings)
        critical_chains = [c for c in self.chains if c.chain_severity == "Critical" and c.exploitability == "Confirmed"]
        high_chains = [c for c in self.chains if c.chain_severity in ("Critical", "High")]

        if has_critical and critical_chains:
            return "F"
        if has_critical or critical_chains:
            return "D"
        if has_high or high_chains:
            return "D"
        if has_medium:
            return "C"
        return "B"

    def enrich_findings(self) -> List[dict]:
        """Add OWASP category, remediation, and attack-chain steps to each finding."""
        for finding in self.findings:
            vuln = finding.get("vuln", "")
            finding["owasp"] = self.get_owasp_category(vuln)
            finding["remediation"] = self.get_remediation(vuln)

            chain_steps = []
            for chain in self.chains:
                chain_step_names = {(step.get("vuln"), step.get("url")) for step in chain.steps}
                if (finding.get("vuln"), finding.get("url")) in chain_step_names:
                    chain_steps.append({
                        "chain_name": chain.name,
                        "chain_severity": chain.chain_severity,
                        "steps": [
                            {"vuln": step.get("vuln"), "url": step.get("url")}
                            for step in chain.steps
                        ],
                    })

            finding["attack_chain_steps"] = chain_steps

            # Calculate composite risk score
            severity_weights = {"Critical": 40, "High": 30, "Medium": 20, "Low": 10}
            sev_score = severity_weights.get(finding.get("severity", "Medium"), 20)
            conf_score = finding.get("confidence", 50) * 0.6
            finding["risk_score"] = min(100, int(sev_score + conf_score))

        return self.findings
