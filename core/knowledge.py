"""
Central Security Knowledge Base v6.0.

Provides structured metadata, OWASP mappings, CWE details, fingerprints,
and remediation guidance inspired by open-source security intelligence
(SQLMap, Dalfox, Nikto, WPScan, SpiderFoot, Recon-ng, Book of Secret Knowledge).
"""

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class RuleMetadata:
    id: str
    name: str
    category: str
    owasp: str
    cwe: int
    cvss: float
    severity: str
    detection_logic: str
    validation_logic: str
    remediation: str
    references: List[str] = field(default_factory=list)


KNOWLEDGE_RULES: Dict[str, RuleMetadata] = {
    "SQLI_001": RuleMetadata(
        id="SQLI_001",
        name="SQL Injection (Error-Based)",
        category="Injection",
        owasp="A05 Injection",
        cwe=89,
        cvss=8.6,
        severity="Critical",
        detection_logic="Inject DBMS syntax breaking characters and detect non-baseline database error signatures.",
        validation_logic="Re-verify error string on payload injection and confirm absence on safe negative control.",
        remediation="Use parameterized queries (prepared statements) for all database access.",
        references=["https://owasp.org/www-community/attacks/SQL_Injection", "https://github.com/sqlmapproject/sqlmap"],
    ),
    "SQLI_002": RuleMetadata(
        id="SQLI_002",
        name="SQL Injection (Boolean-Based Blind)",
        category="Injection",
        owasp="A05 Injection",
        cwe=89,
        cvss=8.6,
        severity="Critical",
        detection_logic="Inject true and false boolean expressions and measure response similarity ratio.",
        validation_logic="True query must match baseline (>0.85 sim), False query must differ (<0.80 sim).",
        remediation="Use parameterized queries and Object-Relational Mapping (ORM) frameworks.",
        references=["https://github.com/sqlmapproject/sqlmap"],
    ),
    "XSS_001": RuleMetadata(
        id="XSS_001",
        name="Cross-Site Scripting (Reflected)",
        category="Injection",
        owasp="A05 Injection",
        cwe=79,
        cvss=6.1,
        severity="High",
        detection_logic="Inject canary payload and check for unescaped reflection in executable DOM context.",
        validation_logic="Verify payload is NOT HTML-entity encoded and resides in executable tag/attribute/script context.",
        remediation="Context-aware output encoding (HTML, Attribute, JavaScript escaping) and CSP headers.",
        references=["https://github.com/hahwul/dalfox", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Preventative_Cheat_Sheet.html"],
    ),
    "XSS_002": RuleMetadata(
        id="XSS_002",
        name="DOM-Based Cross-Site Scripting",
        category="Injection",
        owasp="A05 Injection",
        cwe=79,
        cvss=6.1,
        severity="High",
        detection_logic="Analyze client-side JavaScript for data flow from sources (location.hash, URL) to dangerous sinks (innerHTML, eval).",
        validation_logic="Verify complete source-to-sink data flow without sanitization.",
        remediation="Avoid raw DOM sinks like innerHTML; use textContent or safe DOM APIs.",
        references=["https://github.com/hahwul/dalfox"],
    ),
    "WP_001": RuleMetadata(
        id="WP_001",
        name="WordPress Core / Plugin Exposure",
        category="Supply Chain",
        owasp="A03 Software Supply Chain Failures",
        cwe=1104,
        cvss=7.5,
        severity="Medium",
        detection_logic="Inspect WordPress generator meta tags, readme.html, plugin paths, and exposed author endpoints.",
        validation_logic="Confirm exact version string against known vulnerable version database.",
        remediation="Keep WordPress core, themes, and plugins updated to latest releases.",
        references=["https://github.com/wpscanteam/wpscan"],
    ),
    "NIKTO_001": RuleMetadata(
        id="NIKTO_001",
        name="Exposed Administrative / Debug Endpoint",
        category="Security Misconfiguration",
        owasp="A02 Security Misconfiguration",
        cwe=200,
        cvss=5.3,
        severity="Medium",
        detection_logic="Compound matching: HEADER/BODY/STATUS checks for sensitive backup/debug files.",
        validation_logic="Confirm non-404 response differs from soft-404 wildcard body.",
        remediation="Restrict access to admin and debug interfaces; remove backup files from web root.",
        references=["https://github.com/sullo/nikto"],
    ),
}


def get_rule(rule_id: str) -> Optional[RuleMetadata]:
    return KNOWLEDGE_RULES.get(rule_id)
