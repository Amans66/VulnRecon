"""
Plugin base classes and Finding dataclass for standardized vulnerability reporting.

Provides:
  - Finding dataclass with full evidence capture and backward compatibility
  - VulnerabilityPlugin base class with standardized metadata
  - Legacy dict conversion utilities
"""

import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import List, Optional
from core.config import ScannerConfig


@dataclass
class Finding:
    """Canonical vulnerability finding with evidence-backed lifecycle tracking."""
    # ── Identity ──
    id: str = ""
    finding_id: str = ""
    title: str = ""
    category: str = ""
    url: str = ""
    method: str = "GET"
    parameter: str = ""
    target: str = ""
    asset: str = ""

    # ── Classification ──
    severity: str = "Medium"        # Critical, High, Medium, Low, Informational
    confidence: int = 50            # 0-100
    confidence_label: str = ""      # Computed from confidence
    owasp: str = ""                 # legacy taxonomy value
    owasp_2025: str = ""            # current OWASP Top 10 2025 label
    cwe: int = 0                    # e.g., 89
    cvss: float = 0.0              # e.g., 8.6

    # ── Details ──
    description: str = ""
    evidence: str = ""
    impact: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    payload: str = ""
    detection_method: str = ""
    root_cause: str = ""
    attack_scenario: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    poc: str = ""
    expected_behavior: str = ""
    observed_behavior: str = ""
    validation: str = ""
    affected_component: str = ""
    attack_prerequisites: str = ""
    writeup: str = ""
    attack_story: str = ""
    confidence_reasoning: str = ""
    what_proven: str = ""
    what_not_tested: str = ""
    attacker_requirements: str = ""
    request: str = ""
    response: str = ""
    validation_request: str = ""
    validation_response: str = ""
    baseline: str = ""
    true_condition: str = ""
    false_condition: str = ""
    detection: str = ""
    payload_purpose: str = ""
    impacted_component: str = ""

    # ── Evidence Chain ──
    baseline_request: str = ""
    test_request: str = ""
    baseline_response: str = ""
    test_response: str = ""
    request_evidence: str = ""
    response_evidence: str = ""
    validation_steps: List[str] = field(default_factory=list)
    validation_result: dict = field(default_factory=lambda: {"oracle": "", "consistent": False, "repetitions": 0})

    # ── Validation / lifecycle ──
    validation_status: str = "needs_manual"
    lifecycle: str = "DISCOVERED"
    status: str = "DISCOVERED"
    source_engine: str = "sentinel"
    source_tools: List[str] = field(default_factory=lambda: ["sentinel"])
    reproducible: bool = False
    security_impact: str = ""
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Legacy compatibility
    signals: List[str] = field(default_factory=list)
    risk_score: int = 0             # 0-100 composite

    def __post_init__(self):
        if not self.id:
            self.id = uuid.uuid4().hex[:16]
        if not self.finding_id:
            self.finding_id = self.id
        if not self.owasp_2025:
            self.owasp_2025 = self._derive_owasp_2025()
        if not self.owasp:
            self.owasp = self.owasp_2025
        if not self.category:
            self.category = self._derive_category()
        if not self.confidence_label:
            self.confidence_label = ScannerConfig.get_confidence_label(self.confidence)
        if self.source_tools == []:
            self.source_tools = ["sentinel"]
        if self.status in {"", None}:
            self.status = "DISCOVERED"
        if self.lifecycle in {"", None}:
            self.lifecycle = "DISCOVERED"

    def _derive_owasp_2025(self) -> str:
        title = (self.title or "").strip()
        if not title:
            return "A10 Mishandling of Exceptional Conditions"
        return ScannerConfig.get_owasp_2025(title)

    def _derive_category(self) -> str:
        title = (self.title or "").lower()
        if any(token in title for token in ["sql", "xss", "injection", "rce", "sqli", "ssti", "command", "ldap", "xpath", "nosql", "xxe", "lfi", "path traversal", "rfi"]):
            return "Injection"
        if any(token in title for token in ["idor", "authorization", "privilege", "forced browsing", "redirect", "access control"]):
            return "Broken Access Control"
        if any(token in title for token in ["misconfig", "header", "cors", "clickjacking", "cookie", "security header", "exposed"]):
            return "Security Misconfiguration"
        if any(token in title for token in ["dependency", "component", "wordpress", "plugin", "package", "sbom"]):
            return "Supply Chain"
        if any(token in title for token in ["auth", "session", "token", "credential", "login", "jwt"]):
            return "Authentication"
        return "Security Finding"

    def to_dict(self) -> dict:
        """Convert to a compatibility-ready dict while exposing the new canonical contract."""
        legacy_status = self.status or "DISCOVERED"

        if self.confidence >= ScannerConfig.CONFIDENCE_CONFIRMED:
            status = "CONFIRMED"
        elif self.confidence >= ScannerConfig.CONFIDENCE_POSSIBLE:
            status = "POSSIBLE"
        else:
            status = "NOISE"

        return {
            # Canonical contract
            "finding_id": self.finding_id,
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "target": self.target,
            "asset": self.asset,
            "status": legacy_status,
            "lifecycle": self.lifecycle,
            "owasp": self.owasp,
            "owasp_2025": self.owasp_2025,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "severity": self.severity,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "source_engine": self.source_engine,
            "source_tools": list(self.source_tools),
            "baseline_request": self.baseline_request,
            "test_request": self.test_request,
            "baseline_response": self.baseline_response,
            "test_response": self.test_response,
            "evidence": self.evidence,
            "validation_steps": list(self.validation_steps),
            "validation_result": dict(self.validation_result),
            "confidence": self.confidence,
            "reproducible": self.reproducible,
            "security_impact": self.security_impact,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "validation_status": self.validation_status,
            "confidence_label": self.confidence_label,
            "detection_method": self.detection_method,
            "root_cause": self.root_cause,
            "attack_scenario": self.attack_scenario,
            "poc": self.poc,
            "expected_behavior": self.expected_behavior,
            "observed_behavior": self.observed_behavior,
            "validation": self.validation,
            "affected_component": self.affected_component,
            "attack_prerequisites": self.attack_prerequisites,
            "writeup": self.writeup,
            "attack_story": self.attack_story,
            "confidence_reasoning": self.confidence_reasoning,
            "what_proven": self.what_proven,
            "what_not_tested": self.what_not_tested,
            "attacker_requirements": self.attacker_requirements,
            "request": self.request,
            "response": self.response,
            "validation_request": self.validation_request,
            "validation_response": self.validation_response,
            "baseline": self.baseline,
            "true_condition": self.true_condition,
            "false_condition": self.false_condition,
            "detection": self.detection,
            "payload_purpose": self.payload_purpose,
            "impacted_component": self.impacted_component,
            # Legacy fields
            "vuln": self.title,
            "details": self.description,
            "description": self.description,
            "payload": self.payload,
            "signals": self.signals,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references,
            "request_evidence": self.request_evidence,
            "response_evidence": self.response_evidence,
            "reproduction_steps": self.reproduction_steps,
            "risk_score": self.risk_score,
        }

    @classmethod
    def from_legacy_dict(cls, d: dict) -> 'Finding':
        """Convert a legacy finding dict to a Finding object."""
        vuln_name = d.get("vuln", d.get("title", "Unknown"))
        confidence = int(d.get("confidence", 50))
        source_tools = d.get("source_tools", ["sentinel"])
        if isinstance(source_tools, str):
            source_tools = [source_tools]

        return cls(
            id=d.get("id", d.get("finding_id", "")),
            finding_id=d.get("finding_id", d.get("id", "")),
            title=vuln_name,
            category=d.get("category", ""),
            target=d.get("target", ""),
            asset=d.get("asset", ""),
            url=d.get("url", ""),
            method=d.get("method", "GET"),
            parameter=d.get("parameter", ""),
            severity=d.get("severity", "Medium"),
            confidence=confidence,
            confidence_label=ScannerConfig.get_confidence_label(confidence),
            owasp=d.get("owasp", ""),
            owasp_2025=d.get("owasp_2025", ScannerConfig.get_owasp_2025(vuln_name)),
            cwe=d.get("cwe", ScannerConfig.get_cwe(vuln_name)),
            cvss=d.get("cvss", ScannerConfig.get_cvss(vuln_name)),
            description=d.get("details", d.get("description", "")),
            evidence=d.get("evidence", ""),
            impact=d.get("impact", ""),
            remediation=d.get("remediation", ""),
            references=d.get("references", []),
            payload=d.get("payload", ""),
            baseline_request=d.get("baseline_request", ""),
            test_request=d.get("test_request", ""),
            baseline_response=d.get("baseline_response", ""),
            test_response=d.get("test_response", ""),
            request_evidence=d.get("request_evidence", ""),
            response_evidence=d.get("response_evidence", ""),
            reproduction_steps=d.get("reproduction_steps", []),
            validation_steps=d.get("validation_steps", []),
            validation_result=d.get("validation_result", {"oracle": "", "consistent": False, "repetitions": 0}),
            validation_status=d.get("validation_status", "needs_manual"),
            lifecycle=d.get("lifecycle", "DISCOVERED"),
            status=d.get("status", ""),
            source_engine=d.get("source_engine", "sentinel"),
            source_tools=source_tools,
            reproducible=d.get("reproducible", False),
            security_impact=d.get("security_impact", ""),
            first_seen=d.get("first_seen", datetime.now(timezone.utc).isoformat()),
            last_seen=d.get("last_seen", datetime.now(timezone.utc).isoformat()),
            signals=d.get("signals", []),
            risk_score=d.get("risk_score", 0),
        )


def enrich_finding(finding_dict: dict) -> dict:
    """Enrich a legacy finding dict with canonical lifecycle/state metadata."""
    vuln_name = finding_dict.get("vuln", "")
    confidence = int(finding_dict.get("confidence", 50))

    finding_dict.setdefault("finding_id", finding_dict.get("id", uuid.uuid4().hex[:16]))
    finding_dict.setdefault("id", finding_dict["finding_id"])
    finding_dict.setdefault("cwe", ScannerConfig.get_cwe(vuln_name))
    finding_dict.setdefault("cvss", ScannerConfig.get_cvss(vuln_name))
    finding_dict.setdefault("confidence_label", ScannerConfig.get_confidence_label(confidence))
    finding_dict.setdefault("validation_status", "needs_manual")
    finding_dict.setdefault("lifecycle", "DISCOVERED")
    finding_dict.setdefault("status", "")
    finding_dict.setdefault("method", "GET")
    finding_dict.setdefault("impact", "")
    finding_dict.setdefault("references", [])
    finding_dict.setdefault("request_evidence", "")
    finding_dict.setdefault("response_evidence", "")
    finding_dict.setdefault("reproduction_steps", [])
    finding_dict.setdefault("validation_steps", [])
    finding_dict.setdefault("validation_result", {"oracle": "", "consistent": False, "repetitions": 0})
    finding_dict.setdefault("source_engine", "sentinel")
    finding_dict.setdefault("source_tools", ["sentinel"])
    finding_dict.setdefault("title", vuln_name)
    finding_dict.setdefault("description", finding_dict.get("details", ""))
    finding_dict.setdefault("category", Finding(title=vuln_name)._derive_category())
    finding_dict.setdefault("owasp_2025", ScannerConfig.get_owasp_2025(vuln_name))
    finding_dict.setdefault("security_impact", "")
    finding_dict.setdefault("reproducible", False)
    finding_dict.setdefault("first_seen", datetime.now(timezone.utc).isoformat())
    finding_dict.setdefault("last_seen", datetime.now(timezone.utc).isoformat())

    return finding_dict
