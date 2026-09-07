"""
Finding Correlator — Deduplication, merging, and severity amplification.

Post-scan analysis that:
  - Removes exact duplicate findings
  - Merges findings with the same root cause
  - Elevates severity when correlated findings indicate systemic issues
  - Groups related vulnerabilities
"""


# ── Correlation Rules ──────────────────────────────────────────────────
# If findings match BOTH vuln types in a rule, severity may be elevated.
CORRELATION_RULES = [
    {
        "name": "Broken Access Control Cluster",
        "types": ["IDOR", "Privilege Escalation", "Missing Function Level Access",
                  "Forced Browsing"],
        "elevated_severity": "Critical",
        "min_count": 2,
    },
    {
        "name": "Injection Cluster",
        "types": ["SQL Injection", "Command Injection", "SSTI", "XSS",
                  "LDAP Injection", "NoSQL Injection", "XPath Injection"],
        "elevated_severity": "Critical",
        "min_count": 2,
    },
    {
        "name": "Authentication Weakness Cluster",
        "types": ["Broken Authentication", "Session Fixation", "Session Hijacking",
                  "Credential Stuffing", "JWT", "Cookie Security"],
        "elevated_severity": "High",
        "min_count": 2,
    },
    {
        "name": "Information Disclosure Cluster",
        "types": ["Sensitive Data", "Secrets Exposure", "Error Disclosure",
                  "Technology Stack", "Security Misconfiguration"],
        "elevated_severity": "High",
        "min_count": 3,
    },
    {
        "name": "Configuration Weakness Cluster",
        "types": ["CORS", "Clickjacking", "Security Misconfiguration",
                  "Cookie Security", "Missing Security Headers"],
        "elevated_severity": "Medium",
        "min_count": 3,
    },
]


class FindingCorrelator:
    """Deduplicates, merges, and correlates scan findings."""

    def __init__(self):
        self.correlation_groups = []

    def correlate(self, findings: list) -> list:
        """
        Full correlation pipeline:
          1. Deduplicate exact copies
          2. Merge similar findings (same root cause)
          3. Elevate severity for systemic issues
          4. Sort by risk score

        Returns: Processed list of finding dicts.
        """
        if not findings:
            return []

        findings = self._deduplicate(findings)
        findings = self._merge_similar(findings)
        findings = self._elevate_severity(findings)

        # Sort by risk_score desc, then confidence desc
        findings.sort(
            key=lambda f: (f.get("risk_score", 0), f.get("confidence", 0)),
            reverse=True,
        )

        return findings

    def _deduplicate(self, findings: list) -> list:
        """Remove exact duplicate findings (same vuln + url + parameter)."""
        seen = set()
        unique = []

        for finding in findings:
            key = (
                finding.get("vuln", ""),
                finding.get("url", ""),
                finding.get("parameter", ""),
                finding.get("payload", ""),
            )
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    def _merge_similar(self, findings: list) -> list:
        """
        Merge findings with the same root cause.
        When the same vuln type is found on the same URL with different
        parameters, keep the highest-confidence one and annotate it.
        """
        # Group by (vuln_type, url)
        groups = {}
        for finding in findings:
            key = (finding.get("vuln", ""), finding.get("url", ""))
            groups.setdefault(key, []).append(finding)

        merged = []
        for key, group in groups.items():
            if len(group) == 1:
                merged.append(group[0])
            else:
                # Keep the highest-confidence finding
                group.sort(key=lambda f: f.get("confidence", 0), reverse=True)
                best = dict(group[0])  # Copy

                # Annotate with other affected parameters
                other_params = [
                    f.get("parameter", "")
                    for f in group[1:]
                    if f.get("parameter")
                ]
                if other_params:
                    existing_details = best.get("details", "")
                    best["details"] = (
                        f"{existing_details} "
                        f"[Also affects parameters: {', '.join(other_params)}]"
                    ).strip()

                # Take max confidence and risk_score
                best["confidence"] = max(f.get("confidence", 0) for f in group)
                best["risk_score"] = max(f.get("risk_score", 0) for f in group)

                # Merge signals
                all_signals = set()
                for f in group:
                    all_signals.update(f.get("signals", []))
                best["signals"] = list(all_signals)

                merged.append(best)

        return merged

    def _elevate_severity(self, findings: list) -> list:
        """
        Check correlation rules and elevate severity when multiple
        related vulnerability types are found together.
        """
        vuln_types = set()
        for f in findings:
            vuln = f.get("vuln", "")
            for rule in CORRELATION_RULES:
                for rule_type in rule["types"]:
                    if rule_type.lower() in vuln.lower():
                        vuln_types.add(rule_type)

        self.correlation_groups = []

        for rule in CORRELATION_RULES:
            matched = [t for t in rule["types"] if t in vuln_types]
            if len(matched) >= rule["min_count"]:
                self.correlation_groups.append({
                    "name": rule["name"],
                    "matched_types": matched,
                    "elevated_severity": rule["elevated_severity"],
                })

                # Elevate severity of related findings
                severity_order = {
                    "Critical": 4, "High": 3, "Medium": 2,
                    "Low": 1, "Informational": 0,
                }
                target_level = severity_order.get(rule["elevated_severity"], 2)

                for finding in findings:
                    vuln = finding.get("vuln", "")
                    for rule_type in matched:
                        if rule_type.lower() in vuln.lower():
                            current_level = severity_order.get(
                                finding.get("severity", "Medium"), 2
                            )
                            if current_level < target_level:
                                finding["severity"] = rule["elevated_severity"]
                                finding["details"] = (
                                    finding.get("details", "") +
                                    f" [Severity elevated: part of {rule['name']}]"
                                ).strip()
                            break

        return findings

    def get_correlation_summary(self) -> list:
        """Return detected correlation groups for reporting."""
        return self.correlation_groups
