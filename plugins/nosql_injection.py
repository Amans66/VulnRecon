"""
NoSQL Injection Detection Plugin v6.0.

Tests for MongoDB operator injection ($gt, $ne, $regex, $where)
in query parameters and JSON request bodies.

CWE-943 | CVSS 8.1 | OWASP A03:2021 Injection
"""

import json
from core.http_client import get, post
from core.response_analyzer import (
    get_baseline, diff_responses, detect_waf_block,
    calculate_confidence, make_finding,
)
from core.utils import inject_into_params, extract_params

PLUGIN_CWE = 943
PLUGIN_CVSS = 8.1
PLUGIN_OWASP = "A03:2021 Injection"

# Payloads targeting MongoDB query operators
NOSQL_PAYLOADS = [
    ('{"$gt":""}', "operator_gt"),
    ('{"$ne":""}', "operator_ne"),
    ('{"$regex":".*"}', "operator_regex"),
    ('{"$exists":true}', "operator_exists"),
    ("true, $where: '1 == 1'", "where_true"),
    ("'; return true; var a='", "js_return"),
    ('{"$gt":"","$lt":"z"}', "operator_range"),
]

# Error strings indicating NoSQL injection
NOSQL_ERRORS = [
    "mongoerror", "mongo", "bson", "bsonerror",
    "cast to objectid failed", "objectid",
    "syntaxerror", "unexpected token",
    "unterminated string", "json parse error",
    "$where", "mapreduce", "aggregate",
    "cannot apply $gt", "bad query",
    "command failed", "ns not found",
]


def test_nosql_injection(url):
    """Test for NoSQL injection in query parameters."""
    try:
        baseline = get_baseline(url, get)
        baseline_text = baseline.get("text_lower", "")

        for param_name, crafted_url in inject_into_params(url, '{"$gt":""}'):
            try:
                r = get(crafted_url)
                if r is None:
                    continue

                blocked, _ = detect_waf_block(r)
                if blocked:
                    continue

                body_lower = r.text.lower()
                signals = {}

                # Check for NoSQL errors
                errors_found = []
                for err in NOSQL_ERRORS:
                    if err in body_lower and err not in baseline_text:
                        errors_found.append(err)

                if errors_found:
                    signals["error_string"] = True
                    signals["nosql_bypass"] = True

                # Check for response differences indicating operator acceptance
                similarity = diff_responses(baseline.get("text", ""), r.text)
                if similarity < 0.85:
                    signals["response_diff"] = True

                # Status code change to 500 indicates injection
                if r.status_code >= 500 and baseline.get("status_code", 200) < 500:
                    signals["status_change"] = True

                if signals:
                    confidence = calculate_confidence(signals)
                    finding = make_finding(
                        url, "NoSQL Injection",
                        confidence=confidence, signals=signals,
                        details=f"NoSQL operator injection detected via parameter '{param_name}'",
                        severity="High", payload='{"$gt":""}',
                        evidence=f"Error indicators: {', '.join(errors_found)}" if errors_found else f"Response diff: {similarity:.2f}",
                        parameter=param_name,
                    )
                    if finding:
                        finding["cwe"] = PLUGIN_CWE
                        finding["cvss"] = PLUGIN_CVSS
                        finding["owasp"] = PLUGIN_OWASP
                        return finding

            except Exception:
                continue

        # Test JSON body injection on root URL
        json_payloads = [
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": {"$ne": ""}, "password": {"$ne": ""}},
        ]
        for payload in json_payloads:
            try:
                r = post(url, json=payload)
                if r is None:
                    continue
                blocked, _ = detect_waf_block(r)
                if blocked:
                    continue
                body_lower = r.text.lower()
                if any(err in body_lower and err not in baseline_text for err in NOSQL_ERRORS):
                    signals = {"error_string": True, "nosql_bypass": True}
                    confidence = calculate_confidence(signals)
                    finding = make_finding(
                        url, "NoSQL Injection",
                        confidence=confidence, signals=signals,
                        details="NoSQL operator injection via JSON body",
                        severity="High", payload=json.dumps(payload),
                        evidence="NoSQL error triggered by operator payload",
                    )
                    if finding:
                        finding["cwe"] = PLUGIN_CWE
                        finding["cvss"] = PLUGIN_CVSS
                        finding["owasp"] = PLUGIN_OWASP
                        return finding
            except Exception:
                continue

    except Exception:
        pass
    return None
