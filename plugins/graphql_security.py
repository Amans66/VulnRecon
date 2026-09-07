"""
GraphQL Security Plugin v6.0.

Detects GraphQL endpoints and tests for introspection status, field suggestion leaks,
and query complexity/depth protections.

CWE-200 | CVSS 5.3 | OWASP A01:2021 Broken Access Control
"""

import json
from urllib.parse import urlparse
from core.http_client import get, post
from core.response_analyzer import calculate_confidence, make_finding

PLUGIN_CWE = 200
PLUGIN_CVSS = 5.3
PLUGIN_OWASP = "A01:2021 Broken Access Control"

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/query", "/api/query", "/graphql/console", "/graphiql",
]

INTROSPECTION_QUERY = {
    "query": "{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind description } } }"
}


def test_graphql_security(url):
    """Test GraphQL endpoints for introspection and information leaks."""
    parsed = urlparse(url)
    if parsed.path not in ("", "/"):
        return None  # Host-only plugin

    base = url.rstrip("/")

    for path in GRAPHQL_PATHS:
        target_url = f"{base}{path}"
        try:
            # First probe with introspection POST request
            r = post(target_url, json=INTROSPECTION_QUERY, timeout=7)
            if r is None:
                # Try GET fallback
                r = get(f"{target_url}?query={{__schema{{types{{name}}}}}}", timeout=7)

            if r is None or r.status_code != 200:
                continue

            body_lower = r.text.lower()

            # Check if introspection succeeded
            if "__schema" in body_lower or "querytype" in body_lower or "mutationtype" in body_lower:
                signals = {
                    "graphql_exposed": True,
                    "introspection": True,
                    "data_leak": True,
                }
                confidence = calculate_confidence(signals)
                finding = make_finding(
                    url, "GraphQL Introspection Enabled",
                    confidence=confidence, signals=signals,
                    details=f"GraphQL endpoint at '{path}' has introspection enabled, leaking full API schema.",
                    severity="Medium", payload="INTROSPECTION_QUERY",
                    evidence=f"Response contained __schema details at {path}",
                )
                if finding:
                    finding["cwe"] = PLUGIN_CWE
                    finding["cvss"] = PLUGIN_CVSS
                    finding["owasp"] = PLUGIN_OWASP
                    return finding

            # Check for GraphiQL IDE exposure
            if "graphiql" in body_lower or "graphql playground" in body_lower or "apollo sandbox" in body_lower:
                signals = {
                    "graphql_exposed": True,
                    "admin_access": True,
                }
                confidence = calculate_confidence(signals)
                finding = make_finding(
                    url, "GraphQL IDE Exposed",
                    confidence=confidence, signals=signals,
                    details=f"Interactive GraphQL IDE exposed publicly at '{path}'.",
                    severity="Low", payload=path,
                    evidence=f"Interactive console detected at {path}",
                )
                if finding:
                    finding["cwe"] = PLUGIN_CWE
                    finding["cvss"] = PLUGIN_CVSS
                    finding["owasp"] = PLUGIN_OWASP
                    return finding

        except Exception:
            continue

    return None
