"""
Unit tests for Sentinel v6.0 core features.
Tests scope validation, request history, auth profiles, attack surface,
JS analyzer, validation engine, and finding correlator.
"""

from core.scope import ScopeValidator
from core.request_history import RequestHistory
from core.auth_profiles import AuthProfile, AuthProfileManager
from core.attack_surface import AttackSurfaceMap, Endpoint, DiscoveredForm, FormField
from core.js_analyzer import JSAnalyzer
from core.validator import ValidationEngine
from core.correlator import FindingCorrelator
from core.plugin_base import Finding


def test_scope_validator():
    validator = ScopeValidator(allowed_hosts=["example.com"], excluded_paths=[r"^/admin/.*"])
    
    # In scope
    assert validator.is_in_scope("https://example.com/page") is True
    
    # Out of scope host
    assert validator.is_in_scope("https://otherdomain.com/page") is False
    
    # Excluded path
    assert validator.is_in_scope("https://example.com/admin/settings") is False


def test_request_history():
    history = RequestHistory()
    req_id = history.record(
        method="GET",
        url="https://example.com/api/test",
        headers={"User-Agent": "Sentinel"},
        response_status=200,
        response_body_snippet="OK",
        elapsed=0.15,
    )
    
    assert req_id is not None
    assert history.size() == 1
    
    record = history.get(req_id)
    assert record["method"] == "GET"
    assert record["url"] == "https://example.com/api/test"
    
    har = history.export_har()
    assert har["log"]["creator"]["name"] == "VulnerabilityScanner"
    assert len(har["log"]["entries"]) == 1


def test_auth_profiles():
    manager = AuthProfileManager()
    
    # Check default unauthenticated profile
    assert manager.get_profile("unauthenticated") is not None
    
    # Add authenticated profile
    user_profile = AuthProfile(
        name="user1",
        role="normal",
        auth_type="cookie",
        session_cookies={"sessionid": "xyz123"},
    )
    manager.add_profile(user_profile)
    
    assert len(manager.get_authenticated()) == 1
    assert manager.has_multiple_profiles() is True


def test_attack_surface_map():
    surface = AttackSurfaceMap()
    
    surface.add_endpoint(Endpoint(url="https://example.com/api/users", method="GET", params=["id"]))
    surface.add_technology("Django")
    surface.add_technology("PostgreSQL")
    surface.add_form(DiscoveredForm(action="/login", method="POST", fields=[FormField(name="username")]))
    
    injectable = surface.get_injectable_endpoints()
    assert len(injectable) == 1
    assert injectable[0].params == ["id"]
    
    summary = surface.summary()
    assert "Django" in summary
    assert "Endpoints: 1" in summary


def test_js_analyzer():
    analyzer = JSAnalyzer()
    sample_js = """
    function getUsers() {
        fetch('/api/v1/users?role=admin');
        axios.post('/api/v1/auth/login');
    }
    const apiKey = "AKIA1234567890ABCDEF";
    """
    
    result = analyzer.analyze_file("https://example.com/app.js", sample_js)
    
    assert "/api/v1/users?role=admin" in result["endpoints"] or "/api/v1/auth/login" in result["endpoints"]
    assert len(result["secrets"]) >= 1


def test_finding_dataclass():
    finding = Finding(
        title="SQL Injection",
        url="https://example.com/item",
        parameter="id",
        severity="High",
        confidence=85,
        cwe=89,
        cvss=8.6,
    )
    
    d = finding.to_dict()
    assert d["vuln"] == "SQL Injection"
    assert d["cwe"] == 89
    assert d["cvss"] == 8.6
    assert d["status"] == "DISCOVERED"
    
    reconstructed = Finding.from_legacy_dict(d)
    assert reconstructed.title == "SQL Injection"
    assert reconstructed.cwe == 89


def test_finding_correlator():
    correlator = FindingCorrelator()
    findings = [
        {"vuln": "IDOR", "url": "https://example.com/user/1", "parameter": "id", "severity": "Medium", "confidence": 80},
        {"vuln": "Privilege Escalation", "url": "https://example.com/admin", "parameter": "", "severity": "Medium", "confidence": 75},
        # Duplicate
        {"vuln": "IDOR", "url": "https://example.com/user/1", "parameter": "id", "severity": "Medium", "confidence": 80},
    ]
    
    correlated = correlator.correlate(findings)
    
    # Should deduplicate
    assert len(correlated) == 2
    
    # Access control cluster should elevate severity to Critical
    assert any(f["severity"] == "Critical" for f in correlated)
