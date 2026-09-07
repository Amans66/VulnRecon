import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from main import has_active_inputs, normalize_target_url, select_plugins_for_intensity, HOST_PLUGINS, normalize_finding, should_keep_finding, ProgressTracker


def test_has_active_inputs_detects_query_strings():
    assert has_active_inputs('https://example.com/search?q=1') is True


def test_has_active_inputs_treats_static_extensions_as_non_input_pages():
    assert has_active_inputs('https://example.com/app.js') is False


def test_has_active_inputs_treats_root_path_as_dynamic():
    assert has_active_inputs('https://example.com/') is True


def test_normalize_target_url_adds_http_scheme():
    assert normalize_target_url('example.com') == 'http://example.com/'


def test_select_plugins_for_quick_mode_skips_expensive_checks():
    selected = select_plugins_for_intensity(HOST_PLUGINS, 1, is_host=True)
    assert all(plugin.__name__ != 'test_port_scanner' for plugin in selected)


def test_normalize_finding_adds_defaults_and_clamps_status():
    finding = normalize_finding({"vuln": "XSS", "url": "https://example.com", "confidence": 60})
    assert finding["status"] == "POSSIBLE"
    assert finding["confidence"] == 60
    assert finding["signals"] == []
    assert finding["severity"] == "Medium"


def test_should_keep_finding_respects_confidence_threshold():
    low_confidence = normalize_finding({"vuln": "XSS", "url": "https://example.com", "confidence": 20})
    high_confidence = normalize_finding({"vuln": "XSS", "url": "https://example.com", "confidence": 80})

    assert should_keep_finding(low_confidence, 40) is False
    assert should_keep_finding(high_confidence, 40) is True


def test_should_keep_finding_rejects_incomplete_results():
    incomplete = normalize_finding({"confidence": 80})
    assert should_keep_finding(incomplete, 40) is False


def test_progress_tracker_handles_zero_total_without_crashing():
    tracker = ProgressTracker(0)
    tracker.tick()
    tracker.finish()


def test_normalize_finding_handles_string_confidence_values():
    finding = normalize_finding({"vuln": "XSS", "url": "https://example.com", "confidence": "68.5", "risk_score": "75"})
    assert finding["confidence"] == 68
    assert finding["risk_score"] == 75
