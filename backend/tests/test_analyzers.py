"""Tests for analyzer modules (permission, component, API detection, etc.)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "analyzer", "scripts"))


def test_permission_classification():
    """Test that known permissions are classified correctly."""
    from permission_analyzer import analyze_permissions

    perms = [
        "android.permission.INTERNET",
        "android.permission.READ_SMS",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
    ]

    classified, _ = analyze_permissions(perms)

    classifications = {p["name"]: p["classification"] for p in classified}
    assert classifications["INTERNET"] == "NORMAL"
    assert classifications["READ_SMS"] == "DANGEROUS"
    assert classifications["SYSTEM_ALERT_WINDOW"] == "SPECIAL"
    assert classifications["REQUEST_INSTALL_PACKAGES"] == "HIGH_RISK"


def test_permission_correlation_sms_internet():
    """Test SMS + INTERNET correlation rule fires."""
    from permission_analyzer import analyze_permissions

    perms = [
        "android.permission.READ_SMS",
        "android.permission.INTERNET",
    ]

    _, correlations = analyze_permissions(perms)

    rule_ids = [c["rule_id"] for c in correlations]
    assert "CORR_SMS_INTERNET" in rule_ids


def test_permission_correlation_no_false_positive():
    """Test that correlations don't fire without all required permissions."""
    from permission_analyzer import analyze_permissions

    perms = ["android.permission.INTERNET"]  # Only INTERNET, no SMS

    _, correlations = analyze_permissions(perms)

    assert not any(c["rule_id"] == "CORR_SMS_INTERNET" for c in correlations)


def test_correlation_has_required_fields():
    """Test that every correlation has rule_id, severity, evidence, etc."""
    from permission_analyzer import analyze_permissions

    perms = [
        "android.permission.READ_SMS",
        "android.permission.INTERNET",
        "android.permission.RECORD_AUDIO",
    ]

    _, correlations = analyze_permissions(perms)

    for corr in correlations:
        assert "rule_id" in corr
        assert "severity" in corr
        assert "points" in corr
        assert "evidence" in corr
        assert "description" in corr


def test_component_exported_unprotected():
    """Test that exported unprotected components are flagged."""
    from component_analyzer import analyze_components

    components = [
        {
            "name": "com.example.ExposedActivity",
            "type": "activity",
            "exported": True,
            "permission_protected": False,
            "permission": None,
            "has_intent_filter": True,
            "intent_filters": [],
        }
    ]

    analyzed, summary = analyze_components(components)

    assert summary["exported_activities"] == 1
    assert summary["unprotected_exported"] == 1
    assert analyzed[0]["severity"] == "HIGH"


def test_component_exported_protected():
    """Test that exported protected components get MEDIUM severity."""
    from component_analyzer import analyze_components

    components = [
        {
            "name": "com.example.ProtectedService",
            "type": "service",
            "exported": True,
            "permission_protected": True,
            "permission": "com.example.MY_PERMISSION",
            "has_intent_filter": False,
            "intent_filters": [],
        }
    ]

    analyzed, summary = analyze_components(components)

    assert summary["exported_services"] == 1
    assert summary["unprotected_exported"] == 0
    assert analyzed[0]["severity"] == "MEDIUM"


def test_component_summary_counts():
    """Test that component summary counts are accurate."""
    from component_analyzer import analyze_components

    components = [
        {"name": "A1", "type": "activity", "exported": False, "permission_protected": False, "has_intent_filter": False, "intent_filters": []},
        {"name": "A2", "type": "activity", "exported": True, "permission_protected": False, "has_intent_filter": True, "intent_filters": []},
        {"name": "S1", "type": "service", "exported": False, "permission_protected": False, "has_intent_filter": False, "intent_filters": []},
        {"name": "R1", "type": "receiver", "exported": True, "permission_protected": True, "permission": "P", "has_intent_filter": True, "intent_filters": []},
        {"name": "P1", "type": "provider", "exported": False, "permission_protected": False, "has_intent_filter": False, "intent_filters": []},
    ]

    _, summary = analyze_components(components)

    assert summary["total_activities"] == 2
    assert summary["exported_activities"] == 1
    assert summary["total_services"] == 1
    assert summary["exported_services"] == 0
    assert summary["total_receivers"] == 1
    assert summary["exported_receivers"] == 1
    assert summary["total_providers"] == 1
    assert summary["exported_providers"] == 0
    assert summary["unprotected_exported"] == 1  # Only A2


def test_secret_redaction():
    """Test that secrets are properly redacted."""
    from secret_detector import _redact

    assert _redact("AKIAIOSFODNN7EXAMPLE") == "AKIA…MPLE"
    assert _redact("short") == "****"
    assert _redact("12345678") == "****"
    assert _redact("123456789") == "1234…6789"


def test_shannon_entropy():
    """Test entropy calculation."""
    from secret_detector import _shannon_entropy

    # All same character = 0 entropy
    assert _shannon_entropy("aaaaaaa") == 0.0

    # High entropy string
    high_entropy = _shannon_entropy("aB3$xK9!mZ")
    assert high_entropy > 3.0

    # Empty string
    assert _shannon_entropy("") == 0.0


def test_obfuscation_score_range():
    """Test that obfuscation score is in valid range."""
    from obfuscation_analyzer import _compute_score

    stats = {
        "total_classes": 100,
        "short_name_classes": 80,
        "total_methods": 200,
        "short_name_methods": 150,
        "base64_strings": 30,
        "dynamic_loading": 5,
        "encoded_strings": 15,
    }
    indicators = []

    score = _compute_score(stats, indicators)
    assert 0 <= score <= 100
    assert len(indicators) > 0
