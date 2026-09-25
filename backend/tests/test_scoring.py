"""Tests for the deterministic scoring engine."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.scoring import ScoringEngine, _classify_risk_level


def test_risk_level_classification():
    """Test risk level boundaries."""
    assert _classify_risk_level(0) == "LOW"
    assert _classify_risk_level(20) == "LOW"
    assert _classify_risk_level(21) == "MODERATE"
    assert _classify_risk_level(40) == "MODERATE"
    assert _classify_risk_level(41) == "MEDIUM"
    assert _classify_risk_level(60) == "MEDIUM"
    assert _classify_risk_level(61) == "HIGH"
    assert _classify_risk_level(80) == "HIGH"
    assert _classify_risk_level(81) == "CRITICAL"
    assert _classify_risk_level(100) == "CRITICAL"


def test_empty_findings_score_zero():
    """Test that no findings produces a score of 0."""
    engine = ScoringEngine()
    results = engine.calculate_score({
        "permissions": [],
        "permission_correlations": [],
        "components": [],
        "suspicious_apis": [],
        "network_indicators": [],
        "potential_secrets": [],
        "obfuscation": {},
    })

    assert results["score"]["total"] == 0
    assert results["score"]["level"] == "LOW"


def test_permission_scoring():
    """Test that permissions are scored by classification."""
    engine = ScoringEngine()
    results = engine.calculate_score({
        "permissions": [
            {"name": "READ_SMS", "classification": "DANGEROUS"},
            {"name": "INTERNET", "classification": "NORMAL"},
        ],
        "permission_correlations": [],
        "components": [],
        "suspicious_apis": [],
        "network_indicators": [],
        "potential_secrets": [],
        "obfuscation": {},
    })

    score = results["score"]
    perm_breakdown = score["breakdown"]["permissions"]
    assert perm_breakdown["raw_points"] > 0
    assert len(perm_breakdown["contributions"]) == 2


def test_correlation_scoring():
    """Test that permission correlations add to score."""
    engine = ScoringEngine()
    results = engine.calculate_score({
        "permissions": [
            {"name": "READ_SMS", "classification": "DANGEROUS"},
            {"name": "INTERNET", "classification": "NORMAL"},
        ],
        "permission_correlations": [
            {
                "rule_id": "CORR_SMS_INTERNET",
                "severity": "HIGH",
                "points": 8,
                "evidence": "READ_SMS + INTERNET",
                "description": "SMS + Internet combination",
            }
        ],
        "components": [],
        "suspicious_apis": [],
        "network_indicators": [],
        "potential_secrets": [],
        "obfuscation": {},
    })

    perm = results["score"]["breakdown"]["permissions"]
    # Should have 2 permission contributions + 1 correlation
    assert len(perm["contributions"]) == 3


def test_component_scoring_exported_unprotected():
    """Test that exported unprotected components score HIGH."""
    engine = ScoringEngine()
    results = engine.calculate_score({
        "permissions": [],
        "permission_correlations": [],
        "components": [
            {"type": "activity", "name": "TestActivity", "exported": True, "permission_protected": False},
        ],
        "suspicious_apis": [],
        "network_indicators": [],
        "potential_secrets": [],
        "obfuscation": {},
    })

    comp = results["score"]["breakdown"]["components"]
    assert comp["raw_points"] == 8  # HIGH severity component
    assert comp["contributions"][0]["severity"] == "HIGH"


def test_api_scoring():
    """Test that suspicious API findings are scored."""
    engine = ScoringEngine()
    results = engine.calculate_score({
        "permissions": [],
        "permission_correlations": [],
        "components": [],
        "suspicious_apis": [
            {"category": "PROCESS_EXECUTION", "matched_api": "Runtime.exec", "file": "Test.java", "severity": "HIGH"},
            {"category": "SMS", "matched_api": "SmsManager", "file": "Sms.java", "severity": "HIGH"},
        ],
        "network_indicators": [],
        "potential_secrets": [],
        "obfuscation": {},
    })

    api = results["score"]["breakdown"]["code_api"]
    assert api["raw_points"] > 0
    assert len(api["contributions"]) == 2


def test_secret_scoring():
    """Test that secrets contribute to indicator score."""
    engine = ScoringEngine()
    results = engine.calculate_score({
        "permissions": [],
        "permission_correlations": [],
        "components": [],
        "suspicious_apis": [],
        "network_indicators": [],
        "potential_secrets": [
            {"type": "API_KEY", "redacted_evidence": "AKIA…WXYZ"},
        ],
        "obfuscation": {},
    })

    ind = results["score"]["breakdown"]["indicators"]
    assert ind["raw_points"] == 10
    assert ind["contributions"][0]["rule_id"] == "SECRET_API_KEY"


def test_score_capped_at_100():
    """Test that total score never exceeds 100."""
    engine = ScoringEngine()

    # Create extreme findings
    results = engine.calculate_score({
        "permissions": [{"name": f"PERM_{i}", "classification": "HIGH_RISK"} for i in range(50)],
        "permission_correlations": [
            {"rule_id": f"CORR_{i}", "severity": "HIGH", "points": 10, "evidence": "test", "description": "test"}
            for i in range(20)
        ],
        "components": [
            {"type": "activity", "name": f"Act{i}", "exported": True, "permission_protected": False}
            for i in range(30)
        ],
        "suspicious_apis": [
            {"category": "PROCESS_EXECUTION", "matched_api": f"Api{i}", "file": "test.java", "severity": "CRITICAL"}
            for i in range(30)
        ],
        "network_indicators": list(range(100)),
        "potential_secrets": [
            {"type": f"SECRET_{i}", "redacted_evidence": "****"} for i in range(20)
        ],
        "obfuscation": {"score": 90},
    })

    assert results["score"]["total"] <= 100.0


def test_score_deterministic():
    """Test that the same input always produces the same score."""
    engine = ScoringEngine()
    test_data = {
        "permissions": [
            {"name": "INTERNET", "classification": "NORMAL"},
            {"name": "CAMERA", "classification": "DANGEROUS"},
        ],
        "permission_correlations": [],
        "components": [
            {"type": "service", "name": "Svc", "exported": True, "permission_protected": True},
        ],
        "suspicious_apis": [
            {"category": "NETWORKING", "matched_api": "Socket", "file": "a.java", "severity": "MEDIUM"},
        ],
        "network_indicators": [],
        "potential_secrets": [],
        "obfuscation": {"score": 25},
    }

    import copy
    result1 = engine.calculate_score(copy.deepcopy(test_data))
    result2 = engine.calculate_score(copy.deepcopy(test_data))

    assert result1["score"]["total"] == result2["score"]["total"]
    assert result1["score"]["level"] == result2["score"]["level"]


def test_every_contribution_has_required_fields():
    """Test that all score contributions have traceable fields."""
    engine = ScoringEngine()
    results = engine.calculate_score({
        "permissions": [{"name": "READ_SMS", "classification": "DANGEROUS"}],
        "permission_correlations": [
            {"rule_id": "CORR_TEST", "severity": "HIGH", "points": 5, "evidence": "test", "description": "desc"}
        ],
        "components": [{"type": "activity", "name": "A", "exported": True, "permission_protected": False}],
        "suspicious_apis": [
            {"category": "SMS", "matched_api": "SmsManager", "file": "t.java", "severity": "HIGH"}
        ],
        "network_indicators": [],
        "potential_secrets": [{"type": "API_KEY", "redacted_evidence": "****"}],
        "obfuscation": {"score": 70},
    })

    required_fields = {"rule_id", "category", "severity", "points", "evidence", "explanation"}

    for cat_data in results["score"]["breakdown"].values():
        for contrib in cat_data["contributions"]:
            missing = required_fields - set(contrib.keys())
            assert not missing, f"Missing fields {missing} in contribution {contrib}"
