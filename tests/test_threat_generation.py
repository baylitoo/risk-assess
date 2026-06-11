"""Tests for ThreatGeneration schema and ProposedFinding contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from riskos.schemas.generation import ProposedFinding, ThreatGeneration

REPO_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE = REPO_ROOT / "evals" / "findings" / "dev" / "payments-hub-dev-001.json"

_VALID_FACTORS = {
    "exposure": "internet_facing",
    "exploitability": "practical",
    "threat_activity": "high",
    "impact": "major",
    "control_strength": "absent",
}


def _finding(**overrides) -> dict:
    base = {
        "key": "fnd-test",
        "name": "Test Finding",
        "category": "vulnerability",
        "scenario": "An attacker exploits a known CVE.",
        "source_chunk_ids": ["chk-001"],
        "factors": _VALID_FACTORS,
    }
    base.update(overrides)
    return base


def test_proposed_finding_valid():
    f = ProposedFinding(**_finding())
    assert f.category == "vulnerability"
    assert f.factors["exposure"] == "internet_facing"


def test_proposed_finding_invalid_category():
    with pytest.raises(ValueError, match="not a valid FindingCategory"):
        ProposedFinding(**_finding(category="nonexistent_cat"))


def test_proposed_finding_empty_scenario_rejected():
    with pytest.raises(ValidationError):
        ProposedFinding(**_finding(scenario=""))


def test_proposed_finding_extra_fields_rejected():
    with pytest.raises(ValidationError):
        ProposedFinding(**_finding(unexpected="boom"))


def test_threat_generation_valid():
    tg = ThreatGeneration(findings=[ProposedFinding(**_finding())])
    assert len(tg.findings) == 1
    assert tg.schema_version == "1"


def test_threat_generation_extra_fields_rejected():
    with pytest.raises(ValidationError):
        ThreatGeneration(findings=[], unexpected="boom")


def test_all_finding_categories_accepted():
    from riskos.schemas.artifacts import FindingCategory
    for cat in FindingCategory:
        f = ProposedFinding(**_finding(category=cat.value))
        assert f.category == cat.value


def test_golden_fixture_loads():
    raw = _FIXTURE.read_text(encoding="utf-8")
    tg = ThreatGeneration.model_validate_json(raw)
    assert len(tg.findings) >= 4


def test_golden_fixture_has_all_factor_keys():
    required = {"exposure", "exploitability", "threat_activity", "impact", "control_strength"}
    tg = ThreatGeneration.model_validate_json(_FIXTURE.read_text(encoding="utf-8"))
    for f in tg.findings:
        assert required.issubset(f.factors.keys()), f"Finding {f.key} missing factors"


def test_golden_fixture_covers_required_categories():
    tg = ThreatGeneration.model_validate_json(_FIXTURE.read_text(encoding="utf-8"))
    categories = {f.category for f in tg.findings}
    assert "abuse_prevention" in categories   # COV-001
    assert "privacy" in categories            # COV-002
    assert "third_party" in categories        # COV-003
    assert "genai" in categories              # COV-005
