"""Tests for the synthesis eval harness."""

import pytest

from riskos.evals.findings import FindingEvalCase, FindingEvalThresholds
from riskos.evals.synthesis import (
    SynthesisCorpusEvalReport,
    SynthesisEvalCase,
    SynthesisEvalResult,
    evaluate_synthesis,
    evaluate_synthesis_corpus,
)
from riskos.gateway import FakeStructuredGenerationGateway
from riskos.ids import stable_id
from riskos.schemas.artifacts import (
    AssessmentDepth,
    AssessmentScope,
    FindingCategory,
    FindingStatus,
    Producer,
    RiskFinding,
    RiskRegister,
)
from riskos.schemas.generation import ProposedFinding, ThreatGeneration
from tests.conftest import make_finding


def _scope(inventory):
    return AssessmentScope(
        artifact_id=stable_id("artifact", inventory.assessment_id, "scope", "1"),
        assessment_id=inventory.assessment_id,
        phase="scoping",
        producer=Producer(agent="test"),
        depth=AssessmentDepth.FULL,
    )


def _empty_register(inventory):
    return RiskRegister(
        artifact_id=stable_id("artifact", inventory.assessment_id, "rr", "1"),
        assessment_id=inventory.assessment_id,
        phase="synthesis",
        producer=Producer(agent="test"),
        findings=[],
    )


def _proposed(key, category, asset_keys):
    return ProposedFinding(
        key=key,
        name=f"Finding {key}",
        category=category,
        scenario="Scenario",
        source_chunk_ids=["chk-001"],
        confidence=0.85,
        affected_asset_keys=asset_keys,
        factors={
            "exposure": "internet_facing",
            "exploitability": "practical",
            "threat_activity": "high",
            "impact": "major",
            "control_strength": "absent",
        },
    )


def _golden_eval_case(inventory, split="regression"):
    # Synthesizer resolves all asset keys via stable_id("component", name).
    # Use matching IDs in golden findings so coverage can be evaluated.
    api_id = stable_id("component", inventory.components[0].name)
    pii_id = stable_id("component", inventory.data_assets[0].name)
    return FindingEvalCase(
        case_id="synth-test-001",
        split=split,
        golden_findings=[
            make_finding(FindingCategory.ABUSE_PREVENTION, [api_id],
                         finding_id="g1", band="high"),
            make_finding(FindingCategory.PRIVACY, [pii_id],
                         finding_id="g2", band="high"),
        ],
    )


def test_evaluate_synthesis_no_gaps(inventory):
    """When gateway provides all required findings, false_safe_rate=0."""
    api = inventory.components[0]
    pii = inventory.data_assets[0]
    vendor = inventory.third_parties[0]
    admin = inventory.components[1]
    bot = inventory.components[2]

    gateway = FakeStructuredGenerationGateway()
    generation = ThreatGeneration(
        findings=[
            _proposed("s-001", "abuse_prevention", [api.name]),
            _proposed("s-002", "privacy", [pii.name]),
            _proposed("s-003", "third_party", [vendor.name]),
            _proposed("s-004", "access_management", [admin.name]),
            _proposed("s-005", "genai", [bot.name]),
        ]
    )
    gateway.set_response(ThreatGeneration, generation)

    golden_case = _golden_eval_case(inventory)
    register = _empty_register(inventory)
    scope = _scope(inventory)

    result = evaluate_synthesis(
        inventory=inventory,
        threat_register=register,
        scope=scope,
        gateway=gateway,
        golden_findings_eval_case=golden_case,
    )

    assert result.false_safe_rate == 0.0
    assert result.produced_finding_count == 5


def test_evaluate_synthesis_misses_findings(inventory):
    """Empty gateway produces high false_safe_rate."""
    gateway = FakeStructuredGenerationGateway()  # no response = empty generation
    golden_case = _golden_eval_case(inventory)
    register = _empty_register(inventory)
    scope = _scope(inventory)

    result = evaluate_synthesis(
        inventory=inventory,
        threat_register=register,
        scope=scope,
        gateway=gateway,
        golden_findings_eval_case=golden_case,
        max_challenge_iterations=1,
    )

    assert result.false_safe_rate == 1.0
    assert result.produced_finding_count == 0
    assert result.coverage_resolved is False


def test_evaluate_synthesis_with_seeded_register(inventory):
    """Seeding the threat register pre-covers some findings."""
    api = inventory.components[0]
    seeded_finding = make_finding(
        FindingCategory.ABUSE_PREVENTION,
        [api.id],
        finding_id="g1",
        band="high",
        factors={
            "exposure": "internet_facing",
            "exploitability": "practical",
            "threat_activity": "high",
            "impact": "major",
            "control_strength": "absent",
        },
    )
    register = RiskRegister(
        artifact_id=stable_id("artifact", inventory.assessment_id, "rr", "1"),
        assessment_id=inventory.assessment_id,
        phase="synthesis",
        producer=Producer(agent="test"),
        findings=[seeded_finding],
    )
    gateway = FakeStructuredGenerationGateway()
    golden_case = _golden_eval_case(inventory)
    scope = _scope(inventory)

    result = evaluate_synthesis(
        inventory=inventory,
        threat_register=register,
        scope=scope,
        gateway=gateway,
        golden_findings_eval_case=golden_case,
        max_challenge_iterations=1,
    )

    # abuse_prevention covered by seeded; privacy missed
    assert result.produced_finding_count == 1


def test_evaluate_synthesis_corpus_aggregate():
    """Aggregate report averages over multiple eval results."""
    cases = [
        SynthesisEvalResult(
            case_id="c1", split="regression",
            false_safe_rate=0.0, band_agreement=1.0,
            challenge_convergence_rate=1.0,
            challenge_iterations=1, coverage_resolved=True,
            produced_finding_count=5, golden_finding_count=5,
        ),
        SynthesisEvalResult(
            case_id="c2", split="regression",
            false_safe_rate=0.1, band_agreement=0.8,
            challenge_convergence_rate=1.0,
            challenge_iterations=2, coverage_resolved=True,
            produced_finding_count=4, golden_finding_count=5,
        ),
    ]
    report = evaluate_synthesis_corpus(cases, split="regression")

    assert report.case_count == 2
    assert report.false_safe_rate == pytest.approx(0.05)
    assert report.challenge_convergence_rate == 1.0


def test_evaluate_synthesis_corpus_quality_gate_fail():
    cases = [
        SynthesisEvalResult(
            case_id="c1", split="regression",
            false_safe_rate=0.2, band_agreement=0.5,
            challenge_convergence_rate=0.5,
            challenge_iterations=2, coverage_resolved=False,
            produced_finding_count=3, golden_finding_count=5,
        ),
    ]
    thresholds = FindingEvalThresholds(
        max_false_safe_rate=0.05,
        min_coverage_pass_rate=0.9,
    )
    report = evaluate_synthesis_corpus(cases, split="regression", thresholds=thresholds)

    assert report.passed is False
    assert len(report.violations) >= 1
