"""Tests for the LLM-backed challenge reviser."""

from riskos.gateway import FakeStructuredGenerationGateway
from riskos.ids import stable_id
from riskos.schemas.artifacts import (
    AssessmentDepth,
    AssessmentScope,
    FindingCategory,
    Producer,
    RiskFinding,
    RiskRegister,
)
from riskos.schemas.generation import ProposedFinding, ThreatGeneration
from riskos.scoring.scorer import RiskScorer
from riskos.threat.reviser import make_reviser
from riskos.workflow.challenge import run_challenge_loop
from tests.conftest import make_finding


def _register(inventory, findings=None):
    return RiskRegister(
        artifact_id=stable_id("artifact", inventory.assessment_id, "risk_register", "1"),
        assessment_id=inventory.assessment_id,
        phase="threat_modeling",
        producer=Producer(agent="test"),
        findings=findings or [],
    )


def _proposed(key, category, asset_keys):
    return ProposedFinding(
        key=key,
        name=f"Gap filler {key}",
        category=category,
        scenario="Scenario",
        source_chunk_ids=["chk-001"],
        confidence=0.8,
        affected_asset_keys=asset_keys,
        factors={
            "exposure": "internet_facing",
            "exploitability": "practical",
            "threat_activity": "high",
            "impact": "major",
            "control_strength": "absent",
        },
    )


def test_reviser_adds_gap_filling_findings(inventory):
    gateway = FakeStructuredGenerationGateway()
    api_name = inventory.components[0].name
    generation = ThreatGeneration(
        findings=[_proposed("gap-001", "abuse_prevention", [api_name])]
    )
    gateway.set_response(ThreatGeneration, generation)

    scorer = RiskScorer.load("config/risk_matrix.yaml")
    reviser = make_reviser(
        gateway, inventory.assessment_id, inventory, scorer
    )

    register = _register(inventory)
    from riskos.critic import CoverageGap
    gap = CoverageGap(
        rule_id="COV-001",
        description="internet-facing component needs abuse_prevention finding",
        entity_id=inventory.components[0].id,
        expected_categories=frozenset({FindingCategory.ABUSE_PREVENTION}),
    )

    revised = reviser(register, [gap], iteration=1)

    assert revised.version == register.version + 1
    assert len(revised.findings) == 1
    assert revised.findings[0].category == FindingCategory.ABUSE_PREVENTION


def test_reviser_increments_version_on_gateway_error(inventory):
    gateway = FakeStructuredGenerationGateway()  # no response configured
    scorer = RiskScorer.load("config/risk_matrix.yaml")
    reviser = make_reviser(gateway, inventory.assessment_id, inventory, scorer)

    register = _register(inventory)
    revised = reviser(register, [], iteration=1)

    assert revised.version == register.version + 1
    assert revised.findings == []


def test_reviser_does_not_duplicate_existing_findings(inventory):
    gateway = FakeStructuredGenerationGateway()
    api_name = inventory.components[0].name
    generation = ThreatGeneration(
        findings=[_proposed("gap-001", "abuse_prevention", [api_name])]
    )
    gateway.set_response(ThreatGeneration, generation)

    scorer = RiskScorer.load("config/risk_matrix.yaml")
    reviser = make_reviser(gateway, inventory.assessment_id, inventory, scorer)

    existing = RiskFinding(
        finding_id=stable_id("finding", "gap-001"),
        title="existing",
        category=FindingCategory.ABUSE_PREVENTION,
        scenario="s",
        affected_asset_ids=[inventory.components[0].id],
    )
    register = _register(inventory, findings=[existing])
    from riskos.critic import CoverageGap
    gap = CoverageGap(
        rule_id="COV-001",
        description="internet-facing component needs abuse_prevention finding",
        entity_id=inventory.components[0].id,
        expected_categories=frozenset({FindingCategory.ABUSE_PREVENTION}),
    )

    revised = reviser(register, [gap], iteration=1)

    assert len(revised.findings) == 1  # not duplicated


def test_reviser_integrates_with_challenge_loop(inventory):
    """Full integration: challenge loop drives reviser to convergence."""
    gateway = FakeStructuredGenerationGateway()
    api = inventory.components[0]
    pii = inventory.data_assets[0]
    vendor = inventory.third_parties[0]
    admin = inventory.components[1]
    bot = inventory.components[2]

    generation = ThreatGeneration(
        findings=[
            _proposed("g-001", "abuse_prevention", [api.name]),
            _proposed("g-002", "privacy", [pii.name]),
            _proposed("g-003", "third_party", [vendor.name]),
            _proposed("g-004", "access_management", [admin.name]),
            _proposed("g-005", "genai", [bot.name]),
        ]
    )
    gateway.set_response(ThreatGeneration, generation)

    scorer = RiskScorer.load("config/risk_matrix.yaml")
    reviser = make_reviser(gateway, inventory.assessment_id, inventory, scorer)
    register = _register(inventory)

    result = run_challenge_loop(inventory, register, reviser, max_iterations=2)

    assert result.resolved is True
    assert result.iterations == 1
