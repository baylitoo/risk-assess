"""Tests for the threat_modeler agent."""

from riskos.gateway import FakeStructuredGenerationGateway, GenerationGatewayError
from riskos.ids import stable_id
from riskos.schemas.artifacts import (
    AssessmentDepth,
    AssessmentScope,
    DocumentCorpus,
    FindingCategory,
    FindingStatus,
    Producer,
)
from riskos.schemas.generation import ProposedFinding, ThreatGeneration, UnresolvedMention
from riskos.threat import extract_threats


def _scope(inventory):
    return AssessmentScope(
        artifact_id=stable_id("artifact", inventory.assessment_id, "scope", "1"),
        assessment_id=inventory.assessment_id,
        phase="scoping",
        producer=Producer(agent="test"),
        depth=AssessmentDepth.FULL,
    )


def _corpus(inventory):
    return DocumentCorpus(
        artifact_id=stable_id("artifact", inventory.assessment_id, "corpus", "1"),
        assessment_id=inventory.assessment_id,
        phase="ingestion",
        producer=Producer(agent="test"),
    )


def _proposed_finding(key, category, asset_keys):
    return ProposedFinding(
        key=key,
        name=f"Test finding {key}",
        category=category,
        scenario="Test scenario",
        source_chunk_ids=["chk-001"],
        confidence=0.9,
        affected_asset_keys=asset_keys,
        factors={
            "exposure": "internet_facing",
            "exploitability": "practical",
            "threat_activity": "high",
            "impact": "major",
            "control_strength": "absent",
        },
    )


def test_extract_threats_returns_register(inventory):
    gateway = FakeStructuredGenerationGateway()
    generation = ThreatGeneration(
        findings=[
            _proposed_finding("fnd-001", "abuse_prevention", ["payments-api"]),
        ]
    )
    gateway.set_response(ThreatGeneration, generation)
    scope = _scope(inventory)
    corpus = _corpus(inventory)
    producer = Producer(agent="threat_modeler", prompt_version="1")

    register = extract_threats(corpus, inventory, scope, gateway, producer)

    assert register.artifact_type == "risk_register"
    assert register.assessment_id == inventory.assessment_id
    assert len(register.findings) == 1
    assert register.findings[0].category == FindingCategory.ABUSE_PREVENTION


def test_findings_are_scored(inventory):
    gateway = FakeStructuredGenerationGateway()
    generation = ThreatGeneration(
        findings=[
            _proposed_finding("fnd-001", "abuse_prevention", ["public-api"]),
        ]
    )
    gateway.set_response(ThreatGeneration, generation)
    producer = Producer(agent="threat_modeler", prompt_version="1")
    scope = _scope(inventory)
    corpus = _corpus(inventory)

    register = extract_threats(corpus, inventory, scope, gateway, producer)

    f = register.findings[0]
    assert f.inherent_score is not None
    assert f.residual_score is not None
    assert f.band != ""


def test_gateway_failure_returns_empty_register(inventory):
    gateway = FakeStructuredGenerationGateway()  # no response configured
    producer = Producer(agent="threat_modeler", prompt_version="1")
    scope = _scope(inventory)
    corpus = _corpus(inventory)

    register = extract_threats(corpus, inventory, scope, gateway, producer)

    assert register.findings == []


def test_asset_keys_resolved_by_name(inventory):
    """Asset keys matching inventory component names are resolved to stable IDs."""
    api = inventory.components[0]
    gateway = FakeStructuredGenerationGateway()
    generation = ThreatGeneration(
        findings=[
            _proposed_finding("fnd-001", "abuse_prevention", [api.name]),
        ]
    )
    gateway.set_response(ThreatGeneration, generation)
    producer = Producer(agent="threat_modeler", prompt_version="1")
    scope = _scope(inventory)
    corpus = _corpus(inventory)

    register = extract_threats(corpus, inventory, scope, gateway, producer)

    assert api.id in register.findings[0].affected_asset_ids


def test_gateway_called_with_route(inventory):
    gateway = FakeStructuredGenerationGateway()
    generation = ThreatGeneration()
    gateway.set_response(ThreatGeneration, generation)
    producer = Producer(agent="threat_modeler", prompt_version="1")
    scope = _scope(inventory)
    corpus = _corpus(inventory)

    extract_threats(
        corpus, inventory, scope, gateway, producer, route="threat_modeler"
    )

    assert len(gateway.calls) == 1
    assert gateway.calls[0].route == "threat_modeler"


def test_findings_have_draft_status(inventory):
    gateway = FakeStructuredGenerationGateway()
    generation = ThreatGeneration(
        findings=[
            _proposed_finding("fnd-001", "privacy", ["customer-records"]),
        ]
    )
    gateway.set_response(ThreatGeneration, generation)
    producer = Producer(agent="threat_modeler", prompt_version="1")
    scope = _scope(inventory)
    corpus = _corpus(inventory)

    register = extract_threats(corpus, inventory, scope, gateway, producer)

    assert register.findings[0].status == FindingStatus.DRAFT
