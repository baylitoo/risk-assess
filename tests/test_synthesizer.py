"""Tests for the synthesis phase: synthesize_register and SynthesisWorker."""

from __future__ import annotations

import pytest

from riskos.gateway import FakeStructuredGenerationGateway
from riskos.ids import stable_id
from riskos.policy import PolicyEngine
from riskos.runtime import AgentHarness, ArtifactWorkspace, JsonlAuditLog
from riskos.schemas.artifacts import (
    AssetInventory,
    AssessmentScope,
    AssessmentDepth,
    FindingCategory,
    Producer,
    RiskRegister,
    VulnerabilityFindings,
)
from riskos.schemas.generation import ThreatGeneration
from riskos.scoring.scorer import RiskScorer
from riskos.synthesis import SynthesisConfig, SynthesisResult, SynthesisWorker, synthesize_register
from tests.conftest import REPO_ROOT, make_finding


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def assessment_id() -> str:
    return stable_id("assessment", "synthesis-test")


@pytest.fixture()
def synth_producer() -> Producer:
    return Producer(agent="risk_synthesizer", prompt_version="1")


@pytest.fixture()
def scope(assessment_id, synth_producer) -> AssessmentScope:
    return AssessmentScope(
        artifact_id=stable_id("artifact", assessment_id, "scope"),
        assessment_id=assessment_id,
        phase="scoping",
        producer=synth_producer,
        depth=AssessmentDepth.FULL,
        scheduled_agents=["risk_synthesizer"],
    )


@pytest.fixture()
def threat_register(inventory, assessment_id, synth_producer) -> RiskRegister:
    """A minimal threat register with one threat finding."""
    api_id = inventory.components[0].id
    finding = make_finding(FindingCategory.ABUSE_PREVENTION, [api_id])
    return RiskRegister(
        artifact_id=stable_id("artifact", assessment_id, "threat-register"),
        assessment_id=assessment_id,
        phase="threat-modeling",
        producer=synth_producer,
        findings=[finding],
    )


@pytest.fixture()
def scorer() -> RiskScorer:
    return RiskScorer.load(REPO_ROOT / "config" / "risk_matrix.yaml")


@pytest.fixture()
def gateway() -> FakeStructuredGenerationGateway:
    gw = FakeStructuredGenerationGateway()
    # Configure an empty ThreatGeneration so the reviser stub can return
    gw.set_response(ThreatGeneration, ThreatGeneration())
    return gw


@pytest.fixture()
def harness(tmp_path, assessment_id):
    workspace = ArtifactWorkspace(tmp_path / "workspace", assessment_id)
    audit = JsonlAuditLog(tmp_path / "audit.jsonl")
    policy = PolicyEngine.load_dir(REPO_ROOT / "policies")
    return AgentHarness("risk_synthesizer", policy, workspace, audit)


# ---------------------------------------------------------------------------
# synthesize_register tests
# ---------------------------------------------------------------------------

def test_synthesize_merges_findings(inventory, threat_register, scope, gateway, scorer, synth_producer):
    """Threat and vuln findings both appear in output register."""
    admin_id = inventory.components[1].id
    vuln_finding = make_finding(
        FindingCategory.ACCESS_MANAGEMENT,
        [admin_id],
        finding_id=stable_id("finding", "vuln-access-management", admin_id),
    )
    vuln_findings = VulnerabilityFindings(
        artifact_id=stable_id("artifact", threat_register.assessment_id, "vulns"),
        assessment_id=threat_register.assessment_id,
        phase="evidence",
        producer=synth_producer,
        findings=[vuln_finding],
    )

    final_register, challenge_result = synthesize_register(
        inventory=inventory,
        threat_register=threat_register,
        vuln_findings=vuln_findings,
        scope=scope,
        gateway=gateway,
        scorer=scorer,
        producer=synth_producer,
    )

    finding_ids = {f.finding_id for f in final_register.findings}
    assert threat_register.findings[0].finding_id in finding_ids
    assert vuln_finding.finding_id in finding_ids


def test_synthesize_deduplicates(inventory, threat_register, scope, gateway, scorer, synth_producer):
    """Same finding_id in both threat and vuln findings appears only once."""
    # Use the same finding_id as the threat register's finding
    duplicate_id = threat_register.findings[0].finding_id
    api_id = inventory.components[0].id
    duplicate_finding = make_finding(
        FindingCategory.ABUSE_PREVENTION,
        [api_id],
        finding_id=duplicate_id,
    )
    vuln_findings = VulnerabilityFindings(
        artifact_id=stable_id("artifact", threat_register.assessment_id, "vulns-dup"),
        assessment_id=threat_register.assessment_id,
        phase="evidence",
        producer=synth_producer,
        findings=[duplicate_finding],
    )

    final_register, _ = synthesize_register(
        inventory=inventory,
        threat_register=threat_register,
        vuln_findings=vuln_findings,
        scope=scope,
        gateway=gateway,
        scorer=scorer,
        producer=synth_producer,
    )

    matching = [f for f in final_register.findings if f.finding_id == duplicate_id]
    assert len(matching) == 1


def test_synthesize_no_vuln_findings(inventory, threat_register, scope, gateway, scorer, synth_producer):
    """Works correctly when vuln_findings is None."""
    final_register, challenge_result = synthesize_register(
        inventory=inventory,
        threat_register=threat_register,
        vuln_findings=None,
        scope=scope,
        gateway=gateway,
        scorer=scorer,
        producer=synth_producer,
    )

    assert isinstance(final_register, RiskRegister)
    assert len(final_register.findings) >= 1


# ---------------------------------------------------------------------------
# SynthesisWorker tests
# ---------------------------------------------------------------------------

def test_synthesis_worker_persists_artifact(inventory, threat_register, scope, gateway, harness, tmp_path):
    """The final RiskRegister artifact exists in the workspace after run."""
    config = SynthesisConfig(
        risk_matrix_path=str(REPO_ROOT / "config" / "risk_matrix.yaml"),
        max_challenge_iterations=1,
    )
    worker = SynthesisWorker(gateway, harness, config)
    result = worker.run(inventory, threat_register, None, scope)

    # Artifact should be loadable from the workspace
    loaded = harness.workspace.read(
        "risk_register", result.register_artifact_id, RiskRegister
    )
    assert loaded.artifact_id == result.register_artifact_id


def test_synthesis_worker_reports_gaps(inventory, threat_register, scope, gateway, harness):
    """If coverage gaps remain, coverage_resolved is False and remaining_gap_count > 0."""
    # The inventory has components requiring GENAI, ACCESS_MANAGEMENT (admin), PRIVACY (PII),
    # THIRD_PARTY findings.  The threat register only covers ABUSE_PREVENTION on api.
    # The gateway returns empty ThreatGeneration, so gaps will remain.
    config = SynthesisConfig(
        risk_matrix_path=str(REPO_ROOT / "config" / "risk_matrix.yaml"),
        max_challenge_iterations=2,
    )
    worker = SynthesisWorker(gateway, harness, config)
    result = worker.run(inventory, threat_register, None, scope)

    assert result.coverage_resolved is False
    assert result.remaining_gap_count > 0


def test_synthesis_worker_returns_result(inventory, threat_register, scope, gateway, harness):
    """SynthesisResult fields are all populated."""
    config = SynthesisConfig(
        risk_matrix_path=str(REPO_ROOT / "config" / "risk_matrix.yaml"),
        max_challenge_iterations=2,
    )
    worker = SynthesisWorker(gateway, harness, config)
    result = worker.run(inventory, threat_register, None, scope)

    assert isinstance(result, SynthesisResult)
    assert result.register_artifact_id
    assert isinstance(result.challenge_iterations, int)
    assert isinstance(result.coverage_resolved, bool)
    assert isinstance(result.remaining_gap_count, int)
    assert result.audit_event_count > 0
