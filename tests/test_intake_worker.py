"""Tests for the Phase 0 intake worker."""

from __future__ import annotations

import pytest

from riskos.gateway import FakeStructuredGenerationGateway
from riskos.ids import stable_id
from riskos.intake import (
    IntakeResult,
    IntakeWorker,
    IntakeWorkerConfig,
    InventoryGenerationError,
    ingest_directory,
)
from riskos.policy import PolicyEngine, PolicyError
from riskos.runtime import AgentHarness, ArtifactWorkspace, JsonlAuditLog
from riskos.schemas.generation import InventoryGeneration, ProposedSystem
from tests.conftest import REPO_ROOT


def _make_generation(chunk_id: str) -> InventoryGeneration:
    return InventoryGeneration(
        systems=[
            ProposedSystem(
                key="main-system",
                name="Main System",
                source_chunk_ids=[chunk_id],
                confidence=0.9,
            )
        ]
    )


@pytest.fixture()
def assessment_id() -> str:
    return stable_id("assessment", "intake-worker-test")


@pytest.fixture()
def corpus(tmp_path, assessment_id):
    (tmp_path / "sats.md").write_text(
        "# Architecture\n\nCore banking system with internal API.",
        encoding="utf-8",
    )
    return ingest_directory(tmp_path, assessment_id)


@pytest.fixture()
def harness(tmp_path, assessment_id):
    workspace = ArtifactWorkspace(tmp_path / "workspace", assessment_id)
    audit = JsonlAuditLog(tmp_path / "audit.jsonl")
    policy = PolicyEngine.load_dir(REPO_ROOT / "policies")
    return AgentHarness("intake_worker", policy, workspace, audit)


@pytest.fixture()
def gateway(corpus):
    gw = FakeStructuredGenerationGateway()
    gw.set_response(InventoryGeneration, _make_generation(corpus.chunks[0].chunk_id))
    return gw


def test_successful_run(corpus, gateway, harness):
    worker = IntakeWorker(gateway, harness)
    result = worker.run(corpus)

    assert result.extraction_artifact_id
    assert result.inventory_artifact_id
    assert result.completeness_artifact_id
    assert result.audit_event_count > 0


def test_successful_run_returns_intake_result_type(corpus, gateway, harness):
    worker = IntakeWorker(gateway, harness)
    result = worker.run(corpus)
    assert isinstance(result, IntakeResult)


def test_policy_denial(tmp_path, corpus, gateway, assessment_id):
    (tmp_path / "policies" / "intake_worker.yaml").parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "policies" / "intake_worker.yaml").write_text(
        "agent: intake_worker\ncannot:\n  - write:artifact.inventory_extraction\n",
        encoding="utf-8",
    )
    policy = PolicyEngine.load_dir(tmp_path / "policies")
    workspace = ArtifactWorkspace(tmp_path / "workspace", assessment_id)
    audit = JsonlAuditLog(tmp_path / "audit.jsonl")
    harness = AgentHarness("intake_worker", policy, workspace, audit)
    worker = IntakeWorker(gateway, harness)

    with pytest.raises(PolicyError, match="denied"):
        worker.run(corpus)


def test_invalid_generation_bad_chunks(corpus, harness):
    gw = FakeStructuredGenerationGateway()
    gw.set_response(
        InventoryGeneration,
        InventoryGeneration(
            systems=[
                ProposedSystem(
                    key="sys",
                    name="System",
                    source_chunk_ids=["chk-does-not-exist-000000"],
                    confidence=0.9,
                )
            ]
        ),
    )
    worker = IntakeWorker(gw, harness)

    with pytest.raises(InventoryGenerationError):
        worker.run(corpus)


def test_incomplete_inventory(tmp_path, harness):
    assessment_id = harness.workspace.assessment_id
    (tmp_path / "sats.md").write_text("# System\n\nA system.", encoding="utf-8")
    corpus = ingest_directory(tmp_path, assessment_id)

    gw = FakeStructuredGenerationGateway()
    gw.set_response(InventoryGeneration, InventoryGeneration())
    worker = IntakeWorker(gw, harness)

    result = worker.run(corpus)

    assert result.complete is False
    assert result.missing_requirements


def test_audit_events_logged(corpus, gateway, harness):
    worker = IntakeWorker(gateway, harness)
    worker.run(corpus)

    events = harness.audit_log.read_all()
    assert len(events) >= 3
