"""Tests for ScopeWorker."""

from __future__ import annotations

from pathlib import Path

import pytest

from riskos.ids import stable_id
from riskos.policy import PolicyEngine
from riskos.runtime import AgentHarness, ArtifactWorkspace, JsonlAuditLog
from riskos.scoping import ScopeResult, ScopeWorker, ScopingError
from riskos.schemas.artifacts import (
    AssetInventory,
    IntakeAssessment,
    Producer,
)
from riskos.schemas.entities import Component, DataAsset, Exposure, System

REPO_ROOT = Path(__file__).resolve().parents[1]


def _producer(agent: str = "scope_engine") -> Producer:
    return Producer(agent=agent)


def _assessment_id() -> str:
    return stable_id("assessment", "scope-worker-test")


def _inventory(assessment_id: str, **extras) -> AssetInventory:
    return AssetInventory(
        artifact_id=stable_id("artifact", assessment_id, "inventory"),
        assessment_id=assessment_id,
        phase="intake",
        producer=_producer("intake_worker"),
        **extras,
    )


def _intake(assessment_id: str, complete: bool = True) -> IntakeAssessment:
    return IntakeAssessment(
        artifact_id=stable_id("artifact", assessment_id, "intake"),
        assessment_id=assessment_id,
        phase="intake",
        producer=_producer("intake_worker"),
        complete=complete,
    )


@pytest.fixture()
def assessment_id():
    return _assessment_id()


@pytest.fixture()
def harness(tmp_path, assessment_id):
    workspace = ArtifactWorkspace(tmp_path / "workspace", assessment_id)
    audit = JsonlAuditLog(tmp_path / "audit.jsonl")
    policy = PolicyEngine.load_dir(REPO_ROOT / "policies")
    return AgentHarness("scope_engine", policy, workspace, audit)


def test_scope_worker_complete_intake(harness, assessment_id):
    inventory = _inventory(assessment_id)
    intake = _intake(assessment_id)
    worker = ScopeWorker(harness)
    result = worker.run(inventory, intake)
    assert isinstance(result, ScopeResult)
    assert result.scope_artifact_id
    assert result.audit_event_count > 0


def test_scope_worker_incomplete_intake(harness, assessment_id):
    inventory = _inventory(assessment_id)
    intake = _intake(assessment_id, complete=False)
    worker = ScopeWorker(harness)
    with pytest.raises(ScopingError):
        worker.run(inventory, intake)


def test_scope_worker_dora_always_in_modules(harness, assessment_id):
    inventory = _inventory(assessment_id)
    intake = _intake(assessment_id)
    result = ScopeWorker(harness).run(inventory, intake)
    assert "dora" in result.modules


def test_scope_worker_genai_module_conditional(tmp_path, assessment_id):
    comp = Component(
        id=stable_id("component", assessment_id, "fraud-model"),
        name="Fraud Model",
        system_id=stable_id("system", assessment_id, "core"),
        is_genai=True,
    )
    inventory = _inventory(assessment_id, components=[comp])
    intake = _intake(assessment_id)
    workspace = ArtifactWorkspace(tmp_path / "ws2", assessment_id)
    audit = JsonlAuditLog(tmp_path / "audit2.jsonl")
    policy = PolicyEngine.load_dir(REPO_ROOT / "policies")
    harness = AgentHarness("scope_engine", policy, workspace, audit)
    result = ScopeWorker(harness).run(inventory, intake)
    assert "genai" in result.modules


def test_scope_worker_artifact_persisted(harness, assessment_id, tmp_path):
    inventory = _inventory(assessment_id)
    intake = _intake(assessment_id)
    result = ScopeWorker(harness).run(inventory, intake)
    workspace = ArtifactWorkspace(tmp_path / "workspace", assessment_id)
    # Artifact was persisted — read it back (raises on missing)
    from riskos.schemas.artifacts import AssessmentScope
    scope = workspace.read("assessment_scope", result.scope_artifact_id, AssessmentScope)
    assert scope is not None
