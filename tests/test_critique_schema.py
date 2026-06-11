"""Tests for Critique artifact schema and CritiqueGeneration contract."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from riskos.ids import stable_id
from riskos.policy.engine import PolicyEngine
from riskos.schemas.artifacts import (
    Critique,
    CritiqueIssueType,
    CritiqueItem,
    CritiqueVerdict,
    Producer,
)
from riskos.schemas.generation import CritiqueGeneration, ProposedCritiqueItem

REPO_ROOT = Path(__file__).resolve().parents[1]
_POLICIES_DIR = REPO_ROOT / "policies"


def _producer() -> Producer:
    return Producer(agent="critic")


def _critique(**overrides) -> Critique:
    base = dict(
        artifact_id=stable_id("artifact", "critique-test"),
        assessment_id="asm-test",
        phase="challenge",
        producer=_producer(),
        target_register_id="reg-001",
    )
    base.update(overrides)
    return Critique(**base)


def test_critique_artifact_validates():
    c = _critique()
    assert c.artifact_type == "critique"
    assert c.overall_verdict == CritiqueVerdict.PASS
    assert c.items == []


def test_critique_with_items():
    item = CritiqueItem(
        target_finding_id="fnd-001",
        issue_type=CritiqueIssueType.FALSE_SAFE,
        description="Finding severity is understated.",
        suggested_action="Upgrade band to CRITICAL.",
    )
    c = _critique(items=[item])
    assert len(c.items) == 1
    assert c.items[0].issue_type == CritiqueIssueType.FALSE_SAFE


def test_critique_item_invalid_issue_type():
    with pytest.raises(ValidationError):
        CritiqueItem(
            target_finding_id="fnd-001",
            issue_type="nonexistent_type",
            description="Bad type.",
        )


def test_critique_requires_revision_verdict():
    c = _critique(overall_verdict=CritiqueVerdict.REQUIRES_REVISION)
    assert c.overall_verdict == "requires_revision"


def test_critique_generation_validates():
    item = ProposedCritiqueItem(
        target_finding_id="fnd-001",
        issue_type="false_safe",
        description="This finding is underscored.",
    )
    cg = CritiqueGeneration(items=[item], verdict="requires_revision")
    assert cg.schema_version == "1"
    assert len(cg.items) == 1


def test_critique_generation_empty_items():
    cg = CritiqueGeneration(items=[], verdict="pass")
    assert cg.items == []


def test_critic_policy_allows_write_critique():
    engine = PolicyEngine.load_dir(_POLICIES_DIR)
    decision = engine.check("critic", "write", "artifact.critique")
    assert decision.allowed


def test_critic_policy_denies_write_register():
    engine = PolicyEngine.load_dir(_POLICIES_DIR)
    decision = engine.check("critic", "write", "artifact.risk_register")
    assert not decision.allowed
