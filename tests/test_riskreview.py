"""Tests for riskreview CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from riskos.cli.riskreview import main
from riskos.ids import stable_id
from riskos.schemas.artifacts import (
    FindingCategory,
    FindingStatus,
    Producer,
    RiskFinding,
    RiskRegister,
)
from riskos.workflow.state import Phase, WorkflowState


def _producer() -> Producer:
    return Producer(agent="test")


def _finding(idx: int, band: str, status: FindingStatus = FindingStatus.DRAFT) -> RiskFinding:
    return RiskFinding(
        finding_id=stable_id("finding", f"test-{idx}"),
        title=f"Finding {idx}: some risk title here",
        category=FindingCategory.VULNERABILITY,
        scenario="An attacker exploits something.",
        band=band,
        status=status,
        factors={},
    )


def _register(findings: list[RiskFinding], tmp_path: Path) -> Path:
    assessment_id = stable_id("assessment", "review-test")
    reg = RiskRegister(
        artifact_id=stable_id("artifact", "register-test"),
        assessment_id=assessment_id,
        phase="synthesis",
        producer=_producer(),
        findings=findings,
    )
    p = tmp_path / "register.json"
    p.write_text(reg.model_dump_json(indent=2), encoding="utf-8")
    return p


def _workflow(phase: Phase, tmp_path: Path, human_approved: bool = False) -> Path:
    from riskos.workflow.state import AssessmentWorkflow, Transition
    assessment_id = stable_id("assessment", "review-test")
    state = WorkflowState(assessment_id=assessment_id, phase=phase)
    p = tmp_path / "workflow.json"
    p.write_text(state.model_dump_json(indent=2), encoding="utf-8")
    return p


@pytest.fixture()
def findings():
    return [
        _finding(1, "critical", FindingStatus.DRAFT),
        _finding(2, "high", FindingStatus.DRAFT),
        _finding(3, "low", FindingStatus.DRAFT),
    ]


@pytest.fixture()
def register_path(findings, tmp_path):
    return _register(findings, tmp_path)


def test_list_outputs_all_findings(register_path, capsys):
    main(["list", str(register_path)])
    out = capsys.readouterr().out
    assert "Finding 1" in out
    assert "Finding 2" in out
    assert "Finding 3" in out


def test_accept_sets_status(register_path, findings, tmp_path, capsys):
    fid = findings[0].finding_id
    out_path = tmp_path / "out.json"
    code = main(["accept", str(register_path), fid, "--output", str(out_path)])
    assert code == 0
    result = RiskRegister.model_validate_json(out_path.read_text(encoding="utf-8"))
    updated = next(f for f in result.findings if f.finding_id == fid)
    assert updated.status == FindingStatus.ACCEPTED


def test_reject_sets_status(register_path, findings, tmp_path):
    fid = findings[1].finding_id
    out_path = tmp_path / "out.json"
    code = main(["reject", str(register_path), fid, "--reason", "Not applicable", "--output", str(out_path)])
    assert code == 0
    result = RiskRegister.model_validate_json(out_path.read_text(encoding="utf-8"))
    updated = next(f for f in result.findings if f.finding_id == fid)
    assert updated.status == FindingStatus.REJECTED


def test_edit_sets_edited_status(register_path, findings, tmp_path):
    fid = findings[2].finding_id
    out_path = tmp_path / "out.json"
    code = main(["edit", str(register_path), fid, "--field", "title", "--value", "New Title", "--output", str(out_path)])
    assert code == 0
    result = RiskRegister.model_validate_json(out_path.read_text(encoding="utf-8"))
    updated = next(f for f in result.findings if f.finding_id == fid)
    assert updated.title == "New Title"
    assert updated.status == FindingStatus.EDITED


def test_edit_rejects_unknown_field(register_path, findings):
    fid = findings[0].finding_id
    code = main(["edit", str(register_path), fid, "--field", "artifact_id", "--value", "boom"])
    assert code == 2


def test_approve_blocked_by_draft_critical(register_path, tmp_path):
    wf_path = _workflow(Phase.REVIEW, tmp_path)
    code = main(["approve", str(register_path), "--workflow", str(wf_path)])
    assert code == 1


def test_approve_succeeds_when_no_draft_criticals(tmp_path):
    findings = [
        _finding(1, "critical", FindingStatus.ACCEPTED),
        _finding(2, "high", FindingStatus.ACCEPTED),
        _finding(3, "low", FindingStatus.DRAFT),
    ]
    reg_path = _register(findings, tmp_path)
    wf_path = _workflow(Phase.REVIEW, tmp_path)
    code = main(["approve", str(reg_path), "--workflow", str(wf_path)])
    assert code == 0
