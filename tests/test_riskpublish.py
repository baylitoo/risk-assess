"""Tests for riskpublish CLI and report writer."""

import json
from pathlib import Path

import pytest

from riskos.cli.riskpublish import main
from riskos.ids import stable_id
from riskos.report.writer import write_report
from riskos.schemas.artifacts import (
    FindingCategory,
    FindingStatus,
    Producer,
    RiskRegister,
)
from riskos.workflow.state import AssessmentWorkflow, Phase
from tests.conftest import make_finding


@pytest.fixture()
def assessment_id():
    return stable_id("assessment", "publish-test")


@pytest.fixture()
def register(assessment_id):
    api_id = stable_id("component", "payments-hub", "public-api")
    pii_id = stable_id("data_asset", "payments-hub", "customer-records")
    findings = [
        make_finding(
            FindingCategory.ABUSE_PREVENTION, [api_id],
            finding_id="fnd-001", band="critical",
            factors={
                "exposure": "internet_facing",
                "exploitability": "practical",
                "threat_activity": "high",
                "impact": "severe",
                "control_strength": "absent",
            },
        ),
        make_finding(
            FindingCategory.PRIVACY, [pii_id],
            finding_id="fnd-002", band="high",
        ),
    ]
    accepted_findings = [
        f.model_copy(update={"status": FindingStatus.ACCEPTED})
        for f in findings
    ]
    return RiskRegister(
        artifact_id=stable_id("artifact", assessment_id, "risk_register", "1"),
        assessment_id=assessment_id,
        phase="review",
        producer=Producer(agent="risk_synthesizer"),
        findings=accepted_findings,
    )


@pytest.fixture()
def review_workflow(assessment_id):
    wf = AssessmentWorkflow.start(assessment_id)
    wf.advance(actor="system")            # INTAKE -> SCOPING (needs approval)
    # advance past scoping with human approval
    wf.advance(actor="reviewer", human_approved=True)  # SCOPING -> EVIDENCE
    wf.advance(actor="system")            # EVIDENCE -> SYNTHESIS
    wf.advance(actor="system")            # SYNTHESIS -> CHALLENGE
    wf.advance(actor="system")            # CHALLENGE -> REVIEW
    assert wf.state.phase == Phase.REVIEW
    return wf


def _write_fixtures(tmp_path, register, workflow):
    register_path = tmp_path / "register.json"
    workflow_path = tmp_path / "workflow.json"
    register_path.write_text(register.model_dump_json(), encoding="utf-8")
    workflow_path.write_text(workflow.serialize(), encoding="utf-8")
    return register_path, workflow_path


class TestReportWriter:
    def test_report_contains_all_high_critical_findings(self, register):
        sections = write_report(register)
        assert "fnd-001" in sections.markdown
        assert "fnd-002" in sections.markdown

    def test_csv_has_all_findings(self, register):
        sections = write_report(register)
        assert "fnd-001" in sections.findings_csv
        assert "fnd-002" in sections.findings_csv

    def test_findings_sorted_by_band(self, register):
        sections = write_report(register)
        critical_pos = sections.markdown.index("fnd-001")
        high_pos = sections.markdown.index("fnd-002")
        assert critical_pos < high_pos

    def test_evidence_json_is_valid(self, register):
        sections = write_report(register)
        parsed = json.loads(sections.evidence_json)
        assert isinstance(parsed, list)


class TestRiskpublishCLI:
    def test_publish_creates_all_output_files(
        self, tmp_path, register, review_workflow
    ):
        register_path, workflow_path = _write_fixtures(
            tmp_path, register, review_workflow
        )
        out_dir = tmp_path / "output"

        code = main(
            [str(register_path), str(workflow_path), str(out_dir)]
        )

        assert code == 0
        assert (out_dir / "report.md").exists()
        assert (out_dir / "findings_table.csv").exists()
        assert (out_dir / "evidence_index.json").exists()

    def test_publish_advances_workflow_to_complete(
        self, tmp_path, register, review_workflow
    ):
        register_path, workflow_path = _write_fixtures(
            tmp_path, register, review_workflow
        )
        out_dir = tmp_path / "output"

        main([str(register_path), str(workflow_path), str(out_dir)])

        updated_wf = AssessmentWorkflow.resume(
            workflow_path.read_text(encoding="utf-8")
        )
        assert updated_wf.state.phase == Phase.COMPLETE

    def test_publish_blocked_without_review_phase(
        self, tmp_path, register, assessment_id, capsys
    ):
        wf = AssessmentWorkflow.start(assessment_id)
        # Only at INTAKE phase
        register_path, workflow_path = _write_fixtures(tmp_path, register, wf)
        out_dir = tmp_path / "output"

        code = main([str(register_path), str(workflow_path), str(out_dir)])

        assert code == 1
        err = json.loads(capsys.readouterr().err)
        assert "REVIEW" in err["error"]

    def test_publish_blocked_with_draft_high_findings(
        self, tmp_path, assessment_id, review_workflow
    ):
        # Register with DRAFT HIGH finding
        draft_finding = make_finding(
            FindingCategory.ABUSE_PREVENTION,
            [stable_id("component", "api")],
            finding_id="fnd-draft",
            band="critical",
        )
        register = RiskRegister(
            artifact_id=stable_id("artifact", assessment_id, "risk_register", "1"),
            assessment_id=assessment_id,
            phase="review",
            producer=Producer(agent="test"),
            findings=[draft_finding],
        )
        register_path, workflow_path = _write_fixtures(
            tmp_path, register, review_workflow
        )
        out_dir = tmp_path / "output"

        code = main([str(register_path), str(workflow_path), str(out_dir)])

        assert code == 1

    def test_report_contains_finding_titles(
        self, tmp_path, register, review_workflow, capsys
    ):
        register_path, workflow_path = _write_fixtures(
            tmp_path, register, review_workflow
        )
        out_dir = tmp_path / "output"
        main([str(register_path), str(workflow_path), str(out_dir)])

        report_content = (out_dir / "report.md").read_text(encoding="utf-8")
        assert "abuse_prevention" in report_content or "fnd-001" in report_content
