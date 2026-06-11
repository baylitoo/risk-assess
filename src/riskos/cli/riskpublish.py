"""riskpublish — publish a reviewed risk assessment to output files.

Requires human approval (WorkflowState.phase == REVIEW with human_approved=True).
Writes:
  <output_dir>/report.md         — structured Markdown narrative
  <output_dir>/findings_table.csv — sorted findings CSV
  <output_dir>/evidence_index.json — evidence provenance index
Advances workflow to COMPLETE.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from riskos.report.writer import write_report
from riskos.schemas.artifacts import FindingStatus, RiskRegister
from riskos.workflow.state import AssessmentWorkflow, Phase, WorkflowError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "register_json",
        type=Path,
        help="path to the RiskRegister JSON artifact",
    )
    parser.add_argument(
        "workflow_json",
        type=Path,
        help="path to the WorkflowState JSON file",
    )
    parser.add_argument(
        "output_dir",
        type=Path,
        help="directory to write report outputs",
    )
    parser.add_argument(
        "--actor",
        default="system",
        help="actor name recorded in the workflow transition",
    )
    parser.add_argument(
        "--title",
        default="Risk Assessment Report",
        help="title for the Markdown report",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        register = _load_register(args.register_json)
        workflow = _load_workflow(args.workflow_json)
    except (OSError, ValueError) as exc:
        _fail(f"failed to load inputs: {exc}")
        return 2

    # Gate: must be at REVIEW phase
    if workflow.state.phase != Phase.REVIEW:
        _fail(
            f"workflow must be at REVIEW phase to publish "
            f"(current: {workflow.state.phase.value})"
        )
        return 1

    # Gate: no HIGH/CRITICAL findings in DRAFT status
    draft_high = [
        f for f in register.findings
        if f.status == FindingStatus.DRAFT
        and f.band in ("high", "very_high", "critical")
    ]
    if draft_high:
        _fail(
            f"{len(draft_high)} HIGH/CRITICAL finding(s) are still in DRAFT status; "
            "review and accept/reject before publishing"
        )
        return 1

    # Render report
    sections = write_report(
        register=register,
        assessment_title=args.title,
    )

    # Write outputs
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(sections.markdown, encoding="utf-8")
    (out / "findings_table.csv").write_text(sections.findings_csv, encoding="utf-8")
    (out / "evidence_index.json").write_text(sections.evidence_json, encoding="utf-8")

    # Advance workflow REVIEW -> PUBLISH -> COMPLETE
    try:
        workflow.advance(actor=args.actor, human_approved=True)  # REVIEW -> PUBLISH
        new_state = workflow.advance(actor=args.actor)           # PUBLISH -> COMPLETE
    except WorkflowError as exc:
        _fail(f"workflow advance failed: {exc}")
        return 1

    # Write back updated workflow state
    args.workflow_json.write_text(workflow.serialize(), encoding="utf-8")

    result = {
        "published": True,
        "output_dir": str(out),
        "finding_count": len(register.findings),
        "workflow_phase": new_state.phase.value,
    }
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def _load_register(path: Path) -> RiskRegister:
    return RiskRegister.model_validate_json(path.read_text(encoding="utf-8"))


def _load_workflow(path: Path) -> AssessmentWorkflow:
    return AssessmentWorkflow.resume(path.read_text(encoding="utf-8"))


def _fail(message: str) -> None:
    json.dump({"error": message}, sys.stderr)
    sys.stderr.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
