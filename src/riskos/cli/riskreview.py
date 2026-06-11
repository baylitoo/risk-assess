"""riskreview — human review gate CLI for RiskRegister."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from riskos.schemas.artifacts import FindingStatus, RiskRegister
from riskos.workflow.state import AssessmentWorkflow, Phase, WorkflowState

_HIGH_CRITICAL = {"high", "critical"}
_BAND_ORDER = ["low", "medium", "high", "critical"]

_EDITABLE_FIELDS = {"title", "scenario", "band", "remediation"}


def _load_register(path: str) -> RiskRegister:
    return RiskRegister.model_validate_json(Path(path).read_text(encoding="utf-8"))


def _load_workflow(path: str) -> WorkflowState:
    return WorkflowState.model_validate_json(Path(path).read_text(encoding="utf-8"))


def _save(obj, path: str | None) -> None:
    if path:
        Path(path).write_text(obj.model_dump_json(indent=2), encoding="utf-8")
    else:
        print(obj.model_dump_json(indent=2))


def _band_sort_key(finding) -> int:
    return -_BAND_ORDER.index(finding.band) if finding.band in _BAND_ORDER else 0


def cmd_list(args) -> int:
    register = _load_register(args.register_json)
    findings = sorted(register.findings, key=_band_sort_key)
    rows = [f"{'ID':<24}  {'BAND':<10}  {'CATEGORY':<24}  {'STATUS':<14}  TITLE"]
    rows.append("-" * 100)
    for f in findings:
        title = f.title[:60] + "..." if len(f.title) > 60 else f.title
        rows.append(f"{f.finding_id:<24}  {f.band:<10}  {f.category.value:<24}  {f.status.value:<14}  {title}")
    print("\n".join(rows))
    return 0


def cmd_accept(args) -> int:
    register = _load_register(args.register_json)
    updated = []
    found = False
    for f in register.findings:
        if f.finding_id == args.finding_id:
            updated.append(f.model_copy(update={"status": FindingStatus.ACCEPTED}))
            found = True
        else:
            updated.append(f)
    if not found:
        json.dump({"error": f"finding {args.finding_id!r} not found"}, sys.stderr)
        return 2
    new_register = register.model_copy(update={"findings": updated})
    _save(new_register, getattr(args, "output", None))
    return 0


def cmd_reject(args) -> int:
    register = _load_register(args.register_json)
    updated = []
    found = False
    for f in register.findings:
        if f.finding_id == args.finding_id:
            new_scenario = f"{f.scenario}\n\n[REJECTED] {args.reason}"
            updated.append(f.model_copy(update={
                "status": FindingStatus.REJECTED,
                "scenario": new_scenario,
            }))
            found = True
        else:
            updated.append(f)
    if not found:
        json.dump({"error": f"finding {args.finding_id!r} not found"}, sys.stderr)
        return 2
    new_register = register.model_copy(update={"findings": updated})
    _save(new_register, getattr(args, "output", None))
    return 0


def cmd_edit(args) -> int:
    if args.field not in _EDITABLE_FIELDS:
        json.dump({"error": f"field {args.field!r} is not editable; allowed: {sorted(_EDITABLE_FIELDS)}"}, sys.stderr)
        return 2
    register = _load_register(args.register_json)
    updated = []
    found = False
    for f in register.findings:
        if f.finding_id == args.finding_id:
            updated.append(f.model_copy(update={
                args.field: args.value,
                "status": FindingStatus.EDITED,
            }))
            found = True
        else:
            updated.append(f)
    if not found:
        json.dump({"error": f"finding {args.finding_id!r} not found"}, sys.stderr)
        return 2
    new_register = register.model_copy(update={"findings": updated})
    _save(new_register, getattr(args, "output", None))
    return 0


def cmd_approve(args) -> int:
    register = _load_register(args.register_json)
    workflow = _load_workflow(args.workflow)

    # Block if any HIGH/CRITICAL finding is still DRAFT
    draft_criticals = [
        f for f in register.findings
        if f.band in _HIGH_CRITICAL and f.status == FindingStatus.DRAFT
    ]
    if draft_criticals:
        ids = [f.finding_id for f in draft_criticals]
        json.dump({"error": f"cannot approve: {len(ids)} HIGH/CRITICAL finding(s) still in DRAFT: {ids}"}, sys.stderr)
        return 1

    wf = AssessmentWorkflow(workflow)
    try:
        new_state = wf.advance(actor="reviewer", human_approved=True)
    except Exception as exc:
        json.dump({"error": str(exc)}, sys.stderr)
        return 2

    result = json.dumps({
        "register": json.loads(register.model_dump_json()),
        "workflow": json.loads(new_state.model_dump_json()),
    }, indent=2)

    out_reg = getattr(args, "output_register", None)
    out_wf = getattr(args, "output_workflow", None)
    if out_reg:
        Path(out_reg).write_text(register.model_dump_json(indent=2), encoding="utf-8")
    if out_wf:
        Path(out_wf).write_text(new_state.model_dump_json(indent=2), encoding="utf-8")
    if not out_reg and not out_wf:
        print(result)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="riskreview")
    sub = parser.add_subparsers(dest="command", required=True)

    ls = sub.add_parser("list")
    ls.add_argument("register_json")

    acc = sub.add_parser("accept")
    acc.add_argument("register_json")
    acc.add_argument("finding_id")
    acc.add_argument("--output")

    rej = sub.add_parser("reject")
    rej.add_argument("register_json")
    rej.add_argument("finding_id")
    rej.add_argument("--reason", required=True)
    rej.add_argument("--output")

    ed = sub.add_parser("edit")
    ed.add_argument("register_json")
    ed.add_argument("finding_id")
    ed.add_argument("--field", required=True)
    ed.add_argument("--value", required=True)
    ed.add_argument("--output")

    apv = sub.add_parser("approve")
    apv.add_argument("register_json")
    apv.add_argument("--workflow", required=True)
    apv.add_argument("--output-register")
    apv.add_argument("--output-workflow")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    dispatch = {
        "list": cmd_list,
        "accept": cmd_accept,
        "reject": cmd_reject,
        "edit": cmd_edit,
        "approve": cmd_approve,
    }
    handler = dispatch.get(args.command)
    if handler is None:
        json.dump({"error": f"unknown command: {args.command}"}, sys.stderr)
        return 2
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
