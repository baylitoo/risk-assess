"""Run Phase 0 intake on a document corpus artifact."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from riskos.evals.inventory import (
    InventoryCorpusError,
    InventoryEvalThresholds,
    InventorySplit,
    evaluate_inventory_corpus,
    load_inventory_corpus,
)
from riskos.intake import IntakeWorker, IntakeWorkerConfig
from riskos.policy import PolicyError
from riskos.policy.engine import PolicyEngine
from riskos.runtime.harness import AgentHarness, JsonlAuditLog
from riskos.runtime.workspace import ArtifactWorkspace
from riskos.schemas.artifacts import DocumentCorpus

if TYPE_CHECKING:
    from riskos.gateway import StructuredGenerationGateway


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus_json", type=Path)
    parser.add_argument("--workspace-dir", type=Path, required=True)
    parser.add_argument("--audit-log", type=Path, required=True)
    parser.add_argument("--policies-dir", type=Path, default=Path("policies"))
    parser.add_argument("--route", default="inventory-extraction")
    parser.add_argument("--prompt-version", default="1")
    parser.add_argument("--minimum-confidence", type=float, default=0.0)
    parser.add_argument("--eval-corpus", type=Path)
    parser.add_argument("--eval-split", default=InventorySplit.REGRESSION.value,
                        choices=[s.value for s in InventorySplit])
    parser.add_argument("--output", type=Path)
    return parser


def _load_gateway(gateway: StructuredGenerationGateway | None) -> StructuredGenerationGateway:
    if gateway is not None:
        return gateway
    proxy_url = os.environ.get("RISKOS_PROXY_URL")
    if proxy_url:
        from riskos.adapters.gateway import LiteLLMProxyConfig, LiteLLMProxyGateway
        return LiteLLMProxyGateway(LiteLLMProxyConfig.from_env())
    from riskos.gateway import FakeStructuredGenerationGateway
    gw = FakeStructuredGenerationGateway()
    return gw


def main(argv: list[str] | None = None, gateway: StructuredGenerationGateway | None = None) -> int:
    args = build_parser().parse_args(argv)

    # Load corpus
    try:
        corpus_text = args.corpus_json.read_text(encoding="utf-8")
        corpus = DocumentCorpus.model_validate_json(corpus_text)
    except (OSError, ValueError) as exc:
        json.dump({"status": "error", "message": str(exc)}, sys.stderr)
        sys.stderr.write("\n")
        return 2

    # Build harness
    try:
        policy = PolicyEngine.load_dir(args.policies_dir)
        workspace = ArtifactWorkspace(args.workspace_dir, corpus.assessment_id)
        audit_log = JsonlAuditLog(args.audit_log)
        harness = AgentHarness("intake_worker", policy, workspace, audit_log)
    except (OSError, ValueError, PolicyError) as exc:
        json.dump({"status": "error", "message": str(exc)}, sys.stderr)
        sys.stderr.write("\n")
        return 2

    config = IntakeWorkerConfig(
        route=args.route,
        prompt_version=args.prompt_version,
        minimum_confidence=args.minimum_confidence,
    )

    try:
        gw = _load_gateway(gateway)
        result = IntakeWorker(gw, harness, config).run(corpus)
    except PolicyError as exc:
        json.dump({"status": "error", "message": str(exc)}, sys.stderr)
        sys.stderr.write("\n")
        return 2
    except Exception as exc:
        json.dump({"status": "error", "message": str(exc)}, sys.stderr)
        sys.stderr.write("\n")
        return 2

    payload: dict = {
        "status": "ok" if result.complete else "incomplete",
        "complete": result.complete,
        "extraction_artifact_id": result.extraction_artifact_id,
        "inventory_artifact_id": result.inventory_artifact_id,
        "completeness_artifact_id": result.completeness_artifact_id,
        "audit_event_count": result.audit_event_count,
    }
    if not result.complete:
        payload["missing_requirements"] = result.missing_requirements

    exit_code = 0 if result.complete else 1

    # Optional eval corpus check
    if args.eval_corpus:
        try:
            cases = load_inventory_corpus(args.eval_corpus)
            split = InventorySplit(args.eval_split)
            scoreable = [c for c in cases if c.split == split and c.produced_inventory is not None]
            if scoreable:
                report = evaluate_inventory_corpus(scoreable, split=split,
                                                   thresholds=InventoryEvalThresholds())
                payload["eval"] = {
                    "aggregate_recall": report.aggregate_recall,
                    "aggregate_precision": report.aggregate_precision,
                    "aggregate_f1": report.aggregate_f1,
                    "passed": report.passed,
                    "violations": report.violations,
                }
                if not report.passed:
                    exit_code = 1
            else:
                payload["eval"] = {"message": f"no scoreable cases for split {args.eval_split!r}"}
        except (InventoryCorpusError, OSError, ValueError) as exc:
            json.dump({"status": "error", "message": str(exc)}, sys.stderr)
            sys.stderr.write("\n")
            return 2

    out = json.dumps(payload, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(out + "\n", encoding="utf-8")
    sys.stdout.write(out + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
