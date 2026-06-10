"""Run inventory extraction evaluations against a golden corpus."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from riskos.evals.inventory import (
    InventoryCorpusError,
    InventoryEvalThresholds,
    InventorySplit,
    evaluate_inventory_corpus,
    load_inventory_corpus,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus_dir", type=Path)
    parser.add_argument(
        "--split",
        choices=[s.value for s in InventorySplit],
        default=InventorySplit.REGRESSION.value,
    )
    parser.add_argument("--thresholds", type=Path)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = evaluate_inventory_corpus(
            load_inventory_corpus(args.corpus_dir),
            split=InventorySplit(args.split),
            thresholds=_load_thresholds(args.thresholds),
        )
    except (InventoryCorpusError, OSError, ValueError, yaml.YAMLError) as exc:
        json.dump({"error": str(exc)}, sys.stderr)
        sys.stderr.write("\n")
        return 2

    payload = report.model_dump_json(indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    sys.stdout.write(payload + "\n")
    return 0 if report.passed else 1


def _load_thresholds(path: Path | None) -> InventoryEvalThresholds:
    if path is None:
        return InventoryEvalThresholds()
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return InventoryEvalThresholds.model_validate(data)


if __name__ == "__main__":
    raise SystemExit(main())
