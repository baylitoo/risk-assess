"""Validate structured inventory generation and materialize an AssetInventory."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from riskos.intake import (
    InventoryGenerationError,
    create_inventory_extraction,
    load_inventory_generation,
    materialize_inventory,
)
from riskos.schemas.artifacts import DocumentCorpus, Producer
from riskos.schemas.generation import InventoryGeneration


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path, nargs="?")
    parser.add_argument("generation", type=Path, nargs="?")
    parser.add_argument("--schema", action="store_true")
    parser.add_argument("--model-id", default="")
    parser.add_argument("--prompt-version", default="")
    parser.add_argument("--minimum-confidence", type=float, default=0.0)
    parser.add_argument("--version", type=int, default=1)
    parser.add_argument("--extraction-output", type=Path)
    parser.add_argument("--inventory-output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.schema:
        json.dump(InventoryGeneration.model_json_schema(), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    if args.corpus is None or args.generation is None:
        json.dump(
            {"error": "corpus and generation paths are required unless --schema is used"},
            sys.stderr,
        )
        sys.stderr.write("\n")
        return 2
    try:
        corpus = DocumentCorpus.model_validate_json(
            args.corpus.read_text(encoding="utf-8")
        )
        generation = load_inventory_generation(args.generation)
        extraction = create_inventory_extraction(
            corpus,
            generation,
            Producer(
                agent="inventory_extractor",
                model_id=args.model_id,
                prompt_version=args.prompt_version,
            ),
            version=args.version,
        )
        inventory = materialize_inventory(
            corpus,
            extraction,
            minimum_confidence=args.minimum_confidence,
            version=args.version,
        )
    except (OSError, ValidationError, InventoryGenerationError, ValueError) as exc:
        json.dump({"error": str(exc)}, sys.stderr)
        sys.stderr.write("\n")
        return 2

    _write(args.extraction_output, extraction.model_dump_json(indent=2))
    payload = inventory.model_dump_json(indent=2)
    _write(args.inventory_output, payload)
    sys.stdout.write(payload + "\n")
    return 0


def _write(path: Path | None, payload: str) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
