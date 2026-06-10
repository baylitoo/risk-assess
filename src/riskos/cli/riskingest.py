"""Normalize a local text/Markdown dossier into a typed document corpus."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from riskos.intake import IngestionError, ingest_directory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("document_dir", type=Path)
    parser.add_argument("--assessment-id", required=True)
    parser.add_argument("--max-chunk-chars", type=int, default=2_000)
    parser.add_argument("--version", type=int, default=1)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        corpus = ingest_directory(
            args.document_dir,
            args.assessment_id,
            max_chunk_chars=args.max_chunk_chars,
            version=args.version,
        )
    except (IngestionError, OSError, ValueError) as exc:
        json.dump({"error": str(exc)}, sys.stderr)
        sys.stderr.write("\n")
        return 2

    payload = corpus.model_dump_json(indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    sys.stdout.write(payload + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
