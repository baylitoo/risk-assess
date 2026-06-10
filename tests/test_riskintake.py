"""End-to-end tests for the Phase 0 intake CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from riskos.cli.riskintake import main
from riskos.gateway import FakeStructuredGenerationGateway
from riskos.ids import stable_id
from riskos.intake import ingest_directory
from riskos.schemas.generation import InventoryGeneration, ProposedComponent, ProposedSystem
from tests.conftest import REPO_ROOT

_POLICIES_DIR = REPO_ROOT / "policies"


def _make_gateway(chunk_id: str) -> FakeStructuredGenerationGateway:
    gw = FakeStructuredGenerationGateway()
    gw.set_response(
        InventoryGeneration,
        InventoryGeneration(
            systems=[
                ProposedSystem(
                    key="core-system",
                    name="Core System",
                    source_chunk_ids=[chunk_id],
                    confidence=0.9,
                )
            ],
            components=[
                ProposedComponent(
                    key="core-api",
                    name="Core API",
                    system_key="core-system",
                    source_chunk_ids=[chunk_id],
                    confidence=0.9,
                )
            ],
        ),
    )
    return gw


def _empty_gateway() -> FakeStructuredGenerationGateway:
    gw = FakeStructuredGenerationGateway()
    gw.set_response(InventoryGeneration, InventoryGeneration())
    return gw


@pytest.fixture()
def corpus_file(tmp_path) -> tuple[Path, str]:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "sats.md").write_text("# Architecture\n\nCore banking system.", encoding="utf-8")
    assessment_id = stable_id("assessment", "intake-cli-test")
    corpus = ingest_directory(docs, assessment_id)
    corpus_path = tmp_path / "corpus.json"
    corpus_path.write_text(corpus.model_dump_json(indent=2), encoding="utf-8")
    return corpus_path, corpus.chunks[0].chunk_id


def test_run_success(tmp_path, corpus_file, capsys):
    corpus_path, chunk_id = corpus_file
    gateway = _make_gateway(chunk_id)

    code = main(
        [
            str(corpus_path),
            "--workspace-dir", str(tmp_path / "ws"),
            "--audit-log", str(tmp_path / "audit.jsonl"),
            "--policies-dir", str(_POLICIES_DIR),
        ],
        gateway=gateway,
    )

    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out["status"] == "ok"
    assert out["complete"] is True
    assert out["extraction_artifact_id"]
    assert out["inventory_artifact_id"]
    assert out["completeness_artifact_id"]
    assert out["audit_event_count"] > 0
    assert (tmp_path / "ws").exists()


def test_run_incomplete(tmp_path, corpus_file, capsys):
    corpus_path, _ = corpus_file
    gateway = _empty_gateway()

    code = main(
        [
            str(corpus_path),
            "--workspace-dir", str(tmp_path / "ws"),
            "--audit-log", str(tmp_path / "audit.jsonl"),
            "--policies-dir", str(_POLICIES_DIR),
        ],
        gateway=gateway,
    )

    out = json.loads(capsys.readouterr().out)
    assert code == 1
    assert out["complete"] is False
    assert out["missing_requirements"]


def test_run_missing_corpus_file(tmp_path, capsys):
    code = main(
        [
            str(tmp_path / "nonexistent.json"),
            "--workspace-dir", str(tmp_path / "ws"),
            "--audit-log", str(tmp_path / "audit.jsonl"),
            "--policies-dir", str(_POLICIES_DIR),
        ]
    )

    err = json.loads(capsys.readouterr().err)
    assert code == 2
    assert "error" in err or "message" in err


def test_run_output_file(tmp_path, corpus_file, capsys):
    corpus_path, chunk_id = corpus_file
    output_path = tmp_path / "result.json"

    main(
        [
            str(corpus_path),
            "--workspace-dir", str(tmp_path / "ws"),
            "--audit-log", str(tmp_path / "audit.jsonl"),
            "--policies-dir", str(_POLICIES_DIR),
            "--output", str(output_path),
        ],
        gateway=_make_gateway(chunk_id),
    )

    capsys.readouterr()
    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert saved["extraction_artifact_id"]


def test_run_with_eval_corpus(tmp_path, corpus_file, capsys):
    corpus_path, chunk_id = corpus_file
    eval_dir = REPO_ROOT / "evals" / "inventory"

    code = main(
        [
            str(corpus_path),
            "--workspace-dir", str(tmp_path / "ws"),
            "--audit-log", str(tmp_path / "audit.jsonl"),
            "--policies-dir", str(_POLICIES_DIR),
            "--eval-corpus", str(eval_dir),
            "--eval-split", "regression",
        ],
        gateway=_make_gateway(chunk_id),
    )

    out = json.loads(capsys.readouterr().out)
    assert "eval" in out
