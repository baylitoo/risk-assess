import json

from riskos.cli.riskinventory import main
from riskos.ids import stable_id
from riskos.intake import ingest_directory
from riskos.schemas.generation import InventoryGeneration, ProposedSystem


def test_riskinventory_accepts_only_structured_generation(tmp_path, capsys):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "architecture.md").write_text("# Architecture\n\nPayments.", encoding="utf-8")
    corpus = ingest_directory(docs, stable_id("assessment", "cli"))
    corpus_path = tmp_path / "corpus.json"
    corpus_path.write_text(corpus.model_dump_json(), encoding="utf-8")
    generation = InventoryGeneration(
        systems=[
            ProposedSystem(
                key="payments",
                name="Payments",
                source_chunk_ids=[corpus.chunks[0].chunk_id],
                confidence=1.0,
            )
        ]
    )
    generation_path = tmp_path / "generation.json"
    generation_path.write_text(generation.model_dump_json(), encoding="utf-8")
    extraction_path = tmp_path / "extraction.json"

    code = main(
        [
            str(corpus_path),
            str(generation_path),
            "--model-id",
            "provider-model-v1",
            "--extraction-output",
            str(extraction_path),
        ]
    )

    inventory = json.loads(capsys.readouterr().out)
    extraction = json.loads(extraction_path.read_text(encoding="utf-8"))
    assert code == 0
    assert inventory["artifact_type"] == "asset_inventory"
    assert extraction["artifact_type"] == "inventory_extraction"
    assert extraction["producer"]["model_id"] == "provider-model-v1"


def test_riskinventory_exposes_provider_json_schema(capsys):
    code = main(["--schema"])

    schema = json.loads(capsys.readouterr().out)
    assert code == 0
    assert schema["title"] == "InventoryGeneration"
    assert schema["additionalProperties"] is False
    assert "systems" in schema["properties"]


def test_riskinventory_rejects_free_form_generation(tmp_path, capsys):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "notes.md").write_text("# Notes\n\nText.", encoding="utf-8")
    corpus_model = ingest_directory(docs, stable_id("assessment", "invalid-cli"))
    corpus = tmp_path / "corpus.json"
    corpus.write_text(corpus_model.model_dump_json(), encoding="utf-8")
    generation = tmp_path / "generation.json"
    generation.write_text('{"analysis":"There is probably a system."}', encoding="utf-8")

    code = main([str(corpus), str(generation)])

    assert code == 2
    assert "error" in json.loads(capsys.readouterr().err)
