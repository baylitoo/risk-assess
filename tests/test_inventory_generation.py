import json

import pytest
from pydantic import ValidationError

from riskos.ids import stable_id
from riskos.intake import (
    InventoryGenerationError,
    create_inventory_extraction,
    ingest_directory,
    materialize_inventory,
)
from riskos.schemas.artifacts import Producer
from riskos.schemas.artifacts import AssetInventory, InventoryExtraction
from riskos.schemas.generation import (
    InventoryGeneration,
    ProposedComponent,
    ProposedDataAsset,
    ProposedDataFlow,
    ProposedSystem,
    UnresolvedMention,
)


@pytest.fixture()
def corpus(tmp_path):
    (tmp_path / "architecture.md").write_text(
        "# Architecture\n\nPayments system with a public API and customer records.",
        encoding="utf-8",
    )
    return ingest_directory(tmp_path, stable_id("assessment", "generation"))


def _generation(chunk_id: str) -> InventoryGeneration:
    return InventoryGeneration(
        systems=[
            ProposedSystem(
                key="payments",
                name="Payments",
                source_chunk_ids=[chunk_id],
                confidence=0.98,
            )
        ],
        components=[
            ProposedComponent(
                key="public-api",
                name="Public API",
                system_key="payments",
                source_chunk_ids=[chunk_id],
                confidence=0.95,
                exposure="internet_facing",
            )
        ],
        data_assets=[
            ProposedDataAsset(
                key="customer-records",
                name="Customer records",
                system_key="payments",
                source_chunk_ids=[chunk_id],
                confidence=0.9,
                contains_pii=True,
            )
        ],
        data_flows=[
            ProposedDataFlow(
                key="api-records",
                name="API to records",
                source_component_key="public-api",
                target_component_key="public-api",
                data_asset_keys=["customer-records"],
                source_chunk_ids=[chunk_id],
                confidence=0.8,
            )
        ],
    )


def test_generation_models_round_trip_json(corpus):
    generation = _generation(corpus.chunks[0].chunk_id)

    restored = InventoryGeneration.model_validate_json(generation.model_dump_json())

    assert restored == generation
    assert restored.model_json_schema()["additionalProperties"] is False


def test_generation_models_reject_unstructured_extra_fields(corpus):
    payload = _generation(corpus.chunks[0].chunk_id).model_dump()
    payload["systems"][0]["model_commentary"] = "probably a payment system"

    with pytest.raises(ValidationError, match="extra_forbidden"):
        InventoryGeneration.model_validate(payload)


def test_materializer_mints_stable_ids_and_preserves_provenance(corpus):
    generation = _generation(corpus.chunks[0].chunk_id)
    extraction = create_inventory_extraction(
        corpus,
        generation,
        Producer(agent="inventory_extractor", generation_route="inventory-extraction"),
    )

    inventory = materialize_inventory(corpus, extraction)
    repeated = materialize_inventory(corpus, extraction, version=2)

    assert inventory.systems[0].id == repeated.systems[0].id
    assert inventory.components[0].system_id == inventory.systems[0].id
    assert inventory.data_flows[0].data_asset_ids == [inventory.data_assets[0].id]
    assert inventory.systems[0].evidence_ids == [inventory.evidence[0].evidence_id]
    assert inventory.evidence[0].source_ref == "architecture.md#Architecture"
    assert inventory.evidence[0].excerpt == corpus.chunks[0].text
    assert extraction.generation.systems[0].confidence == 0.98


def test_extraction_and_inventory_artifacts_round_trip_json(corpus):
    extraction = create_inventory_extraction(
        corpus,
        _generation(corpus.chunks[0].chunk_id),
        Producer(agent="inventory_extractor", generation_route="inventory-extraction"),
    )
    inventory = materialize_inventory(corpus, extraction)

    restored_extraction = InventoryExtraction.model_validate_json(
        extraction.model_dump_json()
    )
    restored_inventory = AssetInventory.model_validate_json(inventory.model_dump_json())

    assert restored_extraction == extraction
    assert restored_inventory == inventory


def test_materializer_rejects_unknown_relationships(corpus):
    generation = _generation(corpus.chunks[0].chunk_id)
    generation.components[0].system_key = "missing"

    with pytest.raises(InventoryGenerationError, match="unknown system"):
        create_inventory_extraction(
            corpus, generation, Producer(agent="inventory_extractor")
        )


def test_materializer_rejects_unknown_source_chunks(corpus):
    generation = _generation(corpus.chunks[0].chunk_id)
    generation.systems[0].source_chunk_ids = ["chk-unknown"]

    with pytest.raises(InventoryGenerationError, match="unknown chunks"):
        create_inventory_extraction(
            corpus, generation, Producer(agent="inventory_extractor")
        )


def test_generation_rejects_empty_reference_strings(corpus):
    payload = _generation(corpus.chunks[0].chunk_id).model_dump()
    payload["components"][0]["system_key"] = " "

    with pytest.raises(ValidationError, match="string_too_short"):
        InventoryGeneration.model_validate(payload)


def test_low_confidence_and_unresolved_mentions_become_missing_evidence(corpus):
    generation = _generation(corpus.chunks[0].chunk_id)
    generation.components[0].confidence = 0.2
    generation.unresolved_mentions = [
        UnresolvedMention(
            text="legacy gateway",
            reason="ownership unknown",
            source_chunk_ids=[corpus.chunks[0].chunk_id],
        )
    ]
    extraction = create_inventory_extraction(
        corpus, generation, Producer(agent="inventory_extractor")
    )

    inventory = materialize_inventory(corpus, extraction, minimum_confidence=0.5)

    assert inventory.components == []
    assert any("low-confidence component: public-api" in item for item in inventory.missing_evidence)
    assert any("dependency-filtered data flow: api-records" in item for item in inventory.missing_evidence)
    assert any("legacy gateway" in item for item in inventory.missing_evidence)
