"""Tests for the inventory extractor — gateway wiring, prompt shape, validation."""

import pytest

from riskos.gateway import FakeStructuredGenerationGateway
from riskos.ids import stable_id
from riskos.intake import extract_inventory, ingest_directory, InventoryGenerationError
from riskos.schemas.artifacts import ImageChunk, Producer
from riskos.schemas.generation import (
    InventoryGeneration,
    ProposedComponent,
    ProposedSystem,
)


@pytest.fixture()
def corpus(tmp_path):
    (tmp_path / "sats.md").write_text(
        "# Security Architecture\n\nPayments gateway with a REST API and PII storage.",
        encoding="utf-8",
    )
    return ingest_directory(tmp_path, stable_id("assessment", "extractor-test"))


@pytest.fixture()
def producer():
    return Producer(agent="inventory_extractor", generation_route="inventory-extraction")


def _simple_generation(chunk_id: str) -> InventoryGeneration:
    return InventoryGeneration(
        systems=[
            ProposedSystem(
                key="payments-gateway",
                name="Payments Gateway",
                source_chunk_ids=[chunk_id],
                confidence=0.95,
            )
        ],
        components=[
            ProposedComponent(
                key="rest-api",
                name="REST API",
                system_key="payments-gateway",
                source_chunk_ids=[chunk_id],
                confidence=0.9,
                exposure="internet_facing",
            )
        ],
    )


def test_extract_inventory_returns_extraction_artifact(corpus, producer):
    chunk_id = corpus.chunks[0].chunk_id
    gateway = FakeStructuredGenerationGateway()
    gateway.set_response(InventoryGeneration, _simple_generation(chunk_id))

    extraction = extract_inventory(corpus, gateway, producer)

    assert extraction.assessment_id == corpus.assessment_id
    assert extraction.corpus_artifact_id == corpus.artifact_id
    assert len(extraction.generation.systems) == 1
    assert extraction.generation.systems[0].name == "Payments Gateway"


def test_extractor_passes_route_to_gateway(corpus, producer):
    gateway = FakeStructuredGenerationGateway()
    gateway.set_response(InventoryGeneration, _simple_generation(corpus.chunks[0].chunk_id))

    extract_inventory(corpus, gateway, producer, route="inventory-extraction")

    assert gateway.calls[0].route == "inventory-extraction"


def test_extractor_formats_chunk_ids_in_user_message(corpus, producer):
    chunk_id = corpus.chunks[0].chunk_id
    gateway = FakeStructuredGenerationGateway()
    gateway.set_response(InventoryGeneration, _simple_generation(chunk_id))

    extract_inventory(corpus, gateway, producer)

    user_message = gateway.calls[0].user_message
    assert chunk_id in user_message
    assert '<chunk ' in user_message


def test_extractor_validates_chunk_ids_in_generation(corpus, producer):
    generation = InventoryGeneration(
        systems=[
            ProposedSystem(
                key="sys",
                name="Sys",
                source_chunk_ids=["chk-does-not-exist"],
                confidence=0.9,
            )
        ]
    )
    gateway = FakeStructuredGenerationGateway()
    gateway.set_response(InventoryGeneration, generation)

    with pytest.raises(InventoryGenerationError, match="unknown chunks"):
        extract_inventory(corpus, gateway, producer)


def test_extractor_rejects_invalid_version(corpus, producer):
    gateway = FakeStructuredGenerationGateway()
    gateway.set_response(InventoryGeneration, _simple_generation(corpus.chunks[0].chunk_id))

    with pytest.raises(InventoryGenerationError, match="version"):
        extract_inventory(corpus, gateway, producer, version=0)


def test_extractor_heading_in_chunk_tag(corpus, producer):
    gateway = FakeStructuredGenerationGateway()
    gateway.set_response(InventoryGeneration, _simple_generation(corpus.chunks[0].chunk_id))

    extract_inventory(corpus, gateway, producer)

    user_message = gateway.calls[0].user_message
    # The corpus has a markdown heading — it should appear in the formatted chunk tag.
    assert 'heading=' in user_message


def test_extractor_text_only_corpus_has_no_images(corpus, producer):
    gateway = FakeStructuredGenerationGateway()
    gateway.set_response(InventoryGeneration, _simple_generation(corpus.chunks[0].chunk_id))

    extract_inventory(corpus, gateway, producer)

    assert gateway.calls[0].images == []
    assert "Image count: 0" in gateway.calls[0].user_message


def test_extractor_attaches_image_chunks_to_request(corpus, producer):
    image_chunk = ImageChunk(
        chunk_id=stable_id("image_chunk", "doc-1", "1"),
        document_id="doc-1",
        page_num=1,
        media_type="image/jpeg",
        data_b64="ZmFrZS1qcGVn",
        sha256="0" * 64,
        size_bytes=8,
    )
    corpus_with_image = corpus.model_copy(update={"image_chunks": [image_chunk]})
    gateway = FakeStructuredGenerationGateway()
    gateway.set_response(InventoryGeneration, _simple_generation(corpus.chunks[0].chunk_id))

    extract_inventory(corpus_with_image, gateway, producer)

    request = gateway.calls[0]
    assert len(request.images) == 1
    assert request.images[0].media_type == "image/jpeg"
    assert request.images[0].data_b64 == "ZmFrZS1qcGVn"
    assert "Image count: 1" in request.user_message


def test_extractor_lists_image_chunk_ids_for_citation(corpus, producer):
    image_chunk = ImageChunk(
        chunk_id=stable_id("image_chunk", "doc-1", "1"),
        document_id="doc-1",
        page_num=1,
        media_type="image/jpeg",
        data_b64="ZmFrZS1qcGVn",
        sha256="0" * 64,
        size_bytes=8,
    )
    corpus_with_image = corpus.model_copy(update={"image_chunks": [image_chunk]})
    gateway = FakeStructuredGenerationGateway()
    gateway.set_response(InventoryGeneration, _simple_generation(corpus.chunks[0].chunk_id))

    extract_inventory(corpus_with_image, gateway, producer)

    msg = gateway.calls[0].user_message
    # The image id must appear as a citeable <image> tag, ordered to match the
    # attached request.images list, so the model can cite a diagram.
    assert "<image " in msg
    assert image_chunk.chunk_id in msg
    assert 'order="0"' in msg
