"""Validate structured inventory generation and materialize canonical entities."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from pydantic import ValidationError

from riskos.ids import stable_id
from riskos.schemas.artifacts import (
    AssetInventory,
    DocumentCorpus,
    Evidence,
    EvidenceSource,
    InventoryExtraction,
    Producer,
)
from riskos.schemas.entities import Component, Control, DataAsset, DataFlow, System, ThirdParty
from riskos.schemas.generation import InventoryGeneration


class InventoryGenerationError(Exception):
    pass


def load_inventory_generation(path: str | Path) -> InventoryGeneration:
    """Deserialize provider output through the strict structured-generation schema."""
    path = Path(path)
    try:
        return InventoryGeneration.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        raise InventoryGenerationError(f"invalid inventory generation {path}: {exc}") from exc


def create_inventory_extraction(
    corpus: DocumentCorpus,
    generation: InventoryGeneration,
    producer: Producer,
    version: int = 1,
) -> InventoryExtraction:
    if version < 1:
        raise InventoryGenerationError("version must be positive")
    _validate_generation(corpus, generation)
    return InventoryExtraction(
        artifact_id=stable_id("artifact", corpus.assessment_id, "inventory_extraction"),
        assessment_id=corpus.assessment_id,
        phase="intake",
        producer=producer,
        version=version,
        corpus_artifact_id=corpus.artifact_id,
        generation=generation,
    )


def materialize_inventory(
    corpus: DocumentCorpus,
    extraction: InventoryExtraction,
    producer: Producer | None = None,
    minimum_confidence: float = 0.0,
    version: int = 1,
) -> AssetInventory:
    """Convert validated proposals into canonical entities with stable IDs."""
    if extraction.assessment_id != corpus.assessment_id:
        raise InventoryGenerationError("corpus and extraction belong to different assessments")
    if extraction.corpus_artifact_id != corpus.artifact_id:
        raise InventoryGenerationError("extraction references a different document corpus")
    if not 0.0 <= minimum_confidence <= 1.0:
        raise InventoryGenerationError("minimum_confidence must be between 0 and 1")
    if version < 1:
        raise InventoryGenerationError("version must be positive")
    generation = extraction.generation
    _validate_generation(corpus, generation)

    accepted = lambda proposal: proposal.confidence >= minimum_confidence
    systems = [proposal for proposal in generation.systems if accepted(proposal)]
    system_ids = {
        proposal.key: stable_id("system", corpus.assessment_id, proposal.key)
        for proposal in systems
    }
    components = [
        proposal
        for proposal in generation.components
        if accepted(proposal) and proposal.system_key in system_ids
    ]
    component_ids = {
        proposal.key: stable_id(
            "component", system_ids[proposal.system_key], proposal.key
        )
        for proposal in components
    }
    data_assets = [
        proposal
        for proposal in generation.data_assets
        if accepted(proposal) and proposal.system_key in system_ids
    ]
    data_asset_ids = {
        proposal.key: stable_id(
            "data_asset", system_ids[proposal.system_key], proposal.key
        )
        for proposal in data_assets
    }
    data_flows = [
        item
        for item in generation.data_flows
        if accepted(item)
        and item.source_component_key in component_ids
        and item.target_component_key in component_ids
        and all(key in data_asset_ids for key in item.data_asset_keys)
    ]
    third_parties = [
        item
        for item in generation.third_parties
        if accepted(item) and all(key in data_asset_ids for key in item.data_asset_keys)
    ]
    controls = [item for item in generation.controls if accepted(item)]
    materialized = [*systems, *components, *data_assets, *data_flows, *third_parties, *controls]
    used_chunk_ids = sorted(
        {chunk_id for item in materialized for chunk_id in item.source_chunk_ids}
    )
    evidence_ids = {
        chunk_id: stable_id("evidence", chunk_id) for chunk_id in used_chunk_ids
    }
    chunks = {chunk.chunk_id: chunk for chunk in corpus.chunks}
    image_chunks = {image.chunk_id: image for image in corpus.image_chunks}
    documents = {document.document_id: document for document in corpus.documents}

    def provenance(chunk_ids: list[str]) -> list[str]:
        return [evidence_ids[chunk_id] for chunk_id in chunk_ids]

    missing_evidence = [
        f"unresolved mention: {mention.text} ({mention.reason})"
        for mention in generation.unresolved_mentions
    ]
    rejected = _below_confidence(generation, minimum_confidence)
    missing_evidence.extend(
        f"low-confidence {kind}: {key}" for kind, key in rejected
    )
    missing_evidence.extend(
        _dependency_filtered(generation, system_ids, component_ids, data_asset_ids, accepted)
    )

    return AssetInventory(
        artifact_id=stable_id("artifact", corpus.assessment_id, "asset_inventory"),
        assessment_id=corpus.assessment_id,
        phase="intake",
        producer=producer or Producer(agent="inventory_materializer"),
        version=version,
        systems=[
            System(
                id=system_ids[item.key],
                name=item.name,
                description=item.description,
                evidence_ids=provenance(item.source_chunk_ids),
                criticality=item.criticality,
                business_owner=item.business_owner,
                supports_critical_function=item.supports_critical_function,
            )
            for item in systems
        ],
        components=[
            Component(
                id=component_ids[item.key],
                name=item.name,
                description=item.description,
                evidence_ids=provenance(item.source_chunk_ids),
                system_id=system_ids[item.system_key],
                exposure=item.exposure,
                technology=item.technology,
                cpe_candidates=item.cpe_candidates,
                is_admin_interface=item.is_admin_interface,
                is_genai=item.is_genai,
            )
            for item in components
        ],
        data_assets=[
            DataAsset(
                id=data_asset_ids[item.key],
                name=item.name,
                description=item.description,
                evidence_ids=provenance(item.source_chunk_ids),
                system_id=system_ids[item.system_key],
                classification=item.classification,
                contains_pii=item.contains_pii,
            )
            for item in data_assets
        ],
        data_flows=[
            DataFlow(
                id=stable_id("data_flow", corpus.assessment_id, item.key),
                name=item.name,
                description=item.description,
                evidence_ids=provenance(item.source_chunk_ids),
                source_component_id=component_ids[item.source_component_key],
                target_component_id=component_ids[item.target_component_key],
                data_asset_ids=[data_asset_ids[key] for key in item.data_asset_keys],
                protocol=item.protocol,
                encrypted_in_transit=item.encrypted_in_transit,
                crosses_trust_boundary=item.crosses_trust_boundary,
            )
            for item in data_flows
        ],
        third_parties=[
            ThirdParty(
                id=stable_id("third_party", corpus.assessment_id, item.key),
                name=item.name,
                description=item.description,
                evidence_ids=provenance(item.source_chunk_ids),
                service=item.service,
                data_asset_ids=[data_asset_ids[key] for key in item.data_asset_keys],
                outsourcing_classification=item.outsourcing_classification,
                has_exit_plan=item.has_exit_plan,
                concentration_risk=item.concentration_risk,
            )
            for item in third_parties
        ],
        controls=[
            Control(
                id=stable_id("control", corpus.assessment_id, item.key),
                name=item.name,
                description=item.description,
                evidence_ids=provenance(item.source_chunk_ids),
                taxonomy_ref=item.taxonomy_ref,
                framework_refs=item.framework_refs,
                implemented=item.implemented,
                strength=item.strength,
            )
            for item in controls
        ],
        evidence=[
            Evidence(
                evidence_id=evidence_ids[chunk_id],
                source_type=EvidenceSource.DOCUMENT,
                source_ref=_source_ref(chunk_id, chunks, image_chunks, documents),
                excerpt=chunks[chunk_id].text if chunk_id in chunks else "",
            )
            for chunk_id in used_chunk_ids
        ],
        missing_evidence=missing_evidence,
    )


def _validate_generation(corpus: DocumentCorpus, generation: InventoryGeneration) -> None:
    chunk_ids = {chunk.chunk_id for chunk in corpus.chunks} | {
        image.chunk_id for image in corpus.image_chunks
    }
    groups = (
        ("system", generation.systems),
        ("component", generation.components),
        ("data_asset", generation.data_assets),
        ("data_flow", generation.data_flows),
        ("third_party", generation.third_parties),
        ("control", generation.controls),
    )
    errors: list[str] = []
    for kind, proposals in groups:
        duplicates = _duplicates(item.key for item in proposals)
        if duplicates:
            errors.append(f"duplicate {kind} keys: {duplicates}")
        for proposal in proposals:
            unknown = sorted(set(proposal.source_chunk_ids) - chunk_ids)
            if unknown:
                errors.append(f"{kind} {proposal.key!r} references unknown chunks: {unknown}")
    for mention in generation.unresolved_mentions:
        unknown = sorted(set(mention.source_chunk_ids) - chunk_ids)
        if unknown:
            errors.append(f"unresolved mention references unknown chunks: {unknown}")

    system_keys = {item.key for item in generation.systems}
    component_keys = {item.key for item in generation.components}
    data_asset_keys = {item.key for item in generation.data_assets}
    for item in generation.components:
        if item.system_key not in system_keys:
            errors.append(f"component {item.key!r} references unknown system {item.system_key!r}")
    for item in generation.data_assets:
        if item.system_key not in system_keys:
            errors.append(f"data asset {item.key!r} references unknown system {item.system_key!r}")
    for item in generation.data_flows:
        if item.source_component_key not in component_keys:
            errors.append(
                f"data flow {item.key!r} references unknown source component "
                f"{item.source_component_key!r}"
            )
        if item.target_component_key not in component_keys:
            errors.append(
                f"data flow {item.key!r} references unknown target component "
                f"{item.target_component_key!r}"
            )
        unknown = sorted(set(item.data_asset_keys) - data_asset_keys)
        if unknown:
            errors.append(f"data flow {item.key!r} references unknown data assets: {unknown}")
    for item in generation.third_parties:
        unknown = sorted(set(item.data_asset_keys) - data_asset_keys)
        if unknown:
            errors.append(f"third party {item.key!r} references unknown data assets: {unknown}")
    if errors:
        raise InventoryGenerationError("; ".join(errors))


def _duplicates(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return sorted(duplicates)


def _below_confidence(
    generation: InventoryGeneration, minimum: float
) -> list[tuple[str, str]]:
    groups = (
        ("system", generation.systems),
        ("component", generation.components),
        ("data asset", generation.data_assets),
        ("data flow", generation.data_flows),
        ("third party", generation.third_parties),
        ("control", generation.controls),
    )
    return [
        (kind, proposal.key)
        for kind, proposals in groups
        for proposal in proposals
        if proposal.confidence < minimum
    ]


def _dependency_filtered(
    generation: InventoryGeneration,
    system_ids: dict[str, str],
    component_ids: dict[str, str],
    data_asset_ids: dict[str, str],
    accepted,
) -> list[str]:
    filtered = [
        f"dependency-filtered component: {item.key}"
        for item in generation.components
        if accepted(item) and item.system_key not in system_ids
    ]
    filtered.extend(
        f"dependency-filtered data asset: {item.key}"
        for item in generation.data_assets
        if accepted(item) and item.system_key not in system_ids
    )
    filtered.extend(
        f"dependency-filtered data flow: {item.key}"
        for item in generation.data_flows
        if accepted(item)
        and (
            item.source_component_key not in component_ids
            or item.target_component_key not in component_ids
            or any(key not in data_asset_ids for key in item.data_asset_keys)
        )
    )
    filtered.extend(
        f"dependency-filtered third party: {item.key}"
        for item in generation.third_parties
        if accepted(item) and any(key not in data_asset_ids for key in item.data_asset_keys)
    )
    return filtered


def _source_ref(chunk_id, text_chunks, image_chunks, documents) -> str:
    if chunk_id in text_chunks:
        chunk = text_chunks[chunk_id]
        document = documents[chunk.document_id]
        locator = chunk.heading or f"chunk {chunk.ordinal}"
        return f"{document.source_path}#{locator}"
    image = image_chunks[chunk_id]
    document = documents[image.document_id]
    return f"{document.source_path}#page {image.page_num}"
