"""End-to-end pipeline benchmark.

Verifies that the artifact chain from document ingestion through inventory
extraction carries all entities, evidence, and citations forward without
silent data loss. All deterministic tests run against the golden dossier
fixture with a FakeGateway; the live test requires RISKOS_PROXY_URL.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from riskos.gateway import FakeStructuredGenerationGateway, ImageContent
from riskos.ids import stable_id
from riskos.intake import extract_inventory, ingest_directory
from riskos.intake.inventory import materialize_inventory
from riskos.schemas.artifacts import (
    AssetInventory,
    Citation,
    Evidence,
    EvidenceSource,
    FindingCategory,
    Producer,
    RiskFinding,
    RiskRegister,
    VulnerabilityFindings,
)
from riskos.schemas.entities import Component, Exposure, System
from riskos.schemas.generation import (
    InventoryGeneration,
    ProposedComponent,
    ProposedSystem,
)

GOLDEN_DOSSIER = Path(__file__).resolve().parents[1] / "fixtures" / "golden_dossier"
_PRODUCER = Producer(agent="benchmark", generation_route="inventory-extraction")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _golden_corpus():
    return ingest_directory(GOLDEN_DOSSIER, stable_id("assessment", "golden"))


def _simple_generation(chunk_id: str) -> InventoryGeneration:
    return InventoryGeneration(
        systems=[
            ProposedSystem(
                key="nexus-payments-hub",
                name="Nexus Payments Hub",
                source_chunk_ids=[chunk_id],
                confidence=0.95,
                supports_critical_function=True,
            )
        ],
        components=[
            ProposedComponent(
                key="nexus-api-gateway",
                name="nexus-api-gateway",
                system_key="nexus-payments-hub",
                source_chunk_ids=[chunk_id],
                confidence=0.9,
                exposure="internet_facing",
                technology="Kong Gateway 3.6",
            ),
            ProposedComponent(
                key="payment-engine",
                name="payment-engine",
                system_key="nexus-payments-hub",
                source_chunk_ids=[chunk_id],
                confidence=0.9,
                exposure="internal",
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------


def test_corpus_ingestion_produces_text_and_image_chunks():
    corpus = _golden_corpus()

    assert len(corpus.chunks) > 0, "golden dossier must produce text chunks"
    assert len(corpus.image_chunks) == 1, "golden dossier must contain exactly one image"
    assert corpus.image_chunks[0].media_type == "image/png"
    assert corpus.issues == [], f"unexpected ingestion issues: {corpus.issues}"


def test_corpus_document_count():
    corpus = _golden_corpus()

    filenames = {doc.filename for doc in corpus.documents}
    assert "sats.md" in filenames
    assert "architecture.md" in filenames
    assert "network_diagram.png" in filenames


# ---------------------------------------------------------------------------
# Extraction gateway wiring
# ---------------------------------------------------------------------------


def test_extraction_request_carries_diagram_image():
    corpus = _golden_corpus()
    chunk_id = corpus.chunks[0].chunk_id
    gateway = FakeStructuredGenerationGateway()
    gateway.set_response(InventoryGeneration, _simple_generation(chunk_id))

    extract_inventory(corpus, gateway, _PRODUCER)

    req = gateway.calls[0]
    assert len(req.images) == 1
    img: ImageContent = req.images[0]
    assert img.media_type == "image/png"
    assert len(img.data_b64) > 0


def test_extraction_image_data_matches_corpus_chunk():
    corpus = _golden_corpus()
    chunk_id = corpus.chunks[0].chunk_id
    gateway = FakeStructuredGenerationGateway()
    gateway.set_response(InventoryGeneration, _simple_generation(chunk_id))

    extract_inventory(corpus, gateway, _PRODUCER)

    req_image = gateway.calls[0].images[0]
    corpus_image = corpus.image_chunks[0]
    assert req_image.data_b64 == corpus_image.data_b64


def test_diagram_image_is_citeable_in_extraction():
    """An entity grounded in the diagram cites the image chunk id and survives
    validation + materialization (the #46 citation path, end to end)."""
    corpus = _golden_corpus()
    image_chunk_id = corpus.image_chunks[0].chunk_id
    generation = InventoryGeneration(
        systems=[
            ProposedSystem(
                key="nexus-payments-hub",
                name="Nexus Payments Hub",
                source_chunk_ids=[image_chunk_id],
                confidence=0.95,
            )
        ]
    )
    gateway = FakeStructuredGenerationGateway()
    gateway.set_response(InventoryGeneration, generation)

    extraction = extract_inventory(corpus, gateway, _PRODUCER)
    materialized = materialize_inventory(corpus, extraction, _PRODUCER)

    assert materialized.systems[0].name == "Nexus Payments Hub"
    assert materialized.evidence[0].source_ref.endswith("#page 1")


# ---------------------------------------------------------------------------
# Entity ID continuity
# ---------------------------------------------------------------------------


def test_entity_ids_in_findings_all_exist_in_inventory():
    """All asset IDs cited by findings must resolve to entities in the inventory."""
    assessment_id = stable_id("assessment", "benchmark-continuity")
    sys_id = stable_id("system", "nexus-payments-hub")
    api_id = stable_id("component", "nexus-payments-hub", "nexus-api-gateway")
    engine_id = stable_id("component", "nexus-payments-hub", "payment-engine")

    inventory = AssetInventory(
        artifact_id=stable_id("artifact", assessment_id, "asset_inventory"),
        assessment_id=assessment_id,
        phase="intake",
        producer=_PRODUCER,
        systems=[System(id=sys_id, name="nexus-payments-hub")],
        components=[
            Component(id=api_id, name="nexus-api-gateway", system_id=sys_id,
                      exposure=Exposure.INTERNET_FACING),
            Component(id=engine_id, name="payment-engine", system_id=sys_id),
        ],
    )

    findings = [
        RiskFinding(
            finding_id=stable_id("finding", "vulnerability", api_id),
            title="API rate limit bypass",
            category=FindingCategory.VULNERABILITY,
            scenario="Attacker bypasses rate limiting on nexus-api-gateway.",
            affected_asset_ids=[api_id],
        ),
        RiskFinding(
            finding_id=stable_id("finding", "network", api_id, engine_id),
            title="Unvalidated trust boundary crossing",
            category=FindingCategory.NETWORK,
            scenario="Traffic crosses DMZ→Internal without re-authentication.",
            affected_asset_ids=[api_id, engine_id],
        ),
    ]

    vuln_findings = VulnerabilityFindings(
        artifact_id=stable_id("artifact", assessment_id, "vulnerability_findings"),
        assessment_id=assessment_id,
        phase="vuln_analysis",
        producer=_PRODUCER,
        findings=findings,
    )

    all_inventory_ids = (
        {e.id for e in inventory.systems}
        | {e.id for e in inventory.components}
        | {e.id for e in inventory.data_assets}
        | {e.id for e in inventory.third_parties}
    )

    orphaned = [
        (f.finding_id, aid)
        for f in vuln_findings.findings
        for aid in f.affected_asset_ids
        if aid not in all_inventory_ids
    ]
    assert orphaned == [], f"findings reference unknown asset IDs: {orphaned}"


# ---------------------------------------------------------------------------
# Evidence chunk integrity
# ---------------------------------------------------------------------------


def test_evidence_chunk_refs_in_register_trace_back_to_corpus():
    """Every DOCUMENT evidence source_ref cited in the register must be a chunk ID
    that exists in the corpus that produced the inventory."""
    corpus = _golden_corpus()
    valid_chunk_ids = {c.chunk_id for c in corpus.chunks}
    a_chunk_id = corpus.chunks[0].chunk_id

    assessment_id = corpus.assessment_id
    evidence_id = stable_id("evidence", "doc", a_chunk_id)

    register = RiskRegister(
        artifact_id=stable_id("artifact", assessment_id, "risk_register"),
        assessment_id=assessment_id,
        phase="synthesis",
        producer=_PRODUCER,
        findings=[
            RiskFinding(
                finding_id=stable_id("finding", "vulnerability", "nexus-api-gateway"),
                title="Rate limiting gap",
                category=FindingCategory.VULNERABILITY,
                scenario="No rate limiting configured.",
                citations=[Citation(evidence_id=evidence_id, locator="§2.1")],
            )
        ],
        evidence=[
            Evidence(
                evidence_id=evidence_id,
                source_type=EvidenceSource.DOCUMENT,
                source_ref=a_chunk_id,
                excerpt="nexus-api-gateway: no rate limiting configured.",
            )
        ],
    )

    evidence_by_id = {e.evidence_id: e for e in register.evidence}
    broken_citations: list[tuple[str, str, str]] = []
    for finding in register.findings:
        for citation in finding.citations:
            ev = evidence_by_id.get(citation.evidence_id)
            if ev is None:
                broken_citations.append((finding.finding_id, citation.evidence_id, "missing"))
                continue
            if ev.source_type == EvidenceSource.DOCUMENT:
                if ev.source_ref not in valid_chunk_ids:
                    broken_citations.append(
                        (finding.finding_id, citation.evidence_id, ev.source_ref)
                    )

    assert broken_citations == [], f"broken citation chains: {broken_citations}"


# ---------------------------------------------------------------------------
# Live test (requires RISKOS_PROXY_URL)
# ---------------------------------------------------------------------------


@pytest.mark.live
def test_live_extraction_on_golden_dossier_meets_precision_recall():
    """Run the real gateway against the golden dossier and check a recall target.

    Requires RISKOS_PROXY_URL and RISKOS_PROXY_API_KEY to be set.
    The golden component set against which we measure is defined inline here;
    move to a JSON fixture once the first live run produces labeled output.
    """
    from riskos.adapters.gateway import LiteLLMProxyConfig, LiteLLMProxyGateway

    config = LiteLLMProxyConfig.from_env()
    gateway = LiteLLMProxyGateway(config)
    corpus = _golden_corpus()

    extraction = extract_inventory(corpus, gateway, _PRODUCER)
    inventory = materialize_inventory(corpus, extraction, _PRODUCER)

    # Hand-labeled component names that must be present in the extraction.
    expected_component_names = {
        "nexus-api-gateway",
        "payment-engine",
        "customer-db",
        "swift-adapter",
        "fraudguard-ai",
    }
    extracted_names = {c.name for c in inventory.components}
    found = expected_component_names & extracted_names
    recall = len(found) / len(expected_component_names)

    assert recall >= 0.75, (
        f"Component recall {recall:.2%} below 75% target. "
        f"Missing: {expected_component_names - extracted_names}"
    )
