"""Inventory extraction: DocumentCorpus → InventoryExtraction.

This module owns the extraction prompt and wires the gateway call into
the validated pipeline. The generation gateway is asked to produce a structured
``InventoryGeneration``; the result is immediately passed through
``create_inventory_extraction`` for chunk-ID validation before it is
stored as an artifact.

Prompt design notes (ROADMAP §3 rule 2 — "help text is the contract"):
- Written for an LLM operator; examples are in the schema, not here.
- Keys are explicitly constrained to short, hyphen-separated identifiers
  so the materializer key→ID mapping is deterministic and human-readable.
- encrypted_in_transit / confidence semantics are spelt out because LLMs
  over-assert certainty and under-report unknown states without guidance.
"""

from __future__ import annotations

from riskos.gateway import ImageContent, StructuredGenerationGateway, StructuredGenerationRequest
from riskos.intake.inventory import InventoryGenerationError, create_inventory_extraction
from riskos.schemas.artifacts import DocumentCorpus, InventoryExtraction, Producer
from riskos.schemas.generation import InventoryGeneration

_SYSTEM_PROMPT = """\
You are an expert IT risk analyst performing structured inventory extraction for a
bank's IT risk assessment. You will receive document chunks from a system dossier
(SATS, architecture specs, network diagrams, technical specs) and must extract a
structured asset inventory.

WHAT TO EXTRACT
  systems        Top-level IT systems described in the documents.
  components     Software, services, APIs, databases, and interfaces within each system.
  data_assets    Datasets or data categories processed or stored by the system.
  data_flows     Connections between components, especially across trust boundaries.
  third_parties  External vendors or services the system depends on.
  controls       Security controls mentioned or evidenced in the documents.

KEY RULES
  source_chunk_ids  Every entity MUST reference at least one chunk using the exact
                    chunk id from the <chunk id="..."> tag. Do not invent chunk IDs.
  confidence        0.0–1.0. Use ≥0.9 only when the evidence is unambiguous and
                    explicit. Use 0.5–0.7 for reasonable inference. Use <0.5 for
                    weak signals. Never round-up to 1.0 on self-generated inference.
  keys              Short, lowercase, hyphen-separated identifiers, unique within
                    their type (e.g. "payments-api", "customer-records").
  is_genai          Set true for any component that includes an LLM, embedding model,
                    RAG pipeline, or AI agent.
  is_admin_interface  Set true for management consoles, admin panels, RBAC UIs.
  crosses_trust_boundary  True when the flow crosses a network zone boundary
                    (e.g. internet→DMZ, DMZ→internal, internal→restricted).
  encrypted_in_transit  true=confirmed encrypted, false=confirmed cleartext,
                    null=not stated (do not assume encrypted when not stated).
  unresolved_mentions  Use for entities mentioned but too ambiguous to classify
                    properly (e.g. "legacy gateway (ownership unknown)").

OUTPUT
  Return a single InventoryGeneration JSON object.
  Do not add commentary outside the JSON structure.
  Do not hallucinate entities not grounded in the provided chunks.
"""


def extract_inventory(
    corpus: DocumentCorpus,
    gateway: StructuredGenerationGateway,
    producer: Producer,
    route: str = "inventory-extraction",
    prompt_version: str = "1",
    max_output_tokens: int = 8192,
    timeout_seconds: float = 120.0,
    version: int = 1,
) -> InventoryExtraction:
    """Call the generation gateway to extract an inventory from a document corpus.

    Validates the generation output against the corpus chunk IDs immediately
    so any hallucinated chunk references are caught before the artifact is
    stored.
    """
    if version < 1:
        raise InventoryGenerationError("version must be positive")
    user_message = _format_corpus(corpus)
    images = [
        ImageContent(media_type=ic.media_type, data_b64=ic.data_b64)
        for ic in corpus.image_chunks
    ]
    request = StructuredGenerationRequest(
        route=route,
        system_prompt=_SYSTEM_PROMPT,
        user_message=user_message,
        prompt_version=prompt_version,
        max_output_tokens=max_output_tokens,
        timeout_seconds=timeout_seconds,
        images=images,
    )
    generation = gateway.generate_structured(
        request=request,
        response_model=InventoryGeneration,
    )
    return create_inventory_extraction(corpus, generation, producer, version=version)


def _format_corpus(corpus: DocumentCorpus) -> str:
    """Render corpus chunks as tagged XML-like blocks the LLM can reference by ID."""
    parts: list[str] = [
        f"Assessment ID: {corpus.assessment_id}",
        f"Document count: {len(corpus.documents)}",
        f"Chunk count: {len(corpus.chunks)}",
        f"Image count: {len(corpus.image_chunks)}",
        "",
    ]
    for chunk in corpus.chunks:
        attrs = f'id="{chunk.chunk_id}"'
        if chunk.heading:
            attrs += f' heading="{chunk.heading}"'
        parts.append(f"<chunk {attrs}>")
        parts.append(chunk.text)
        parts.append("</chunk>")
        parts.append("")
    return "\n".join(parts)
