"""Stable entity identifiers.

Doctrine rule 1: the graph can wait, identity cannot. Every entity the
platform ever mentions carries a canonical ID minted here. IDs come in two
flavors:

- ``stable_id``: deterministic, derived from the entity's natural key.
  Re-running an extraction over the same dossier yields the same IDs, so
  artifacts from different runs (and the future graph) line up without
  entity resolution.
- ``new_id``: random, for run-scoped objects with no natural key
  (e.g. an agent transcript span).

ID format: ``<prefix>-<12 hex chars>``, e.g. ``cmp-3f9a2e1b07cd``.
"""

from __future__ import annotations

import hashlib
import unicodedata
import uuid

# One prefix per entity kind. Adding a kind is append-only; never reuse.
KIND_PREFIX: dict[str, str] = {
    "assessment": "asm",
    "system": "sys",
    "component": "cmp",
    "data_asset": "dat",
    "data_flow": "flw",
    "third_party": "thp",
    "control": "ctl",
    "threat_scenario": "thr",
    "finding": "fnd",
    "evidence": "evd",
    "document": "doc",
    "chunk": "chk",
    "assumption": "asn",
    "artifact": "art",
    "span": "spn",
}

_DIGEST_LEN = 12


def _normalize(part: str) -> str:
    """Casefold + strip + collapse unicode so 'Núcleo ' == 'nucleo'."""
    text = unicodedata.normalize("NFKD", part)
    text = "".join(c for c in text if not unicodedata.combining(c))
    return " ".join(text.casefold().split())


def stable_id(kind: str, *natural_key: str) -> str:
    """Deterministic ID from an entity's natural key.

    The natural key should be the minimal set of attributes that make the
    entity unique in the bank's world, e.g.
    ``stable_id("component", system_name, component_name)``.
    """
    if kind not in KIND_PREFIX:
        raise ValueError(f"unknown entity kind: {kind!r}")
    if not natural_key or not any(p.strip() for p in natural_key):
        raise ValueError("natural key must contain at least one non-empty part")
    material = "|".join(_normalize(p) for p in natural_key)
    digest = hashlib.sha256(f"{kind}|{material}".encode()).hexdigest()
    return f"{KIND_PREFIX[kind]}-{digest[:_DIGEST_LEN]}"


def new_id(kind: str) -> str:
    """Random ID for run-scoped objects without a natural key."""
    if kind not in KIND_PREFIX:
        raise ValueError(f"unknown entity kind: {kind!r}")
    return f"{KIND_PREFIX[kind]}-{uuid.uuid4().hex[:_DIGEST_LEN]}"


def kind_of(entity_id: str) -> str:
    """Reverse-lookup the entity kind from an ID prefix."""
    prefix = entity_id.split("-", 1)[0]
    for kind, p in KIND_PREFIX.items():
        if p == prefix:
            return kind
    raise ValueError(f"unrecognized id prefix: {entity_id!r}")
