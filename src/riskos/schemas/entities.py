"""Canonical entity model — the ontology v0.

These are the typed objects every artifact is built from. The future
evidence graph is these entities plus edges; until multi-hop queries are
real, they live inside artifacts. IDs come from ``riskos.ids`` and are
deterministic so re-runs and future graph migration line up.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Exposure(StrEnum):
    INTERNET_FACING = "internet_facing"
    PARTNER = "partner"          # B2B / extranet
    INTERNAL = "internal"
    RESTRICTED = "restricted"    # segregated zone, no general internal access


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"


class Criticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"  # DORA: supports a critical or important function


class _Entity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str = ""
    # Where this entity was asserted; evidence IDs, populated at extraction.
    evidence_ids: list[str] = Field(default_factory=list)


class System(_Entity):
    criticality: Criticality = Criticality.MEDIUM
    business_owner: str = ""
    # DORA scoping inputs
    supports_critical_function: bool = False


class Component(_Entity):
    system_id: str
    exposure: Exposure = Exposure.INTERNAL
    technology: str = ""              # e.g. "nginx 1.24", "PostgreSQL 16"
    cpe_candidates: list[str] = Field(default_factory=list)
    is_admin_interface: bool = False
    is_genai: bool = False            # LLM / RAG / agentic component


class DataAsset(_Entity):
    system_id: str
    classification: DataClassification = DataClassification.INTERNAL
    contains_pii: bool = False


class DataFlow(_Entity):
    source_component_id: str
    target_component_id: str
    data_asset_ids: list[str] = Field(default_factory=list)
    protocol: str = ""
    encrypted_in_transit: bool | None = None  # None = unknown (a finding in itself)
    crosses_trust_boundary: bool = False


class ThirdParty(_Entity):
    service: str = ""
    data_asset_ids: list[str] = Field(default_factory=list)
    # DORA third-party ICT fields
    outsourcing_classification: str = ""   # bank taxonomy value
    has_exit_plan: bool | None = None
    concentration_risk: bool = False


class Control(_Entity):
    taxonomy_ref: str = ""    # internal control catalog ID — primary key in audits
    framework_refs: dict[str, str] = Field(default_factory=dict)  # lens mappings, metadata only
    implemented: bool | None = None
    strength: str = ""        # rubric value consumed by the scorer
