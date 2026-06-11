"""Strict structured-generation contracts for inventory extraction."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from riskos.schemas.entities import Criticality, DataClassification, Exposure

NonEmptyStr = Annotated[str, Field(min_length=1)]


class GenerationModel(BaseModel):
    """Base for all model-generated structures: serializable and extra-forbid."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ProposedEntity(GenerationModel):
    key: NonEmptyStr
    name: NonEmptyStr
    description: str = ""
    source_chunk_ids: list[NonEmptyStr] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)


class ProposedSystem(ProposedEntity):
    criticality: Criticality = Criticality.MEDIUM
    business_owner: str = ""
    supports_critical_function: bool = False


class ProposedComponent(ProposedEntity):
    system_key: NonEmptyStr
    exposure: Exposure = Exposure.INTERNAL
    technology: str = ""
    cpe_candidates: list[NonEmptyStr] = Field(default_factory=list)
    is_admin_interface: bool = False
    is_genai: bool = False


class ProposedDataAsset(ProposedEntity):
    system_key: NonEmptyStr
    classification: DataClassification = DataClassification.INTERNAL
    contains_pii: bool = False


class ProposedDataFlow(ProposedEntity):
    source_component_key: NonEmptyStr
    target_component_key: NonEmptyStr
    data_asset_keys: list[NonEmptyStr] = Field(default_factory=list)
    protocol: str = ""
    encrypted_in_transit: bool | None = None
    crosses_trust_boundary: bool = False


class ProposedThirdParty(ProposedEntity):
    service: str = ""
    data_asset_keys: list[NonEmptyStr] = Field(default_factory=list)
    outsourcing_classification: str = ""
    has_exit_plan: bool | None = None
    concentration_risk: bool = False


class ProposedControl(ProposedEntity):
    taxonomy_ref: str = ""
    framework_refs: dict[str, str] = Field(default_factory=dict)
    implemented: bool | None = None
    strength: str = ""


class UnresolvedMention(GenerationModel):
    text: NonEmptyStr
    reason: NonEmptyStr
    source_chunk_ids: list[NonEmptyStr] = Field(min_length=1)


class InventoryGeneration(GenerationModel):
    """Provider-independent structured output expected from every extractor."""

    schema_version: Literal["1"] = "1"
    systems: list[ProposedSystem] = Field(default_factory=list)
    components: list[ProposedComponent] = Field(default_factory=list)
    data_assets: list[ProposedDataAsset] = Field(default_factory=list)
    data_flows: list[ProposedDataFlow] = Field(default_factory=list)
    third_parties: list[ProposedThirdParty] = Field(default_factory=list)
    controls: list[ProposedControl] = Field(default_factory=list)
    unresolved_mentions: list[UnresolvedMention] = Field(default_factory=list)


class ProposedFinding(ProposedEntity):
    """A threat scenario proposed by the threat_modeler or risk_synthesizer."""

    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    category: str  # validated against FindingCategory at runtime (avoids circular import)
    scenario: NonEmptyStr
    affected_asset_keys: list[str] = Field(default_factory=list)
    threat_refs: list[str] = Field(default_factory=list)
    factors: dict[str, str] = Field(default_factory=dict)
    remediation: str = ""

    def model_post_init(self, __context) -> None:  # noqa: ANN001
        from riskos.schemas.artifacts import FindingCategory  # noqa: PLC0415
        allowed = {m.value for m in FindingCategory}
        if self.category not in allowed:
            raise ValueError(
                f"category {self.category!r} is not a valid FindingCategory; "
                f"allowed: {sorted(allowed)}"
            )


class ThreatGeneration(GenerationModel):
    """Structured output from the threat modeler or synthesizer gap-filler."""

    schema_version: Literal["1"] = "1"
    findings: list[ProposedFinding] = Field(default_factory=list)
    unresolved_gaps: list[UnresolvedMention] = Field(default_factory=list)
