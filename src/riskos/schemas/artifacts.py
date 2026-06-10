"""Typed workflow artifacts — the only inter-agent communication channel.

Agents never share a context window; a phase consumes the previous phase's
artifacts and emits its own. Every artifact carries provenance (producer,
model, prompt hash) because the artifact *is* the audit record.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from riskos.schemas.entities import (
    Component,
    Control,
    DataAsset,
    DataFlow,
    System,
    ThirdParty,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Producer(BaseModel):
    """Who/what produced an artifact — pinned for reproducibility."""

    model_config = ConfigDict(extra="forbid")

    agent: str                      # e.g. "vuln_operator"
    model_id: str = ""              # pinned model version, empty for pure code
    prompt_version: str = ""
    tool_versions: dict[str, str] = Field(default_factory=dict)


class Artifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_id: str
    artifact_type: str
    assessment_id: str
    phase: str
    schema_version: str = "1"
    version: int = 1                # bumped when a challenge loop revises it
    created_at: datetime = Field(default_factory=_utcnow)
    producer: Producer


class EvidenceSource(StrEnum):
    DOCUMENT = "document"           # SATS, spec, diagram…
    NVD = "nvd"
    KEV = "kev"
    EPSS = "epss"
    SCANNER = "scanner"
    TAXONOMY = "taxonomy"           # internal control catalog / policy
    INTEL = "intel"                 # mirrored external media
    HUMAN = "human"


# Default reliability per source type; overridable per evidence item.
SOURCE_RELIABILITY: dict[EvidenceSource, float] = {
    EvidenceSource.HUMAN: 1.0,
    EvidenceSource.KEV: 1.0,
    EvidenceSource.NVD: 0.95,
    EvidenceSource.TAXONOMY: 0.95,
    EvidenceSource.SCANNER: 0.9,
    EvidenceSource.EPSS: 0.85,
    EvidenceSource.DOCUMENT: 0.8,   # self-declared by the project
    EvidenceSource.INTEL: 0.7,
}


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    source_type: EvidenceSource
    source_ref: str                 # doc id + section, CVE id, KEV entry, URL…
    excerpt: str = ""
    reliability: float | None = Field(default=None, ge=0.0, le=1.0)

    def effective_reliability(self) -> float:
        if self.reliability is not None:
            return self.reliability
        return SOURCE_RELIABILITY[self.source_type]


class Citation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    locator: str = ""               # page/section/line when applicable


class FindingCategory(StrEnum):
    VULNERABILITY = "vulnerability"
    ACCESS_MANAGEMENT = "access_management"
    ABUSE_PREVENTION = "abuse_prevention"      # rate limiting, anti-automation
    PRIVACY = "privacy"
    RESILIENCE = "resilience"
    THIRD_PARTY = "third_party"
    NETWORK = "network"
    CRYPTOGRAPHY = "cryptography"
    LOGGING_MONITORING = "logging_monitoring"
    GENAI = "genai"
    POLICY_GAP = "policy_gap"


class FindingStatus(StrEnum):
    DRAFT = "draft"
    REQUIRES_CONFIRMATION = "requires_confirmation"  # low confidence × high severity
    CONFIRMED = "confirmed"
    ACCEPTED = "accepted"            # reviewer action
    EDITED = "edited"                # reviewer action — label for the eval flywheel
    REJECTED = "rejected"            # reviewer action


class RiskFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    title: str
    category: FindingCategory
    scenario: str                    # the risk scenario narrative
    affected_asset_ids: list[str] = Field(default_factory=list)
    threat_refs: list[str] = Field(default_factory=list)   # STRIDE/ATT&CK refs

    # The model proposes rubric *levels*; the deterministic scorer fills scores.
    factors: dict[str, str] = Field(default_factory=dict)
    inherent_score: int | None = None
    residual_score: int | None = None
    band: str = ""                   # filled by scorer: low…critical

    confidence: float | None = None  # filled by confidence calculator
    status: FindingStatus = FindingStatus.DRAFT

    citations: list[Citation] = Field(default_factory=list)
    mapped_control_ids: list[str] = Field(default_factory=list)
    remediation: str = ""
    owner: str = ""


class AssetInventory(Artifact):
    """Phase 0 output — the backbone every later phase works against."""

    artifact_type: str = "asset_inventory"
    systems: list[System] = Field(default_factory=list)
    components: list[Component] = Field(default_factory=list)
    data_assets: list[DataAsset] = Field(default_factory=list)
    data_flows: list[DataFlow] = Field(default_factory=list)
    third_parties: list[ThirdParty] = Field(default_factory=list)
    controls: list[Control] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)  # intake bounce list


class AssessmentModule(StrEnum):
    DORA = "dora"
    PRIVACY = "privacy"
    GENAI = "genai"
    ADVERSARY = "adversary"


class AssessmentDepth(StrEnum):
    FAST_TRACK = "fast_track"
    FULL = "full"


class MissingEvidenceRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    description: str
    entity_ids: list[str] = Field(default_factory=list)


class IntakeAssessment(Artifact):
    """Deterministic intake completeness gate output."""

    artifact_type: str = "intake_assessment"
    complete: bool
    requirements: list[MissingEvidenceRequirement] = Field(default_factory=list)


class ScopeDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str
    reason: str
    entity_ids: list[str] = Field(default_factory=list)


class AssessmentScope(Artifact):
    """Phase 1 output confirmed by the first human review gate."""

    artifact_type: str = "assessment_scope"
    depth: AssessmentDepth
    modules: list[AssessmentModule] = Field(default_factory=list)
    scheduled_agents: list[str] = Field(default_factory=list)
    decisions: list[ScopeDecision] = Field(default_factory=list)


class VulnerabilityFindings(Artifact):
    """Vuln-operator output."""

    artifact_type: str = "vulnerability_findings"
    findings: list[RiskFinding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class RiskRegister(Artifact):
    """Synthesis output — what goes in front of the reviewer."""

    artifact_type: str = "risk_register"
    methodology_version: str = ""
    findings: list[RiskFinding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
