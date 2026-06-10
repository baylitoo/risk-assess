"""Computed (never self-reported) finding confidence.

confidence = source_reliability × extraction_confidence × mapping_confidence
             × validation_multiplier

- source_reliability: max effective reliability across the finding's cited
  evidence (a finding is as strong as its best independent source).
- extraction_confidence: how sure the pipeline is that the underlying fact
  was read correctly out of the document/diagram (set at extraction time).
- mapping_confidence: how sure the mapping to taxonomy/control/CVE is.
- validation_multiplier: from methodology config — unvalidated facts are
  discounted; tool-corroborated or human-confirmed are not.

The model is never asked "how confident are you" — LLM self-assessed
confidence is not calibrated. Every input here is a property of evidence
or pipeline state.
"""

from __future__ import annotations

from dataclasses import dataclass

from riskos.schemas.artifacts import Evidence, FindingStatus, RiskFinding

_BAND_ORDER = ["low", "medium", "high", "very_high", "critical"]


@dataclass(frozen=True)
class ConfidenceInputs:
    extraction_confidence: float   # 0..1, set by the extraction pipeline
    mapping_confidence: float      # 0..1, set by the mapping step
    validation_status: str         # unvalidated | tool_corroborated | human_confirmed


def compute_confidence(
    finding: RiskFinding,
    evidence_index: dict[str, Evidence],
    inputs: ConfidenceInputs,
    config: dict,
) -> RiskFinding:
    """Fill ``confidence`` and apply the requires_confirmation gate."""
    cited = [
        evidence_index[c.evidence_id]
        for c in finding.citations
        if c.evidence_id in evidence_index
    ]
    if not cited:
        # No grounding at all ⇒ confidence is zero by definition.
        source_reliability = 0.0
    else:
        source_reliability = max(e.effective_reliability() for e in cited)

    multipliers = config["confidence"]["validation_multiplier"]
    if inputs.validation_status not in multipliers:
        raise ValueError(
            f"unknown validation_status {inputs.validation_status!r} "
            f"(allowed: {sorted(multipliers)})"
        )

    confidence = (
        source_reliability
        * _clamp(inputs.extraction_confidence)
        * _clamp(inputs.mapping_confidence)
        * float(multipliers[inputs.validation_status])
    )
    confidence = round(_clamp(confidence), 4)

    status = finding.status
    gate_band = config["confidence"]["gate_band"]
    threshold = float(config["confidence"]["threshold"])
    if (
        finding.band
        and _BAND_ORDER.index(finding.band) >= _BAND_ORDER.index(gate_band)
        and confidence < threshold
    ):
        status = FindingStatus.REQUIRES_CONFIRMATION

    return finding.model_copy(update={"confidence": confidence, "status": status})


def _clamp(value: float) -> float:
    return min(1.0, max(0.0, float(value)))
