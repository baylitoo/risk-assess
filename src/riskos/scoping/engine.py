"""Deterministic conditional-module activation and specialist scheduling."""

from __future__ import annotations

from riskos.ids import stable_id
from riskos.schemas.artifacts import (
    AssessmentDepth,
    AssessmentModule,
    AssessmentScope,
    AssetInventory,
    IntakeAssessment,
    Producer,
    ScopeDecision,
)
from riskos.schemas.entities import Criticality, Exposure


class ScopingError(Exception):
    pass


def scope_assessment(
    inventory: AssetInventory,
    intake: IntakeAssessment,
    producer: Producer | None = None,
) -> AssessmentScope:
    """Enforce the intake gate before producing an assessment scope."""
    if intake.assessment_id != inventory.assessment_id:
        raise ScopingError("intake assessment and inventory belong to different assessments")
    if not intake.complete:
        rule_ids = ", ".join(requirement.rule_id for requirement in intake.requirements)
        raise ScopingError(f"intake is incomplete; resolve requirements: {rule_ids}")
    return determine_scope(inventory, producer)


def determine_scope(
    inventory: AssetInventory,
    producer: Producer | None = None,
) -> AssessmentScope:
    modules = [AssessmentModule.DORA]
    decisions = [
        ScopeDecision(
            subject=AssessmentModule.DORA,
            reason="DORA is mandatory for EU-bank ICT assessments.",
        )
    ]

    pii_ids = sorted(asset.id for asset in inventory.data_assets if asset.contains_pii)
    if pii_ids:
        modules.append(AssessmentModule.PRIVACY)
        decisions.append(
            ScopeDecision(
                subject=AssessmentModule.PRIVACY,
                reason="Inventory contains personal data.",
                entity_ids=pii_ids,
            )
        )

    genai_ids = sorted(
        component.id for component in inventory.components if component.is_genai
    )
    if genai_ids:
        modules.append(AssessmentModule.GENAI)
        decisions.append(
            ScopeDecision(
                subject=AssessmentModule.GENAI,
                reason="Inventory contains GenAI components.",
                entity_ids=genai_ids,
            )
        )

    exposed_ids = sorted(
        component.id
        for component in inventory.components
        if component.exposure == Exposure.INTERNET_FACING
    )
    if exposed_ids:
        modules.append(AssessmentModule.ADVERSARY)
        decisions.append(
            ScopeDecision(
                subject=AssessmentModule.ADVERSARY,
                reason="Inventory contains internet-facing components.",
                entity_ids=exposed_ids,
            )
        )

    agents = ["internal_docs_analyst", "threat_modeler"]
    technology_ids = sorted(
        component.id
        for component in inventory.components
        if component.technology.strip() or component.cpe_candidates
    )
    if technology_ids:
        agents.extend(["media_intel", "vuln_operator"])
        decisions.append(
            ScopeDecision(
                subject="vulnerability_intelligence",
                reason="Technology inventory is available for vulnerability correlation.",
                entity_ids=technology_ids,
            )
        )

    full_depth_ids = sorted(
        system.id
        for system in inventory.systems
        if system.supports_critical_function
        or system.criticality in {Criticality.HIGH, Criticality.CRITICAL}
    )
    depth = AssessmentDepth.FULL if full_depth_ids else AssessmentDepth.FAST_TRACK
    decisions.append(
        ScopeDecision(
            subject=f"depth:{depth.value}",
            reason=(
                "Critical or high-impact systems require a full assessment."
                if full_depth_ids
                else "No critical or high-impact system was identified."
            ),
            entity_ids=full_depth_ids,
        )
    )

    return AssessmentScope(
        artifact_id=stable_id(
            "artifact", inventory.assessment_id, "assessment_scope", str(inventory.version)
        ),
        assessment_id=inventory.assessment_id,
        phase="scoping",
        producer=producer or Producer(agent="scope_engine"),
        depth=depth,
        modules=modules,
        scheduled_agents=agents,
        decisions=decisions,
    )
