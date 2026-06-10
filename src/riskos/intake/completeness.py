"""Deterministic intake completeness rules for precise dossier bounce-back."""

from __future__ import annotations

from riskos.ids import stable_id
from riskos.schemas.artifacts import (
    AssetInventory,
    IntakeAssessment,
    MissingEvidenceRequirement,
    Producer,
)
from riskos.schemas.entities import Criticality


def assess_completeness(
    inventory: AssetInventory,
    producer: Producer | None = None,
) -> IntakeAssessment:
    """Return actionable missing-evidence requirements for an inventory."""
    requirements: list[MissingEvidenceRequirement] = []

    def add(rule_id: str, description: str, entity_ids: list[str] | None = None) -> None:
        requirements.append(
            MissingEvidenceRequirement(
                rule_id=rule_id,
                description=description,
                entity_ids=sorted(entity_ids or []),
            )
        )

    if inventory.missing_evidence:
        add(
            "INT-000",
            "Extractor reported missing evidence: "
            + "; ".join(sorted(inventory.missing_evidence)),
        )
    if not inventory.systems:
        add("INT-001", "At least one in-scope system is required.")
    if not inventory.components:
        add("INT-002", "At least one system component or service is required.")

    system_ids = {system.id for system in inventory.systems}
    unknown_component_systems = [
        component.id
        for component in inventory.components
        if component.system_id not in system_ids
    ]
    if unknown_component_systems:
        add(
            "INT-003",
            "Components must reference an in-scope system.",
            unknown_component_systems,
        )

    unknown_data_systems = [
        asset.id for asset in inventory.data_assets if asset.system_id not in system_ids
    ]
    if unknown_data_systems:
        add(
            "INT-004",
            "Data assets must reference an in-scope system.",
            unknown_data_systems,
        )

    component_ids = {component.id for component in inventory.components}
    invalid_flows = [
        flow.id
        for flow in inventory.data_flows
        if flow.source_component_id not in component_ids
        or flow.target_component_id not in component_ids
    ]
    if invalid_flows:
        add(
            "INT-005",
            "Data flows must reference known source and target components.",
            invalid_flows,
        )

    critical_without_owner = [
        system.id
        for system in inventory.systems
        if (
            system.supports_critical_function
            or system.criticality == Criticality.CRITICAL
        )
        and not system.business_owner.strip()
    ]
    if critical_without_owner:
        add(
            "INT-DORA-001",
            "Critical or important functions require a named business owner.",
            critical_without_owner,
        )

    third_parties_without_classification = [
        party.id
        for party in inventory.third_parties
        if not party.outsourcing_classification.strip()
    ]
    if third_parties_without_classification:
        add(
            "INT-DORA-002",
            "ICT third parties require an outsourcing classification.",
            third_parties_without_classification,
        )

    third_parties_without_exit_plan = [
        party.id for party in inventory.third_parties if party.has_exit_plan is None
    ]
    if third_parties_without_exit_plan:
        add(
            "INT-DORA-003",
            "ICT third parties require exit-plan evidence or an explicit absence.",
            third_parties_without_exit_plan,
        )

    pii_without_evidence = [
        asset.id
        for asset in inventory.data_assets
        if asset.contains_pii and not asset.evidence_ids
    ]
    if pii_without_evidence:
        add(
            "INT-PRIV-001",
            "PII classification requires supporting evidence.",
            pii_without_evidence,
        )

    genai_without_technology = [
        component.id
        for component in inventory.components
        if component.is_genai and not component.technology.strip()
    ]
    if genai_without_technology:
        add(
            "INT-GENAI-001",
            "GenAI components require model or platform technology details.",
            genai_without_technology,
        )

    requirements.sort(key=lambda requirement: requirement.rule_id)
    return IntakeAssessment(
        artifact_id=stable_id(
            "artifact", inventory.assessment_id, "intake_assessment", str(inventory.version)
        ),
        assessment_id=inventory.assessment_id,
        phase="intake",
        producer=producer or Producer(agent="intake_completeness"),
        complete=not requirements,
        requirements=requirements,
    )
