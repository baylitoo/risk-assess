from riskos.ids import stable_id
from riskos.intake import assess_completeness
from riskos.schemas.artifacts import AssessmentDepth, AssessmentModule, AssetInventory
from riskos.schemas.entities import Component, Criticality, System
from riskos.scoping import ScopingError, determine_scope, scope_assessment
import pytest


def test_representative_inventory_activates_conditional_modules(inventory):
    scope = determine_scope(inventory)

    assert scope.modules == [
        AssessmentModule.DORA,
        AssessmentModule.PRIVACY,
        AssessmentModule.GENAI,
        AssessmentModule.ADVERSARY,
    ]
    assert scope.depth == AssessmentDepth.FAST_TRACK
    assert scope.scheduled_agents == [
        "internal_docs_analyst",
        "threat_modeler",
        "media_intel",
        "vuln_operator",
    ]


def test_minimal_internal_inventory_is_fast_track_and_dora_only(producer):
    system_id = stable_id("system", "internal")
    inventory = AssetInventory(
        artifact_id=stable_id("artifact", "internal", "inventory"),
        assessment_id=stable_id("assessment", "internal"),
        phase="intake",
        producer=producer,
        systems=[System(id=system_id, name="internal")],
        components=[
            Component(id="cmp-internal", name="worker", system_id=system_id)
        ],
    )

    scope = determine_scope(inventory)

    assert scope.modules == [AssessmentModule.DORA]
    assert scope.depth == AssessmentDepth.FAST_TRACK
    assert scope.scheduled_agents == ["internal_docs_analyst", "threat_modeler"]


def test_critical_system_forces_full_depth(producer):
    system_id = stable_id("system", "critical")
    inventory = AssetInventory(
        artifact_id=stable_id("artifact", "critical", "inventory"),
        assessment_id=stable_id("assessment", "critical"),
        phase="intake",
        producer=producer,
        systems=[
            System(
                id=system_id,
                name="critical",
                criticality=Criticality.HIGH,
            )
        ],
        components=[
            Component(id="cmp-critical", name="api", system_id=system_id)
        ],
    )

    scope = determine_scope(inventory)

    assert scope.depth == AssessmentDepth.FULL
    decision = next(d for d in scope.decisions if d.subject == "depth:full")
    assert decision.entity_ids == [system_id]


def test_scope_output_is_stable_for_same_inventory(inventory):
    first = determine_scope(inventory)
    second = determine_scope(inventory)

    assert first.artifact_id == second.artifact_id
    assert first.modules == second.modules
    assert first.scheduled_agents == second.scheduled_agents
    assert first.decisions == second.decisions


def test_incomplete_intake_blocks_scoping(inventory):
    intake = assess_completeness(inventory)

    with pytest.raises(ScopingError, match="INT-DORA-002"):
        scope_assessment(inventory, intake)


def test_complete_intake_can_enter_scoping(producer):
    system_id = stable_id("system", "ready")
    inventory = AssetInventory(
        artifact_id=stable_id("artifact", "ready", "inventory"),
        assessment_id=stable_id("assessment", "ready"),
        phase="intake",
        producer=producer,
        systems=[System(id=system_id, name="ready")],
        components=[Component(id="cmp-ready", name="worker", system_id=system_id)],
    )

    scope = scope_assessment(inventory, assess_completeness(inventory))

    assert scope.assessment_id == inventory.assessment_id
    assert scope.phase == "scoping"
