from riskos.ids import stable_id
from riskos.intake import assess_completeness
from riskos.schemas.artifacts import AssetInventory
from riskos.schemas.entities import Component, Criticality, DataFlow, System


def test_representative_inventory_returns_precise_evidence_gaps(inventory):
    result = assess_completeness(inventory)

    assert not result.complete
    assert [requirement.rule_id for requirement in result.requirements] == [
        "INT-DORA-002",
        "INT-DORA-003",
        "INT-GENAI-001",
        "INT-PRIV-001",
    ]
    assert result.requirements[0].entity_ids == [inventory.third_parties[0].id]


def test_complete_minimal_inventory_passes(producer):
    system_id = stable_id("system", "internal-service")
    inventory = AssetInventory(
        artifact_id=stable_id("artifact", "complete", "inventory"),
        assessment_id=stable_id("assessment", "complete"),
        phase="intake",
        producer=producer,
        systems=[System(id=system_id, name="internal-service")],
        components=[
            Component(
                id=stable_id("component", "internal-service", "worker"),
                name="worker",
                system_id=system_id,
            )
        ],
    )

    result = assess_completeness(inventory)

    assert result.complete
    assert result.requirements == []


def test_broken_references_and_extractor_gaps_are_reported(producer):
    inventory = AssetInventory(
        artifact_id=stable_id("artifact", "broken", "inventory"),
        assessment_id=stable_id("assessment", "broken"),
        phase="intake",
        producer=producer,
        components=[
            Component(
                id="cmp-broken",
                name="broken",
                system_id="sys-missing",
            )
        ],
        data_flows=[
            DataFlow(
                id="flw-broken",
                name="broken",
                source_component_id="cmp-broken",
                target_component_id="cmp-missing",
            )
        ],
        missing_evidence=["network diagram", "SATS section 4"],
    )

    result = assess_completeness(inventory)
    by_rule = {requirement.rule_id: requirement for requirement in result.requirements}

    assert {"INT-000", "INT-001", "INT-003", "INT-005"} <= set(by_rule)
    assert "network diagram" in by_rule["INT-000"].description
    assert by_rule["INT-003"].entity_ids == ["cmp-broken"]


def test_critical_system_requires_named_owner(producer):
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
                criticality=Criticality.CRITICAL,
            )
        ],
        components=[
            Component(id="cmp-critical", name="api", system_id=system_id)
        ],
    )

    result = assess_completeness(inventory)

    assert any(
        requirement.rule_id == "INT-DORA-001"
        and requirement.entity_ids == [system_id]
        for requirement in result.requirements
    )
