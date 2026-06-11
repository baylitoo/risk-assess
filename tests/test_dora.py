"""Tests for DORA ICT risk rule checker."""

from __future__ import annotations

import pytest

from riskos.dora.checker import DORA_RULES, DoraGap, check_dora_compliance
from riskos.ids import stable_id
from riskos.schemas.artifacts import (
    AssetInventory,
    FindingCategory,
    Producer,
    RiskFinding,
)
from riskos.schemas.entities import Component, DataAsset, Exposure, System, ThirdParty


def _assessment_id() -> str:
    return stable_id("assessment", "dora-test")


def _producer() -> Producer:
    return Producer(agent="test")


def _inventory(**kwargs) -> AssetInventory:
    return AssetInventory(
        artifact_id=stable_id("artifact", "dora-inv"),
        assessment_id=_assessment_id(),
        phase="intake",
        producer=_producer(),
        **kwargs,
    )


def _finding(category: FindingCategory, affected: list[str]) -> RiskFinding:
    return RiskFinding(
        finding_id=stable_id("finding", category.value, *affected),
        title=f"Test {category.value}",
        category=category,
        scenario="test scenario",
        affected_asset_ids=affected,
    )


def test_dr001_third_party_no_exit_plan():
    tp = ThirdParty(
        id=stable_id("third_party", "payment-proc"),
        name="PaymentProcessor",
        has_exit_plan=None,
    )
    inv = _inventory(third_parties=[tp])
    gaps = check_dora_compliance(inv, [])
    dr1_gaps = [g for g in gaps if g.rule_id == "DR-001"]
    assert dr1_gaps, "DR-001 should fire for ThirdParty with no exit plan"
    assert dr1_gaps[0].entity_id == tp.id


def test_dr001_cleared_by_finding():
    tp = ThirdParty(
        id=stable_id("third_party", "payment-proc2"),
        name="PaymentProcessor2",
        has_exit_plan=None,
    )
    inv = _inventory(third_parties=[tp])
    finding = _finding(FindingCategory.THIRD_PARTY, [tp.id])
    gaps = check_dora_compliance(inv, [finding])
    dr1_gaps = [g for g in gaps if g.rule_id == "DR-001"]
    assert not dr1_gaps, "DR-001 should be cleared when THIRD_PARTY finding covers the entity"


def test_dr001_has_exit_plan_no_gap():
    tp = ThirdParty(
        id=stable_id("third_party", "payment-proc3"),
        name="PaymentProcessor3",
        has_exit_plan=True,
    )
    inv = _inventory(third_parties=[tp])
    gaps = check_dora_compliance(inv, [])
    dr1_gaps = [g for g in gaps if g.rule_id == "DR-001"]
    assert not dr1_gaps


def test_dr002_concentration_risk():
    tp = ThirdParty(
        id=stable_id("third_party", "mega-cloud"),
        name="MegaCloud",
        concentration_risk=True,
        has_exit_plan=True,
    )
    inv = _inventory(third_parties=[tp])
    gaps = check_dora_compliance(inv, [])
    dr2_gaps = [g for g in gaps if g.rule_id == "DR-002"]
    assert dr2_gaps


def test_dr003_critical_system_no_resilience():
    sys = System(
        id=stable_id("system", "core-banking"),
        name="Core Banking",
        supports_critical_function=True,
    )
    inv = _inventory(systems=[sys])
    gaps = check_dora_compliance(inv, [])
    dr3_gaps = [g for g in gaps if g.rule_id == "DR-003"]
    assert dr3_gaps


def test_dr005_admin_interface():
    comp = Component(
        id=stable_id("component", "admin-portal"),
        name="Admin Portal",
        system_id=stable_id("system", "core"),
        is_admin_interface=True,
    )
    inv = _inventory(components=[comp])
    gaps = check_dora_compliance(inv, [])
    dr5_gaps = [g for g in gaps if g.rule_id == "DR-005"]
    assert dr5_gaps


def test_dr006_genai_pii():
    sys_id = stable_id("system", "fraud")
    comp = Component(
        id=stable_id("component", "fraud-model"),
        name="Fraud Model",
        system_id=sys_id,
        is_genai=True,
    )
    asset = DataAsset(
        id=stable_id("data_asset", "customer-data"),
        name="Customer Data",
        system_id=sys_id,
        contains_pii=True,
    )
    inv = _inventory(components=[comp], data_assets=[asset])
    gaps = check_dora_compliance(inv, [])
    dr6_gaps = [g for g in gaps if g.rule_id == "DR-006"]
    assert dr6_gaps


def test_all_gaps_cleared():
    sys_id = stable_id("system", "full-system")
    sys = System(id=sys_id, name="Full System")
    tp = ThirdParty(
        id=stable_id("third_party", "cleared-tp"),
        name="ClearedTP",
        has_exit_plan=True,
    )
    inv = _inventory(
        systems=[sys],
        third_parties=[tp],
    )
    log_finding = _finding(FindingCategory.LOGGING_MONITORING, [sys_id])
    gaps = check_dora_compliance(inv, [log_finding])
    assert not [g for g in gaps if g.rule_id in ("DR-001", "DR-002", "DR-003", "DR-004", "DR-005", "DR-006")]
