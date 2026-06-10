"""Tests for inventory extraction eval — entity-level precision/recall."""

import pytest

from riskos.evals import EntityEval, InventoryEvalReport, evaluate_inventory
from riskos.ids import stable_id
from riskos.schemas.artifacts import AssetInventory, Producer
from riskos.schemas.entities import Component, DataAsset, Exposure, System, ThirdParty


def _producer():
    return Producer(agent="test")


def _inventory(
    *,
    systems=(),
    components=(),
    data_assets=(),
    third_parties=(),
    assessment_id: str = "asmnt-test",
) -> AssetInventory:
    return AssetInventory(
        artifact_id=stable_id("artifact", assessment_id, "inventory"),
        assessment_id=assessment_id,
        phase="intake",
        producer=_producer(),
        systems=list(systems),
        components=list(components),
        data_assets=list(data_assets),
        third_parties=list(third_parties),
    )


def _system(name: str, aid: str = "asmnt-test") -> System:
    return System(id=stable_id("system", aid, name), name=name)


def _component(name: str, sys_id: str = "sys-test") -> Component:
    return Component(id=stable_id("component", sys_id, name), name=name, system_id=sys_id)


def _data_asset(name: str, sys_id: str = "sys-test") -> DataAsset:
    return DataAsset(id=stable_id("data_asset", sys_id, name), name=name, system_id=sys_id)


def _third_party(name: str) -> ThirdParty:
    return ThirdParty(id=stable_id("third_party", name), name=name)


# -- perfect match -----------------------------------------------------------

def test_perfect_match():
    golden = _inventory(systems=[_system("Payments Hub")], components=[_component("REST API")])
    produced = _inventory(systems=[_system("Payments Hub")], components=[_component("REST API")])

    report = evaluate_inventory(golden, produced)

    assert report.aggregate_precision == 1.0
    assert report.aggregate_recall == 1.0
    assert report.aggregate_f1 == 1.0
    assert report.by_type["system"].missed_names == []
    assert report.by_type["system"].spurious_names == []


# -- name normalisation ------------------------------------------------------

def test_name_normalisation_treats_punctuation_as_whitespace():
    golden = _inventory(systems=[_system("Payments-Hub")])
    produced = _inventory(systems=[_system("Payments Hub")])

    report = evaluate_inventory(golden, produced)

    assert report.by_type["system"].matched == 1
    assert report.aggregate_recall == 1.0


def test_name_normalisation_is_case_insensitive():
    golden = _inventory(systems=[_system("PAYMENTS HUB")])
    produced = _inventory(systems=[_system("payments hub")])

    report = evaluate_inventory(golden, produced)

    assert report.by_type["system"].matched == 1


# -- missed and spurious -----------------------------------------------------

def test_missed_golden_entity():
    golden = _inventory(systems=[_system("Alpha"), _system("Beta")])
    produced = _inventory(systems=[_system("Alpha")])

    report = evaluate_inventory(golden, produced)

    assert report.by_type["system"].recall == 0.5
    assert "beta" in report.by_type["system"].missed_names


def test_spurious_produced_entity():
    golden = _inventory(systems=[_system("Alpha")])
    produced = _inventory(systems=[_system("Alpha"), _system("Gamma")])

    report = evaluate_inventory(golden, produced)

    assert report.by_type["system"].precision == 0.5
    assert "gamma" in report.by_type["system"].spurious_names


# -- empty cases -------------------------------------------------------------

def test_empty_golden_gives_full_recall():
    golden = _inventory()
    produced = _inventory(systems=[_system("Ghost System")])

    report = evaluate_inventory(golden, produced)

    assert report.by_type["system"].recall == 1.0
    assert report.by_type["system"].precision == 0.0


def test_empty_produced_gives_zero_precision_and_zero_recall():
    golden = _inventory(systems=[_system("Core System")])
    produced = _inventory()

    report = evaluate_inventory(golden, produced)

    assert report.by_type["system"].precision == 0.0
    assert report.by_type["system"].recall == 0.0


def test_both_empty_gives_perfect_score():
    report = evaluate_inventory(_inventory(), _inventory())

    assert report.aggregate_precision == 0.0
    assert report.aggregate_recall == 1.0


# -- multi-type aggregate ----------------------------------------------------

def test_aggregate_across_entity_types():
    golden = _inventory(
        systems=[_system("S1")],
        data_assets=[_data_asset("D1"), _data_asset("D2")],
    )
    produced = _inventory(
        systems=[_system("S1")],
        data_assets=[_data_asset("D1")],
    )

    report = evaluate_inventory(golden, produced)

    # 2 matched out of 3 golden total → recall = 2/3
    assert report.aggregate_recall == pytest.approx(2 / 3, abs=1e-4)
    # 2 matched out of 2 produced total → precision = 1.0
    assert report.aggregate_precision == 1.0


# -- third parties -----------------------------------------------------------

def test_third_party_matching():
    golden = _inventory(third_parties=[_third_party("Acme KYC"), _third_party("CloudStorage")])
    produced = _inventory(third_parties=[_third_party("acme-kyc"), _third_party("Unused Vendor")])

    report = evaluate_inventory(golden, produced)

    tp = report.by_type["third_party"]
    assert tp.matched == 1
    assert "cloud storage" in tp.missed_names or "cloudstorage" in tp.missed_names
