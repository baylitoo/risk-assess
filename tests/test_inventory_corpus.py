"""Tests for inventory eval corpus loader and aggregate evaluation."""

import json
from pathlib import Path

import pytest

from riskos.evals.inventory import (
    InventoryCorpusError,
    InventoryEvalCase,
    InventoryEvalThresholds,
    InventorySplit,
    evaluate_inventory_corpus,
    load_inventory_corpus,
)
from tests.conftest import REPO_ROOT

FIXTURE_DIR = REPO_ROOT / "evals" / "inventory"


# -- fixture loading ---------------------------------------------------------

def test_load_dev_fixture():
    cases = load_inventory_corpus(FIXTURE_DIR)
    dev = [c for c in cases if c.split == InventorySplit.DEV]
    assert any(c.case_id == "payments-hub-dev-001" for c in dev)


def test_load_regression_fixture():
    cases = load_inventory_corpus(FIXTURE_DIR)
    reg = [c for c in cases if c.split == InventorySplit.REGRESSION]
    assert any(c.case_id == "core-banking-reg-001" for c in reg)


def test_fixture_golden_inventory_is_valid(tmp_path):
    cases = load_inventory_corpus(FIXTURE_DIR)
    case = next(c for c in cases if c.case_id == "payments-hub-dev-001")
    inv = case.golden_inventory
    assert any(s.name == "Payments Hub" for s in inv.systems)
    assert any(c.is_genai for c in inv.components)
    assert any(d.contains_pii for d in inv.data_assets)
    assert len(inv.third_parties) >= 1
    assert len(inv.controls) >= 1


def test_load_raises_on_missing_directory():
    with pytest.raises(InventoryCorpusError, match="not found"):
        load_inventory_corpus("/does/not/exist")


def test_load_raises_on_duplicate_case_ids(tmp_path):
    case = load_inventory_corpus(FIXTURE_DIR)[0]
    data = json.loads(case.model_dump_json())
    (tmp_path / "a.json").write_text(json.dumps(data), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(InventoryCorpusError, match="duplicate"):
        load_inventory_corpus(tmp_path)


def test_load_raises_on_empty_directory(tmp_path):
    with pytest.raises(InventoryCorpusError, match="no eval cases"):
        load_inventory_corpus(tmp_path)


# -- corpus evaluation -------------------------------------------------------

def _case_with_perfect_produced(base_case: InventoryEvalCase) -> InventoryEvalCase:
    return base_case.model_copy(update={"produced_inventory": base_case.golden_inventory})


def test_corpus_eval_requires_produced_inventory():
    cases = load_inventory_corpus(FIXTURE_DIR)
    reg = [c for c in cases if c.split == InventorySplit.REGRESSION]
    with pytest.raises(InventoryCorpusError, match="no scoreable"):
        evaluate_inventory_corpus(reg, split=InventorySplit.REGRESSION)


def test_corpus_eval_perfect_score(tmp_path):
    cases = load_inventory_corpus(FIXTURE_DIR)
    reg = [c for c in cases if c.split == InventorySplit.REGRESSION]
    scored = [_case_with_perfect_produced(c) for c in reg]

    report = evaluate_inventory_corpus(scored, split=InventorySplit.REGRESSION)

    assert report.aggregate_recall == 1.0
    assert report.aggregate_precision == 1.0
    assert report.passed is True


def test_corpus_eval_threshold_passes_on_perfect_score():
    cases = load_inventory_corpus(FIXTURE_DIR)
    reg = [c for c in cases if c.split == InventorySplit.REGRESSION]
    scored = [_case_with_perfect_produced(c) for c in reg]

    report = evaluate_inventory_corpus(
        scored, split=InventorySplit.REGRESSION,
        thresholds=InventoryEvalThresholds(min_recall=1.0, min_precision=1.0, min_f1=0.99),
    )
    assert report.passed is True


def test_corpus_eval_threshold_fails_on_partial_match():
    cases = load_inventory_corpus(FIXTURE_DIR)
    reg = [c for c in cases if c.split == InventorySplit.REGRESSION]
    base = reg[0]
    # Produced inventory is missing all components → F1 will be well below 0.99
    partial = base.model_copy(update={
        "produced_inventory": base.golden_inventory.model_copy(update={"components": []}),
    })

    report = evaluate_inventory_corpus(
        [partial], split=InventorySplit.REGRESSION,
        thresholds=InventoryEvalThresholds(min_f1=0.99),
    )
    assert report.passed is False
    assert any("f1" in v for v in report.violations)


# -- CLI smoke test ----------------------------------------------------------

def test_riskextracteval_cli_no_produced_exits_2():
    from riskos.cli.riskextracteval import main
    result = main([str(FIXTURE_DIR), "--split", "regression"])
    assert result == 2
