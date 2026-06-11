"""Tests for the finding quality eval harness."""

import json

import pytest

from riskos.evals.findings import (
    FindingEvalCase,
    FindingEvalError,
    FindingEvalThresholds,
    evaluate_finding_case,
    evaluate_finding_corpus,
    load_finding_corpus,
)
from riskos.cli.riskfindingeval import main
from tests.conftest import make_finding
from riskos.schemas.artifacts import FindingCategory


def _make_case(case_id, split, golden, produced):
    return FindingEvalCase(
        case_id=case_id,
        split=split,
        golden_findings=golden,
        produced_findings=produced,
    )


def test_evaluate_finding_case_perfect_match():
    golden = [
        make_finding(FindingCategory.ABUSE_PREVENTION, ["cmp-api"], band="critical"),
        make_finding(FindingCategory.PRIVACY, ["dat-pii"], band="high"),
    ]
    case = _make_case("c1", "regression", golden, golden)
    result = evaluate_finding_case(case)

    assert result.false_safe_rate == 0.0
    assert result.missed_high_golden == 0
    assert result.coverage_pass_rate == 1.0


def test_evaluate_finding_case_missed_critical():
    golden = [
        make_finding(FindingCategory.ABUSE_PREVENTION, ["cmp-api"],
                     finding_id="g1", band="critical"),
        make_finding(FindingCategory.PRIVACY, ["dat-pii"],
                     finding_id="g2", band="medium"),
    ]
    produced = [
        make_finding(FindingCategory.PRIVACY, ["dat-pii"],
                     finding_id="p1", band="medium"),
    ]
    case = _make_case("c1", "regression", golden, produced)
    result = evaluate_finding_case(case)

    assert result.missed_high_golden == 1
    assert result.false_safe_rate == 1.0
    assert "g1" in result.missed_high_golden_ids


def test_medium_findings_not_counted_in_false_safe():
    golden = [
        make_finding(FindingCategory.THIRD_PARTY, ["thp-1"],
                     finding_id="g1", band="medium"),
    ]
    produced = []  # missed medium finding
    case = _make_case("c1", "regression", golden, produced)
    result = evaluate_finding_case(case)

    assert result.false_safe_rate == 0.0  # medium not in HIGH+ set
    assert result.high_golden_total == 0


def test_evaluate_finding_corpus_passes_regression_fixture(repo_root):
    cases = load_finding_corpus(repo_root / "evals" / "findings" / "regression")
    report = evaluate_finding_corpus(
        cases,
        split="regression",
        thresholds=FindingEvalThresholds(
            max_false_safe_rate=0.0,
            min_coverage_pass_rate=1.0,
            min_band_agreement=0.8,
        ),
    )

    assert report.passed is True
    assert report.false_safe_rate == 0.0


def test_evaluate_finding_corpus_raises_on_wrong_split(repo_root):
    cases = load_finding_corpus(repo_root / "evals" / "findings" / "regression")
    with pytest.raises(FindingEvalError, match="no finding eval cases"):
        evaluate_finding_corpus(cases, split="holdout")


def test_cli_passes_regression_fixture(capsys, repo_root):
    code = main([str(repo_root / "evals" / "findings" / "regression")])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["passed"] is True


def test_cli_returns_one_for_quality_gate_failure(tmp_path, capsys):
    case = {
        "case_id": "missed-critical",
        "split": "regression",
        "golden_findings": [
            {
                "finding_id": "g1",
                "title": "critical finding",
                "category": "abuse_prevention",
                "scenario": "test",
                "affected_asset_ids": ["cmp-api"],
                "band": "critical",
            }
        ],
        "produced_findings": [],
    }
    (tmp_path / "case.json").write_text(json.dumps(case), encoding="utf-8")

    code = main([str(tmp_path)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["passed"] is False
    assert payload["violations"]


def test_cli_returns_two_for_invalid_corpus(tmp_path, capsys):
    code = main([str(tmp_path)])
    payload = json.loads(capsys.readouterr().err)
    assert code == 2
    assert "no finding eval cases" in payload["error"]
