import pytest
import yaml

from riskos.evals import (
    CorpusError,
    CorpusSplit,
    EvalCase,
    EvalThresholds,
    evaluate_corpus,
    load_corpus,
)
from riskos.schemas.artifacts import Citation, FindingCategory
from tests.conftest import make_finding


def _case(case_id, split, golden, produced):
    return EvalCase(
        case_id=case_id,
        split=split,
        golden_findings=golden,
        produced_findings=produced,
    )


def test_corpus_aggregates_by_counts_not_case_average(evidence_doc):
    citation = [Citation(evidence_id=evidence_doc.evidence_id)]
    golden_large = [
        make_finding(FindingCategory.VULNERABILITY, [f"cmp-{index}"],
                     finding_id=f"g-{index}", band="high")
        for index in range(3)
    ]
    produced_large = [
        make_finding(FindingCategory.VULNERABILITY, [f"cmp-{index}"],
                     finding_id=f"p-{index}", band="high", citations=citation)
        for index in range(3)
    ]
    cases = [
        _case("large", CorpusSplit.REGRESSION, golden_large, produced_large),
        _case("miss", CorpusSplit.REGRESSION,
              [make_finding(FindingCategory.PRIVACY, ["dat-pii"], finding_id="g-miss")],
              []),
    ]

    report = evaluate_corpus(
        cases,
        thresholds=EvalThresholds(max_false_safe_rate=0.25, min_score_agreement=1.0),
    )

    assert report.case_count == 2
    assert report.false_safe_rate == 0.25
    assert report.precision == 1.0
    assert report.passed


def test_threshold_violation_fails_regression_gate():
    cases = [
        _case("miss", CorpusSplit.REGRESSION,
              [make_finding(FindingCategory.PRIVACY, ["dat-pii"], finding_id="g1")],
              [])
    ]

    report = evaluate_corpus(cases, thresholds=EvalThresholds())

    assert not report.passed
    assert report.violations == [
        "false_safe_rate 1.0000 violates threshold <= 0.0000"
    ]


def test_only_requested_split_is_evaluated():
    regression = _case("reg", CorpusSplit.REGRESSION, [], [])
    holdout = _case(
        "holdout",
        CorpusSplit.HOLDOUT,
        [make_finding(FindingCategory.PRIVACY, ["dat-pii"], finding_id="g1")],
        [],
    )

    report = evaluate_corpus([regression, holdout], split=CorpusSplit.REGRESSION)

    assert report.case_count == 1
    assert report.cases[0].case_id == "reg"


def test_load_corpus_rejects_duplicate_case_ids(tmp_path):
    case = _case("duplicate", CorpusSplit.REGRESSION, [], [])
    (tmp_path / "a.json").write_text(case.model_dump_json(), encoding="utf-8")
    (tmp_path / "b.json").write_text(case.model_dump_json(), encoding="utf-8")

    with pytest.raises(CorpusError, match="duplicate"):
        load_corpus(tmp_path)


def test_load_corpus_rejects_unsupported_schema_version(tmp_path):
    (tmp_path / "future.json").write_text(
        '{"schema_version":"2","case_id":"future","split":"regression"}',
        encoding="utf-8",
    )

    with pytest.raises(CorpusError, match="schema_version"):
        load_corpus(tmp_path)


def test_checked_in_regression_corpus_passes(repo_root):
    cases = load_corpus(repo_root / "evals" / "corpus")
    thresholds = EvalThresholds.model_validate(
        yaml.safe_load(
            (repo_root / "config" / "eval_thresholds.yaml").read_text(encoding="utf-8")
        )
    )

    report = evaluate_corpus(cases, thresholds=thresholds)

    assert report.passed
    assert report.case_count == 1
