"""Versioned corpus loader and aggregate regression evaluation."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from riskos.evals.metrics import EvalReport, evaluate_register
from riskos.schemas.artifacts import RiskFinding


class CorpusError(Exception):
    pass


class CorpusSplit(StrEnum):
    DEV = "dev"
    REGRESSION = "regression"
    HOLDOUT = "holdout"


class EvalCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"] = "1"
    case_id: str
    split: CorpusSplit
    description: str = ""
    golden_findings: list[RiskFinding] = Field(default_factory=list)
    produced_findings: list[RiskFinding] = Field(default_factory=list)


class EvalThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_false_safe_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    max_unsupported_critical_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    min_precision: float = Field(default=0.0, ge=0.0, le=1.0)
    min_score_agreement: float = Field(default=1.0, ge=0.0, le=1.0)


class CaseEvalResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    split: CorpusSplit
    golden_total: int
    produced_total: int
    matched_golden: int
    false_safe_rate: float
    precision: float
    unsupported_critical_rate: float
    score_agreement: float
    missed_golden_ids: list[str]
    unsupported_critical_ids: list[str]


class CorpusEvalReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"] = "1"
    split: CorpusSplit
    case_count: int
    golden_total: int
    produced_total: int
    matched_golden: int
    matched_produced: int
    false_safe_rate: float
    precision: float
    unsupported_critical_rate: float
    score_agreement: float
    passed: bool
    violations: list[str] = Field(default_factory=list)
    cases: list[CaseEvalResult] = Field(default_factory=list)


def load_corpus(directory: str | Path) -> list[EvalCase]:
    """Load all versioned JSON eval cases below a corpus directory."""
    root = Path(directory)
    if not root.is_dir():
        raise CorpusError(f"corpus directory not found: {root}")

    cases: list[EvalCase] = []
    seen: set[str] = set()
    for path in sorted(root.rglob("*.json")):
        try:
            case = EvalCase.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise CorpusError(f"invalid eval case {path}: {exc}") from exc
        if case.case_id in seen:
            raise CorpusError(f"duplicate eval case_id {case.case_id!r}")
        seen.add(case.case_id)
        cases.append(case)
    if not cases:
        raise CorpusError(f"no eval cases found in {root}")
    return cases


def evaluate_corpus(
    cases: list[EvalCase],
    split: CorpusSplit = CorpusSplit.REGRESSION,
    thresholds: EvalThresholds | None = None,
) -> CorpusEvalReport:
    """Evaluate one corpus split and enforce aggregate release thresholds."""
    selected = [case for case in cases if case.split == split]
    if not selected:
        raise CorpusError(f"no eval cases found for split {split.value!r}")

    reports = [
        (case, evaluate_register(case.golden_findings, case.produced_findings))
        for case in selected
    ]
    golden_total = sum(report.golden_total for _, report in reports)
    produced_total = sum(report.produced_total for _, report in reports)
    matched_golden = sum(report.matched_golden for _, report in reports)
    matched_produced = sum(report.matched_produced for _, report in reports)
    high_total = sum(report.high_produced_total for _, report in reports)
    unsupported_total = sum(
        len(report.unsupported_critical_ids) for _, report in reports
    )
    comparable = sum(report.comparable_scores for _, report in reports)
    agreed = sum(report.agreed_scores for _, report in reports)

    false_safe_rate = _ratio(golden_total - matched_golden, golden_total)
    precision = _ratio(matched_produced, produced_total)
    unsupported_rate = _ratio(unsupported_total, high_total)
    score_agreement = _ratio(agreed, comparable, default=1.0)
    thresholds = thresholds or EvalThresholds()
    violations = _threshold_violations(
        false_safe_rate, precision, unsupported_rate, score_agreement, thresholds
    )

    return CorpusEvalReport(
        split=split,
        case_count=len(reports),
        golden_total=golden_total,
        produced_total=produced_total,
        matched_golden=matched_golden,
        matched_produced=matched_produced,
        false_safe_rate=false_safe_rate,
        precision=precision,
        unsupported_critical_rate=unsupported_rate,
        score_agreement=score_agreement,
        passed=not violations,
        violations=violations,
        cases=[_case_result(case, report) for case, report in reports],
    )


def _case_result(case: EvalCase, report: EvalReport) -> CaseEvalResult:
    return CaseEvalResult(
        case_id=case.case_id,
        split=case.split,
        golden_total=report.golden_total,
        produced_total=report.produced_total,
        matched_golden=report.matched_golden,
        false_safe_rate=report.false_safe_rate,
        precision=report.precision,
        unsupported_critical_rate=report.unsupported_critical_rate,
        score_agreement=report.score_agreement,
        missed_golden_ids=report.missed_golden_ids,
        unsupported_critical_ids=report.unsupported_critical_ids,
    )


def _threshold_violations(
    false_safe_rate: float,
    precision: float,
    unsupported_rate: float,
    score_agreement: float,
    thresholds: EvalThresholds,
) -> list[str]:
    checks = (
        ("false_safe_rate", false_safe_rate, "<=", thresholds.max_false_safe_rate),
        (
            "unsupported_critical_rate",
            unsupported_rate,
            "<=",
            thresholds.max_unsupported_critical_rate,
        ),
        ("precision", precision, ">=", thresholds.min_precision),
        ("score_agreement", score_agreement, ">=", thresholds.min_score_agreement),
    )
    return [
        f"{name} {actual:.4f} violates threshold {operator} {expected:.4f}"
        for name, actual, operator, expected in checks
        if (operator == "<=" and actual > expected)
        or (operator == ">=" and actual < expected)
    ]


def _ratio(num: int, den: int, default: float = 0.0) -> float:
    return round(num / den, 4) if den else default
