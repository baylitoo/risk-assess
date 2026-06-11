"""Finding quality eval harness — parallel to evals/corpus.py for threat findings."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from riskos.evals.metrics import EvalReport, evaluate_register
from riskos.schemas.artifacts import RiskFinding

_HIGH_BANDS = {"high", "very_high", "critical"}


class FindingEvalError(Exception):
    pass


class FindingEvalCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"] = "1"
    case_id: str
    split: str  # dev / regression / holdout
    description: str = ""
    golden_findings: list[RiskFinding] = Field(default_factory=list)
    produced_findings: list[RiskFinding] = Field(default_factory=list)


class FindingEvalThresholds(BaseModel):
    """Quality gates — false_safe_rate is the primary KPI."""

    model_config = ConfigDict(extra="forbid")

    max_false_safe_rate: float = Field(default=0.05, ge=0.0, le=1.0)
    min_coverage_pass_rate: float = Field(default=0.90, ge=0.0, le=1.0)
    min_band_agreement: float = Field(default=0.80, ge=0.0, le=1.0)


class FindingCaseEvalResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    split: str
    golden_total: int
    produced_total: int
    high_golden_total: int
    missed_high_golden: int
    false_safe_rate: float
    coverage_pass_rate: float
    band_agreement: float
    missed_high_golden_ids: list[str]


class FindingEvalReport(BaseModel):
    """Aggregate eval report across a finding corpus split."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"] = "1"
    split: str
    case_count: int
    golden_total: int
    produced_total: int
    high_golden_total: int
    missed_high_golden: int
    false_safe_rate: float      # missed HIGH/CRITICAL / total HIGH/CRITICAL golden
    coverage_pass_rate: float   # matched golden / total golden (all severities)
    band_agreement: float       # matched pairs within ±1 band / total matched pairs
    passed: bool
    violations: list[str] = Field(default_factory=list)
    cases: list[FindingCaseEvalResult] = Field(default_factory=list)


def evaluate_finding_case(case: FindingEvalCase) -> FindingCaseEvalResult:
    base = evaluate_register(case.golden_findings, case.produced_findings)

    high_goldens = [f for f in case.golden_findings if f.band in _HIGH_BANDS]
    missed_high = [fid for fid in base.missed_golden_ids
                   if any(f.finding_id == fid and f.band in _HIGH_BANDS
                          for f in case.golden_findings)]
    false_safe_rate = _ratio(len(missed_high), len(high_goldens))
    coverage_pass_rate = _ratio(base.matched_golden, base.golden_total)

    return FindingCaseEvalResult(
        case_id=case.case_id,
        split=case.split,
        golden_total=base.golden_total,
        produced_total=base.produced_total,
        high_golden_total=len(high_goldens),
        missed_high_golden=len(missed_high),
        false_safe_rate=false_safe_rate,
        coverage_pass_rate=coverage_pass_rate,
        band_agreement=base.score_agreement,
        missed_high_golden_ids=missed_high,
    )


def load_finding_corpus(directory: str | Path) -> list[FindingEvalCase]:
    """Load all versioned JSON finding eval cases below a corpus directory."""
    root = Path(directory)
    if not root.is_dir():
        raise FindingEvalError(f"finding corpus directory not found: {root}")
    cases: list[FindingEvalCase] = []
    seen: set[str] = set()
    for path in sorted(root.rglob("*.json")):
        try:
            case = FindingEvalCase.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise FindingEvalError(f"invalid finding eval case {path}: {exc}") from exc
        if case.case_id in seen:
            raise FindingEvalError(f"duplicate finding eval case_id {case.case_id!r}")
        seen.add(case.case_id)
        cases.append(case)
    if not cases:
        raise FindingEvalError(f"no finding eval cases found in {root}")
    return cases


def evaluate_finding_corpus(
    cases: list[FindingEvalCase],
    split: str = "regression",
    thresholds: FindingEvalThresholds | None = None,
) -> FindingEvalReport:
    """Evaluate one split and enforce aggregate quality gates."""
    selected = [c for c in cases if c.split == split]
    if not selected:
        raise FindingEvalError(f"no finding eval cases found for split {split!r}")

    thresholds = thresholds or FindingEvalThresholds()
    case_results = [evaluate_finding_case(c) for c in selected]

    golden_total = sum(r.golden_total for r in case_results)
    produced_total = sum(r.produced_total for r in case_results)
    high_golden_total = sum(r.high_golden_total for r in case_results)
    missed_high_golden = sum(r.missed_high_golden for r in case_results)
    matched_golden = sum(r.golden_total - r.high_golden_total
                        + (r.high_golden_total - r.missed_high_golden)
                        for r in case_results)

    false_safe_rate = _ratio(missed_high_golden, high_golden_total)
    coverage_pass_rate = _ratio(
        sum(r.golden_total for r in case_results if r.coverage_pass_rate >= 1.0),
        len(case_results),
        default=1.0,
    )
    band_agreement = _ratio(
        sum(r.band_agreement * r.golden_total for r in case_results),
        sum(r.golden_total for r in case_results),
        default=1.0,
    )

    violations = _threshold_violations(
        false_safe_rate, coverage_pass_rate, band_agreement, thresholds
    )
    return FindingEvalReport(
        split=split,
        case_count=len(case_results),
        golden_total=golden_total,
        produced_total=produced_total,
        high_golden_total=high_golden_total,
        missed_high_golden=missed_high_golden,
        false_safe_rate=false_safe_rate,
        coverage_pass_rate=coverage_pass_rate,
        band_agreement=band_agreement,
        passed=not violations,
        violations=violations,
        cases=case_results,
    )


def _threshold_violations(
    false_safe_rate: float,
    coverage_pass_rate: float,
    band_agreement: float,
    thresholds: FindingEvalThresholds,
) -> list[str]:
    checks = (
        ("false_safe_rate", false_safe_rate, "<=", thresholds.max_false_safe_rate),
        (
            "coverage_pass_rate",
            coverage_pass_rate,
            ">=",
            thresholds.min_coverage_pass_rate,
        ),
        ("band_agreement", band_agreement, ">=", thresholds.min_band_agreement),
    )
    return [
        f"{name} {actual:.4f} violates threshold {operator} {expected:.4f}"
        for name, actual, operator, expected in checks
        if (operator == "<=" and actual > expected)
        or (operator == ">=" and actual < expected)
    ]


def _ratio(num: float, den: float, default: float = 0.0) -> float:
    return round(num / den, 4) if den else default
