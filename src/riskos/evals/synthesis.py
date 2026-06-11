"""Synthesis phase eval harness — runs synthesize_register against golden findings."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from riskos.evals.findings import (
    FindingEvalCase,
    FindingEvalError,
    FindingEvalThresholds,
    evaluate_finding_case,
)
from riskos.gateway import StructuredGenerationGateway
from riskos.schemas.artifacts import (
    AssetInventory,
    AssessmentScope,
    Producer,
    RiskRegister,
    VulnerabilityFindings,
)
from riskos.scoring.scorer import RiskScorer
from riskos.synthesis.synthesizer import synthesize_register

_HIGH_BANDS = {"high", "very_high", "critical"}


class SynthesisEvalCase(BaseModel):
    """A single synthesis eval case: inputs + expected golden output."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"] = "1"
    case_id: str
    split: str
    description: str = ""
    golden_eval: FindingEvalCase


class SynthesisEvalResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    split: str
    false_safe_rate: float
    band_agreement: float
    challenge_convergence_rate: float
    challenge_iterations: int
    coverage_resolved: bool
    produced_finding_count: int
    golden_finding_count: int


class SynthesisCorpusEvalReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"] = "1"
    split: str
    case_count: int
    false_safe_rate: float
    band_agreement: float
    challenge_convergence_rate: float
    passed: bool
    violations: list[str] = Field(default_factory=list)
    cases: list[SynthesisEvalResult] = Field(default_factory=list)


def evaluate_synthesis(
    inventory: AssetInventory,
    threat_register: RiskRegister,
    scope: AssessmentScope,
    gateway: StructuredGenerationGateway,
    golden_findings_eval_case: FindingEvalCase,
    risk_matrix_path: str = "config/risk_matrix.yaml",
    max_challenge_iterations: int = 2,
) -> SynthesisEvalResult:
    """Run synthesize_register and compare output against golden findings."""
    scorer = RiskScorer.load(risk_matrix_path)
    producer = Producer(agent="synthesis_eval")

    final_register, challenge_result = synthesize_register(
        inventory=inventory,
        threat_register=threat_register,
        vuln_findings=None,
        scope=scope,
        gateway=gateway,
        scorer=scorer,
        producer=producer,
        route="synthesis",
        prompt_version="eval",
        max_challenge_iterations=max_challenge_iterations,
    )

    eval_case = golden_findings_eval_case.model_copy(
        update={"produced_findings": final_register.findings}
    )
    case_result = evaluate_finding_case(eval_case)

    challenge_convergence_rate = 1.0 if challenge_result.resolved else 0.0

    return SynthesisEvalResult(
        case_id=golden_findings_eval_case.case_id,
        split=golden_findings_eval_case.split,
        false_safe_rate=case_result.false_safe_rate,
        band_agreement=case_result.band_agreement,
        challenge_convergence_rate=challenge_convergence_rate,
        challenge_iterations=challenge_result.iterations,
        coverage_resolved=challenge_result.resolved,
        produced_finding_count=len(final_register.findings),
        golden_finding_count=len(golden_findings_eval_case.golden_findings),
    )


def evaluate_synthesis_corpus(
    cases: list[SynthesisEvalResult],
    split: str = "regression",
    thresholds: FindingEvalThresholds | None = None,
) -> SynthesisCorpusEvalReport:
    """Aggregate synthesis eval results and enforce quality gates."""
    selected = [c for c in cases if c.split == split]
    if not selected:
        raise FindingEvalError(f"no synthesis eval cases for split {split!r}")

    thresholds = thresholds or FindingEvalThresholds()

    false_safe_rate = _wavg(selected, "false_safe_rate")
    band_agreement = _wavg(selected, "band_agreement")
    convergence_rate = _wavg(selected, "challenge_convergence_rate")

    violations = []
    if false_safe_rate > thresholds.max_false_safe_rate:
        violations.append(
            f"false_safe_rate {false_safe_rate:.4f} violates threshold <= "
            f"{thresholds.max_false_safe_rate:.4f}"
        )
    if convergence_rate < thresholds.min_coverage_pass_rate:
        violations.append(
            f"challenge_convergence_rate {convergence_rate:.4f} violates threshold >= "
            f"{thresholds.min_coverage_pass_rate:.4f}"
        )

    return SynthesisCorpusEvalReport(
        split=split,
        case_count=len(selected),
        false_safe_rate=false_safe_rate,
        band_agreement=band_agreement,
        challenge_convergence_rate=convergence_rate,
        passed=not violations,
        violations=violations,
        cases=selected,
    )


def _wavg(cases: list[SynthesisEvalResult], attr: str) -> float:
    if not cases:
        return 0.0
    total = sum(getattr(c, attr) for c in cases)
    return round(total / len(cases), 4)
