"""Eval metrics — designed for a 200-pack corpus, fed with what we have.

KPI hierarchy (ROADMAP §5):
  0. false_safe_rate        — golden findings the system missed. THE metric.
  1. unsupported_critical_rate — high+ findings with no grounding.
  2. score_agreement        — matched findings within ±1 band of the signed register.
  3. precision              — produced findings that match a golden finding.

Matching is deliberately conservative: a produced finding matches a golden
finding when categories are equal and affected assets overlap. Stable
entity IDs (riskos.ids) are what make asset overlap meaningful across
runs — this is why identity ships before the graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from riskos.schemas.artifacts import RiskFinding
from riskos.scoring.scorer import RiskScorer

_HIGH_BANDS = {"high", "very_high", "critical"}


@dataclass
class EvalReport:
    golden_total: int
    produced_total: int
    matched_golden: int
    matched_produced: int
    false_safe_rate: float            # missed golden / golden_total
    precision: float                  # matched produced / produced_total
    unsupported_critical_rate: float  # ungrounded high+ / high+ produced
    score_agreement: float            # matched pairs within ±1 band
    missed_golden_ids: list[str] = field(default_factory=list)
    unsupported_critical_ids: list[str] = field(default_factory=list)


def _matches(golden: RiskFinding, produced: RiskFinding) -> bool:
    if golden.category != produced.category:
        return False
    return bool(set(golden.affected_asset_ids) & set(produced.affected_asset_ids))


def evaluate_register(
    golden: list[RiskFinding],
    produced: list[RiskFinding],
) -> EvalReport:
    matched_pairs: list[tuple[RiskFinding, RiskFinding]] = []
    missed: list[str] = []
    claimed_produced: set[str] = set()

    for g in golden:
        match = next(
            (p for p in produced
             if p.finding_id not in claimed_produced and _matches(g, p)),
            None,
        )
        if match is None:
            missed.append(g.finding_id)
        else:
            claimed_produced.add(match.finding_id)
            matched_pairs.append((g, match))

    high_produced = [p for p in produced if p.band in _HIGH_BANDS]
    unsupported = [p.finding_id for p in high_produced if not p.citations]

    agree = 0
    comparable = 0
    for g, p in matched_pairs:
        if g.band and p.band:
            comparable += 1
            if RiskScorer.band_distance(g.band, p.band) <= 1:
                agree += 1

    return EvalReport(
        golden_total=len(golden),
        produced_total=len(produced),
        matched_golden=len(matched_pairs),
        matched_produced=len(claimed_produced),
        false_safe_rate=_ratio(len(missed), len(golden)),
        precision=_ratio(len(claimed_produced), len(produced)),
        unsupported_critical_rate=_ratio(len(unsupported), len(high_produced)),
        score_agreement=_ratio(agree, comparable, default=1.0),
        missed_golden_ids=missed,
        unsupported_critical_ids=unsupported,
    )


def _ratio(num: int, den: int, default: float = 0.0) -> float:
    return round(num / den, 4) if den else default
