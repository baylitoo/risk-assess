"""Deterministic, bounded coverage challenge loop."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from riskos.critic import CoverageGap, check_coverage
from riskos.schemas.artifacts import AssetInventory, RiskRegister

Revision = Callable[[RiskRegister, list[CoverageGap], int], RiskRegister]


@dataclass(frozen=True)
class ChallengeResult:
    register: RiskRegister
    iterations: int
    resolved: bool
    remaining_gaps: tuple[CoverageGap, ...]


def run_challenge_loop(
    inventory: AssetInventory,
    register: RiskRegister,
    revise: Revision,
    max_iterations: int = 2,
) -> ChallengeResult:
    """Revise a register until coverage passes or the bounded loop expires."""
    if max_iterations < 0:
        raise ValueError("max_iterations must be non-negative")

    current = register
    for iteration in range(1, max_iterations + 1):
        gaps = check_coverage(inventory, current.findings)
        if not gaps:
            return ChallengeResult(current, iteration - 1, True, ())
        revised = revise(current, gaps, iteration)
        if revised.assessment_id != current.assessment_id:
            raise ValueError("revision changed assessment_id")
        if revised.version <= current.version:
            raise ValueError("revision must increase artifact version")
        current = revised

    remaining = tuple(check_coverage(inventory, current.findings))
    return ChallengeResult(current, max_iterations, not remaining, remaining)
