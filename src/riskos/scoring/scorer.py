"""Deterministic risk scorer.

The model assesses qualitative factor *levels* under a rubric; this module
turns them into the bank's 1–25 scale. The model never emits a number.
The methodology lives in ``config/risk_matrix.yaml`` and is versioned —
score(finding, matrix_v1) is reproducible forever.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from riskos.schemas.artifacts import RiskFinding

_BAND_ORDER = ["low", "medium", "high", "very_high", "critical"]


class ScoringError(Exception):
    pass


class RiskScorer:
    def __init__(self, matrix: dict):
        self.matrix = matrix
        self.methodology_version: str = str(matrix["methodology_version"])

    @classmethod
    def load(cls, path: str | Path) -> "RiskScorer":
        return cls(yaml.safe_load(Path(path).read_text(encoding="utf-8")))

    # -- factor resolution -------------------------------------------------

    def _factor_points(self, table_name: str, factor: str, level: str) -> int:
        table = self.matrix["likelihood_factors"][factor]
        if level not in table:
            raise ScoringError(
                f"finding factor {factor}={level!r} not in methodology "
                f"(allowed: {sorted(table)})"
            )
        return int(table[level])

    def likelihood_level(self, factors: dict[str, str]) -> int:
        required = set(self.matrix["likelihood_factors"])
        missing = required - set(factors)
        if missing:
            raise ScoringError(f"missing likelihood factors: {sorted(missing)}")
        points = sum(
            self._factor_points("likelihood_factors", f, factors[f]) for f in required
        )
        for row in self.matrix["likelihood_levels"]:
            if points <= int(row["max_points"]):
                return int(row["level"])
        raise ScoringError(f"no likelihood level for {points} points")

    def impact_level(self, factors: dict[str, str]) -> int:
        level = factors.get("impact")
        table = self.matrix["impact_factor"]
        if level not in table:
            raise ScoringError(
                f"impact={level!r} not in methodology (allowed: {sorted(table)})"
            )
        return int(table[level])

    def band(self, score: int) -> str:
        for row in self.matrix["bands"]:
            if score <= int(row["max_score"]):
                return str(row["band"])
        raise ScoringError(f"no band for score {score}")

    # -- public API ---------------------------------------------------------

    def score(self, finding: RiskFinding) -> RiskFinding:
        """Fill inherent/residual scores + band. Returns a new finding."""
        likelihood = self.likelihood_level(finding.factors)
        impact = self.impact_level(finding.factors)
        inherent = likelihood * impact

        strength = finding.factors.get("control_strength", "absent")
        reduction_table = self.matrix["control_strength_reduction"]
        if strength not in reduction_table:
            raise ScoringError(
                f"control_strength={strength!r} not in methodology "
                f"(allowed: {sorted(reduction_table)})"
            )
        residual_likelihood = max(1, likelihood - int(reduction_table[strength]))
        residual = residual_likelihood * impact

        return finding.model_copy(
            update={
                "inherent_score": inherent,
                "residual_score": residual,
                "band": self.band(residual),
            }
        )

    @staticmethod
    def band_distance(band_a: str, band_b: str) -> int:
        try:
            return abs(_BAND_ORDER.index(band_a) - _BAND_ORDER.index(band_b))
        except ValueError as exc:
            raise ScoringError(f"unknown band in {band_a!r}/{band_b!r}") from exc
