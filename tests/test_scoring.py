import pytest

from riskos.schemas.artifacts import FindingCategory
from riskos.scoring import RiskScorer, ScoringError
from tests.conftest import REPO_ROOT, make_finding


@pytest.fixture(scope="module")
def scorer() -> RiskScorer:
    return RiskScorer.load(REPO_ROOT / "config" / "risk_matrix.yaml")


def _factors(**overrides) -> dict[str, str]:
    base = {
        "exposure": "internet_facing",
        "exploitability": "weaponized",
        "threat_activity": "high",
        "impact": "major",
        "control_strength": "absent",
    }
    base.update(overrides)
    return base


def test_worst_case_scores_critical(scorer):
    f = make_finding(FindingCategory.VULNERABILITY, ["cmp-x"],
                     factors=_factors(impact="severe"))
    scored = scorer.score(f)
    assert scored.inherent_score == 25
    assert scored.residual_score == 25
    assert scored.band == "critical"


def test_controls_reduce_residual_not_inherent(scorer):
    f = make_finding(FindingCategory.VULNERABILITY, ["cmp-x"],
                     factors=_factors(control_strength="strong"))
    scored = scorer.score(f)
    assert scored.inherent_score == 20      # L5 × I4
    assert scored.residual_score == 12      # L(5-2)=3 × I4
    assert scored.band == "high"


def test_residual_likelihood_floors_at_one(scorer):
    f = make_finding(
        FindingCategory.VULNERABILITY, ["cmp-x"],
        factors=_factors(exposure="internal", exploitability="theoretical",
                         threat_activity="low", impact="minor",
                         control_strength="strong"),
    )
    scored = scorer.score(f)
    assert scored.residual_score == 2       # L floors at 1 × I2
    assert scored.band == "low"


def test_scoring_is_pure_and_reproducible(scorer):
    f = make_finding(FindingCategory.VULNERABILITY, ["cmp-x"], factors=_factors())
    assert scorer.score(f) == scorer.score(f)
    assert f.inherent_score is None         # original untouched


def test_model_cannot_invent_factor_levels(scorer):
    # The model proposing a level outside the methodology is a hard error,
    # not a silent default — methodology drift defense.
    f = make_finding(FindingCategory.VULNERABILITY, ["cmp-x"],
                     factors=_factors(exploitability="super_bad"))
    with pytest.raises(ScoringError, match="exploitability"):
        scorer.score(f)


def test_missing_factor_is_a_hard_error(scorer):
    factors = _factors()
    del factors["threat_activity"]
    f = make_finding(FindingCategory.VULNERABILITY, ["cmp-x"], factors=factors)
    with pytest.raises(ScoringError, match="missing"):
        scorer.score(f)


def test_methodology_is_versioned(scorer):
    assert scorer.methodology_version == "1.0"


def test_band_distance():
    assert RiskScorer.band_distance("low", "low") == 0
    assert RiskScorer.band_distance("medium", "very_high") == 2
