from riskos.evals import evaluate_register
from riskos.schemas.artifacts import Citation, FindingCategory
from tests.conftest import make_finding


def _golden():
    return [
        make_finding(FindingCategory.VULNERABILITY, ["cmp-api"],
                     finding_id="g1", band="critical"),
        make_finding(FindingCategory.PRIVACY, ["dat-pii"],
                     finding_id="g2", band="high"),
        make_finding(FindingCategory.THIRD_PARTY, ["thp-kyc"],
                     finding_id="g3", band="medium"),
    ]


def test_perfect_run(evidence_doc):
    cit = [Citation(evidence_id=evidence_doc.evidence_id)]
    produced = [
        make_finding(FindingCategory.VULNERABILITY, ["cmp-api"],
                     finding_id="p1", band="critical", citations=cit),
        make_finding(FindingCategory.PRIVACY, ["dat-pii"],
                     finding_id="p2", band="very_high", citations=cit),
        make_finding(FindingCategory.THIRD_PARTY, ["thp-kyc"],
                     finding_id="p3", band="medium", citations=cit),
    ]
    report = evaluate_register(_golden(), produced)
    assert report.false_safe_rate == 0.0
    assert report.precision == 1.0
    assert report.unsupported_critical_rate == 0.0
    assert report.score_agreement == 1.0  # very_high vs high = 1 band, within ±1


def test_false_safe_is_detected():
    # System missed the privacy and third-party risks entirely.
    produced = [
        make_finding(FindingCategory.VULNERABILITY, ["cmp-api"],
                     finding_id="p1", band="critical"),
    ]
    report = evaluate_register(_golden(), produced)
    assert report.false_safe_rate == round(2 / 3, 4)
    assert set(report.missed_golden_ids) == {"g2", "g3"}


def test_unsupported_critical_is_flagged():
    produced = [
        make_finding(FindingCategory.VULNERABILITY, ["cmp-api"],
                     finding_id="p1", band="critical"),  # no citations!
    ]
    report = evaluate_register(_golden(), produced)
    assert report.unsupported_critical_rate == 1.0
    assert report.unsupported_critical_ids == ["p1"]


def test_category_match_requires_asset_overlap():
    # Right category, wrong asset → not a match → still a false-safe.
    produced = [
        make_finding(FindingCategory.PRIVACY, ["dat-other"],
                     finding_id="p1", band="high"),
    ]
    report = evaluate_register(_golden(), produced)
    assert "g2" in report.missed_golden_ids
    assert report.precision == 0.0


def test_one_produced_finding_cannot_match_twice():
    golden = [
        make_finding(FindingCategory.PRIVACY, ["dat-pii"], finding_id="g1"),
        make_finding(FindingCategory.PRIVACY, ["dat-pii"], finding_id="g2"),
    ]
    produced = [
        make_finding(FindingCategory.PRIVACY, ["dat-pii"], finding_id="p1"),
    ]
    report = evaluate_register(golden, produced)
    assert report.matched_golden == 1
    assert report.false_safe_rate == 0.5


def test_empty_inputs_are_safe():
    report = evaluate_register([], [])
    assert report.false_safe_rate == 0.0
    assert report.precision == 0.0
    assert report.score_agreement == 1.0
