from riskos.critic import check_coverage
from riskos.schemas.artifacts import FindingCategory
from tests.conftest import make_finding


def test_empty_register_triggers_all_gaps(inventory):
    gaps = check_coverage(inventory, [])
    rule_ids = {g.rule_id for g in gaps}
    # internet-facing api, pii asset, third party, admin console, genai bot
    assert rule_ids == {"COV-001", "COV-002", "COV-003", "COV-004", "COV-005"}


def test_covered_entities_produce_no_gaps(inventory):
    api, admin, bot = (c.id for c in inventory.components)
    pii = inventory.data_assets[0].id
    vendor = inventory.third_parties[0].id
    findings = [
        make_finding(FindingCategory.ABUSE_PREVENTION, [api]),
        make_finding(FindingCategory.ACCESS_MANAGEMENT, [admin]),
        make_finding(FindingCategory.GENAI, [bot]),
        make_finding(FindingCategory.PRIVACY, [pii]),
        make_finding(FindingCategory.THIRD_PARTY, [vendor]),
    ]
    assert check_coverage(inventory, findings) == []


def test_wrong_category_does_not_cover(inventory):
    # A vulnerability finding on the GenAI bot does not satisfy COV-005:
    # the rule demands a GenAI-specific scenario.
    bot = inventory.components[2].id
    findings = [make_finding(FindingCategory.VULNERABILITY, [bot])]
    gaps = check_coverage(inventory, findings)
    assert any(g.rule_id == "COV-005" and g.entity_id == bot for g in gaps)


def test_right_category_wrong_entity_does_not_cover(inventory):
    # An abuse finding on some other component doesn't cover the public API.
    api = inventory.components[0].id
    findings = [make_finding(FindingCategory.ABUSE_PREVENTION, ["cmp-elsewhere"])]
    gaps = check_coverage(inventory, findings)
    assert any(g.rule_id == "COV-001" and g.entity_id == api for g in gaps)


def test_gap_is_actionable(inventory):
    gaps = check_coverage(inventory, [])
    gap = next(g for g in gaps if g.rule_id == "COV-001")
    assert gap.entity_id.startswith("cmp-")
    assert FindingCategory.ABUSE_PREVENTION in gap.expected_categories
