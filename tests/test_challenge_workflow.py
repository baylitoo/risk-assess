import pytest

from riskos.ids import stable_id
from riskos.schemas.artifacts import FindingCategory, RiskRegister
from riskos.workflow import run_challenge_loop
from tests.conftest import make_finding


def _register(inventory, producer, findings=None) -> RiskRegister:
    return RiskRegister(
        artifact_id=stable_id("artifact", inventory.assessment_id, "register"),
        assessment_id=inventory.assessment_id,
        phase="synthesis",
        producer=producer,
        findings=findings or [],
    )


def _coverage_findings(inventory):
    api, admin, bot = (component.id for component in inventory.components)
    return [
        make_finding(FindingCategory.ABUSE_PREVENTION, [api]),
        make_finding(FindingCategory.ACCESS_MANAGEMENT, [admin]),
        make_finding(FindingCategory.GENAI, [bot]),
        make_finding(FindingCategory.PRIVACY, [inventory.data_assets[0].id]),
        make_finding(FindingCategory.THIRD_PARTY, [inventory.third_parties[0].id]),
    ]


def test_challenge_loop_skips_revision_when_coverage_passes(inventory, producer):
    register = _register(inventory, producer, _coverage_findings(inventory))

    result = run_challenge_loop(
        inventory,
        register,
        lambda *_: pytest.fail("revision should not run"),
    )

    assert result.resolved
    assert result.iterations == 0


def test_challenge_loop_can_resolve_gaps(inventory, producer):
    register = _register(inventory, producer)

    def revise(current, gaps, iteration):
        assert gaps
        return current.model_copy(
            update={"version": current.version + 1, "findings": _coverage_findings(inventory)}
        )

    result = run_challenge_loop(inventory, register, revise)

    assert result.resolved
    assert result.iterations == 1
    assert result.register.version == 2
    assert result.remaining_gaps == ()


def test_challenge_loop_is_bounded_and_returns_remaining_gaps(inventory, producer):
    register = _register(inventory, producer)

    def revise(current, gaps, iteration):
        return current.model_copy(update={"version": current.version + 1})

    result = run_challenge_loop(inventory, register, revise)

    assert not result.resolved
    assert result.iterations == 2
    assert result.register.version == 3
    assert len(result.remaining_gaps) == 5


def test_revision_must_increment_version(inventory, producer):
    register = _register(inventory, producer)

    with pytest.raises(ValueError, match="increase artifact version"):
        run_challenge_loop(inventory, register, lambda current, gaps, iteration: current)
