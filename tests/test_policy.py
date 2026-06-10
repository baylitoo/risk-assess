import pytest

from riskos.policy import PolicyEngine, PolicyError


@pytest.fixture(scope="module")
def engine(request) -> PolicyEngine:
    from tests.conftest import REPO_ROOT
    return PolicyEngine.load_dir(REPO_ROOT / "policies")


def test_vuln_operator_can_read_mirror(engine):
    d = engine.check("vuln_operator", "read", "mirror.nvd")
    assert d.allowed
    assert "can_read" in d.rule


def test_vuln_operator_cannot_read_raw_docs(engine):
    d = engine.check("vuln_operator", "read", "document.raw.sats-2026")
    assert not d.allowed
    assert d.rule.startswith("cannot:")
    assert d.source_file.endswith("vuln_operator.yaml")


def test_synthesizer_injection_firewall(engine):
    # The synthesizer consumes artifacts, never raw documents.
    assert engine.check("risk_synthesizer", "read", "artifact.vulnerability_findings")
    assert not engine.check("risk_synthesizer", "read", "document.raw.anything")


def test_no_agent_can_publish(engine):
    for agent in ("intake_worker", "scope_engine", "vuln_operator",
                  "internal_docs_analyst", "risk_synthesizer", "critic",
                  "report_writer"):
        assert not engine.check(agent, "execute", "report.publish")


def test_critic_cannot_edit_register(engine):
    assert not engine.check("critic", "write", "artifact.risk_register")
    assert engine.check("critic", "write", "artifact.critique")


def test_default_deny_for_unknown_agent(engine):
    d = engine.check("rogue_agent", "read", "artifact.asset_inventory")
    assert not d.allowed
    assert "no policy" in d.rule


def test_default_deny_for_unlisted_resource(engine):
    assert not engine.check("vuln_operator", "write", "artifact.risk_register")


def test_enforce_raises(engine):
    with pytest.raises(PolicyError, match="denied"):
        engine.enforce("vuln_operator", "execute", "scan.active")


def test_decision_is_auditable(engine):
    d = engine.check("vuln_operator", "execute", "scan.active")
    # "show me the rule that denied this" → a file and a rule string
    assert d.rule == "cannot: execute:scan.active"
    assert d.source_file.endswith("vuln_operator.yaml")


def test_scope_engine_is_structured_artifacts_only(engine):
    assert engine.check("scope_engine", "read", "artifact.asset_inventory")
    assert engine.check("scope_engine", "write", "artifact.assessment_scope")
    assert not engine.check("scope_engine", "read", "document.raw.sats")
