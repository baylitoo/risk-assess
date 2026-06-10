import pytest

from riskos.ids import stable_id
from riskos.intake import ingest_directory
from riskos.policy import PolicyEngine, PolicyError
from riskos.runtime import AgentHarness, ArtifactWorkspace, JsonlAuditLog, WorkspaceError
from riskos.schemas.artifacts import RiskRegister, VulnerabilityFindings
from riskos.scoping import determine_scope
from tests.conftest import REPO_ROOT


@pytest.fixture()
def runtime(tmp_path, producer):
    assessment_id = stable_id("assessment", "runtime-test")
    workspace = ArtifactWorkspace(tmp_path / "workspace", assessment_id)
    audit = JsonlAuditLog(tmp_path / "audit.jsonl")
    policy = PolicyEngine.load_dir(REPO_ROOT / "policies")
    return assessment_id, workspace, audit, policy, producer


def test_allowed_write_and_read_are_audited(runtime):
    assessment_id, workspace, audit, policy, producer = runtime
    artifact = VulnerabilityFindings(
        artifact_id=stable_id("artifact", assessment_id, "vulns"),
        assessment_id=assessment_id,
        phase="evidence",
        producer=producer,
    )

    AgentHarness("vuln_operator", policy, workspace, audit).write_artifact(artifact)
    loaded = AgentHarness("risk_synthesizer", policy, workspace, audit).read_artifact(
        "vulnerability_findings", artifact.artifact_id, VulnerabilityFindings
    )

    assert loaded == artifact
    events = audit.read_all()
    assert [event.outcome for event in events] == ["allowed", "allowed"]
    assert events[0].rule == "can_write: artifact.vulnerability_findings"
    assert events[1].artifact_id == artifact.artifact_id


def test_denied_write_is_audited_and_not_persisted(runtime):
    assessment_id, workspace, audit, policy, producer = runtime
    register = RiskRegister(
        artifact_id=stable_id("artifact", assessment_id, "register"),
        assessment_id=assessment_id,
        phase="synthesis",
        producer=producer,
    )

    with pytest.raises(PolicyError, match="denied"):
        AgentHarness("critic", policy, workspace, audit).write_artifact(register)

    event = audit.read_all()[0]
    assert event.outcome == "denied"
    assert event.rule == "cannot: write:artifact.risk_register"
    with pytest.raises(WorkspaceError, match="not found"):
        workspace.read("risk_register", register.artifact_id, RiskRegister)


def test_workspace_is_versioned_and_immutable(runtime):
    assessment_id, workspace, _, _, producer = runtime
    artifact = RiskRegister(
        artifact_id=stable_id("artifact", assessment_id, "register"),
        assessment_id=assessment_id,
        phase="synthesis",
        producer=producer,
    )
    workspace.write(artifact)
    workspace.write(artifact.model_copy(update={"version": 2}))

    latest = workspace.read("risk_register", artifact.artifact_id, RiskRegister)
    assert latest.version == 2
    with pytest.raises(WorkspaceError, match="already exists"):
        workspace.write(artifact)


def test_workspace_rejects_cross_assessment_artifact(runtime):
    _, workspace, _, _, producer = runtime
    artifact = RiskRegister(
        artifact_id=stable_id("artifact", "other", "register"),
        assessment_id=stable_id("assessment", "other"),
        phase="synthesis",
        producer=producer,
    )
    with pytest.raises(WorkspaceError, match="does not match"):
        workspace.write(artifact)


@pytest.mark.parametrize(
    ("artifact_type", "artifact_id"),
    [
        ("../outside", "art-safe"),
        ("risk_register", "../outside"),
        ("risk/register", "art-safe"),
    ],
)
def test_workspace_rejects_unsafe_path_segments(
    runtime, artifact_type, artifact_id
):
    assessment_id, workspace, _, _, producer = runtime
    artifact = RiskRegister(
        artifact_id=artifact_id,
        artifact_type=artifact_type,
        assessment_id=assessment_id,
        phase="synthesis",
        producer=producer,
    )
    with pytest.raises(WorkspaceError, match="invalid"):
        workspace.write(artifact)


def test_workspace_rejects_non_positive_versions(runtime):
    assessment_id, workspace, _, _, producer = runtime
    artifact = RiskRegister(
        artifact_id=stable_id("artifact", assessment_id, "register"),
        assessment_id=assessment_id,
        phase="synthesis",
        producer=producer,
        version=0,
    )
    with pytest.raises(WorkspaceError, match="positive"):
        workspace.write(artifact)


def test_scope_engine_can_persist_scope_but_cannot_read_raw_documents(
    runtime, inventory
):
    _, workspace, audit, policy, _ = runtime
    scoped_inventory = inventory.model_copy(
        update={"assessment_id": workspace.assessment_id}
    )
    scope = determine_scope(scoped_inventory)
    harness = AgentHarness("scope_engine", policy, workspace, audit)

    harness.write_artifact(scope)
    with pytest.raises(PolicyError, match="denied"):
        harness.authorize("read", "document.raw.sats")

    assert [event.outcome for event in audit.read_all()] == ["allowed", "denied"]


def test_document_corpus_versions_flow_through_policy_harness(runtime, tmp_path):
    assessment_id, workspace, audit, policy, _ = runtime
    (tmp_path / "sats.md").write_text("# SATS\n\nSecurity assessment.", encoding="utf-8")
    first = ingest_directory(tmp_path, assessment_id)
    second = ingest_directory(tmp_path, assessment_id, version=2)

    intake = AgentHarness("intake_worker", policy, workspace, audit)
    intake.write_artifact(first)
    intake.write_artifact(second)
    latest = AgentHarness("internal_docs_analyst", policy, workspace, audit).read_artifact(
        "document_corpus", first.artifact_id, type(first)
    )

    assert latest.version == 2
