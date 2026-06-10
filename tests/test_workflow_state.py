import pytest

from riskos.ids import stable_id
from riskos.workflow import AssessmentWorkflow, Phase, WorkflowError


@pytest.fixture()
def workflow():
    return AssessmentWorkflow.start(stable_id("assessment", "workflow-test"))


def test_workflow_advances_in_declared_order(workflow):
    state = workflow.advance("intake_worker")

    assert state.phase == Phase.SCOPING
    assert state.revision == 1
    assert state.transitions[0].from_phase == Phase.INTAKE
    assert state.transitions[0].to_phase == Phase.SCOPING


def test_scope_gate_requires_human_approval(workflow):
    workflow.advance("intake_worker")

    with pytest.raises(WorkflowError, match="human approval required"):
        workflow.advance("orchestrator")
    state = workflow.advance("risk.officer@example.test", human_approved=True)

    assert state.phase == Phase.EVIDENCE
    assert state.transitions[-1].human_approved


def test_review_gate_requires_human_approval(workflow):
    workflow.advance("intake_worker")
    workflow.advance("risk.officer@example.test", human_approved=True)
    workflow.advance("specialist_pool")
    workflow.advance("risk_synthesizer")
    workflow.advance("critic")
    assert workflow.state.phase == Phase.REVIEW

    with pytest.raises(WorkflowError, match="human approval required"):
        workflow.advance("orchestrator")
    assert workflow.advance("risk.officer@example.test", True).phase == Phase.PUBLISH


def test_complete_workflow_cannot_advance(workflow):
    actors = [
        ("intake_worker", False),
        ("risk.officer@example.test", True),
        ("specialist_pool", False),
        ("risk_synthesizer", False),
        ("critic", False),
        ("risk.officer@example.test", True),
        ("publisher", False),
    ]
    for actor, approved in actors:
        workflow.advance(actor, approved)

    assert workflow.state.phase == Phase.COMPLETE
    with pytest.raises(WorkflowError, match="already complete"):
        workflow.advance("orchestrator")


def test_workflow_can_resume_from_serialized_state(workflow):
    workflow.advance("intake_worker")

    resumed = AssessmentWorkflow.resume(workflow.serialize())

    assert resumed.state == workflow.state
    assert resumed.advance("risk.officer@example.test", True).phase == Phase.EVIDENCE
