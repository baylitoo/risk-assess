"""Deterministic assessment phase state machine with explicit human gates."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class WorkflowError(Exception):
    pass


class Phase(StrEnum):
    INTAKE = "intake"
    SCOPING = "scoping"
    EVIDENCE = "evidence"
    SYNTHESIS = "synthesis"
    CHALLENGE = "challenge"
    REVIEW = "review"
    PUBLISH = "publish"
    COMPLETE = "complete"


_NEXT_PHASE: dict[Phase, Phase] = {
    Phase.INTAKE: Phase.SCOPING,
    Phase.SCOPING: Phase.EVIDENCE,
    Phase.EVIDENCE: Phase.SYNTHESIS,
    Phase.SYNTHESIS: Phase.CHALLENGE,
    Phase.CHALLENGE: Phase.REVIEW,
    Phase.REVIEW: Phase.PUBLISH,
    Phase.PUBLISH: Phase.COMPLETE,
}

_HUMAN_GATES = {Phase.SCOPING, Phase.REVIEW}


class Transition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    from_phase: Phase
    to_phase: Phase
    occurred_at: datetime = Field(default_factory=_utcnow)
    actor: str
    human_approved: bool = False


class WorkflowState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment_id: str
    phase: Phase = Phase.INTAKE
    revision: int = 0
    transitions: list[Transition] = Field(default_factory=list)


class AssessmentWorkflow:
    """Advance one phase at a time; gate transitions that require sign-off."""

    def __init__(self, state: WorkflowState):
        self.state = state

    @classmethod
    def start(cls, assessment_id: str) -> "AssessmentWorkflow":
        return cls(WorkflowState(assessment_id=assessment_id))

    def advance(self, actor: str, human_approved: bool = False) -> WorkflowState:
        current = self.state.phase
        if current == Phase.COMPLETE:
            raise WorkflowError("assessment workflow is already complete")
        if current in _HUMAN_GATES and not human_approved:
            raise WorkflowError(f"human approval required after {current.value}")

        target = _NEXT_PHASE[current]
        transition = Transition(
            from_phase=current,
            to_phase=target,
            actor=actor,
            human_approved=human_approved,
        )
        self.state = self.state.model_copy(
            update={
                "phase": target,
                "revision": self.state.revision + 1,
                "transitions": [*self.state.transitions, transition],
            }
        )
        return self.state

    def serialize(self) -> str:
        return self.state.model_dump_json(indent=2)

    @classmethod
    def resume(cls, serialized: str) -> "AssessmentWorkflow":
        return cls(WorkflowState.model_validate_json(serialized))
