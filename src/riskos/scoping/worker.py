"""ScopeWorker — bridges intake output to the scoping phase."""

from __future__ import annotations

from dataclasses import dataclass, field

from riskos.runtime.harness import AgentHarness
from riskos.scoping.engine import ScopingError, scope_assessment
from riskos.schemas.artifacts import AssetInventory, AssessmentScope, IntakeAssessment


@dataclass
class ScopeResult:
    scope_artifact_id: str
    depth: str
    modules: list[str] = field(default_factory=list)
    scheduled_agents: list[str] = field(default_factory=list)
    audit_event_count: int = 0


class ScopeWorker:
    def __init__(self, harness: AgentHarness) -> None:
        self._harness = harness

    def run(self, inventory: AssetInventory, intake: IntakeAssessment) -> ScopeResult:
        scope = scope_assessment(inventory, intake)
        self._harness.write_artifact(scope)
        audit_count = len(self._harness.audit_log.read_all())
        return ScopeResult(
            scope_artifact_id=scope.artifact_id,
            depth=scope.depth.value,
            modules=[m.value for m in scope.modules],
            scheduled_agents=list(scope.scheduled_agents),
            audit_event_count=audit_count,
        )
