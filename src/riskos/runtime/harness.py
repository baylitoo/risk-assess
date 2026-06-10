"""Policy-enforced agent access with an append-only local audit trail."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from riskos.ids import new_id
from riskos.policy import Decision, PolicyEngine
from riskos.schemas.artifacts import Artifact
from riskos.runtime.workspace import ArtifactWorkspace

ArtifactT = TypeVar("ArtifactT", bound=Artifact)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: new_id("span"))
    occurred_at: datetime = Field(default_factory=_utcnow)
    agent: str
    action: str
    resource: str
    outcome: Literal["allowed", "denied"]
    rule: str
    policy_file: str
    artifact_id: str = ""
    artifact_version: int | None = None


class JsonlAuditLog:
    """Append-only JSONL audit log suitable for local development and replay."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def append(self, event: AuditEvent) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(event.model_dump_json() + "\n")

    def read_all(self) -> list[AuditEvent]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as handle:
            return [
                AuditEvent.model_validate(json.loads(line))
                for line in handle
                if line.strip()
            ]


class AgentHarness:
    """The only supported route for agent artifact reads and writes."""

    def __init__(
        self,
        agent: str,
        policy: PolicyEngine,
        workspace: ArtifactWorkspace,
        audit_log: JsonlAuditLog,
    ):
        self.agent = agent
        self.policy = policy
        self.workspace = workspace
        self.audit_log = audit_log

    def write_artifact(self, artifact: Artifact) -> Path:
        resource = f"artifact.{artifact.artifact_type}"
        decision = self._authorize("write", resource, artifact)
        self.policy.enforce(self.agent, "write", resource)
        return self.workspace.write(artifact)

    def read_artifact(
        self,
        artifact_type: str,
        artifact_id: str,
        model: type[ArtifactT],
        version: int | None = None,
    ) -> ArtifactT:
        resource = f"artifact.{artifact_type}"
        self._authorize("read", resource, artifact_id=artifact_id, version=version)
        self.policy.enforce(self.agent, "read", resource)
        return self.workspace.read(artifact_type, artifact_id, model, version)

    def authorize(self, action: str, resource: str) -> Decision:
        """Authorize and audit a non-artifact operation before execution."""
        decision = self._authorize(action, resource)
        self.policy.enforce(self.agent, action, resource)
        return decision

    def _authorize(
        self,
        action: str,
        resource: str,
        artifact: Artifact | None = None,
        artifact_id: str = "",
        version: int | None = None,
    ) -> Decision:
        decision = self.policy.check(self.agent, action, resource)
        self.audit_log.append(
            AuditEvent(
                agent=self.agent,
                action=action,
                resource=resource,
                outcome="allowed" if decision.allowed else "denied",
                rule=decision.rule,
                policy_file=decision.source_file,
                artifact_id=artifact.artifact_id if artifact else artifact_id,
                artifact_version=artifact.version if artifact else version,
            )
        )
        return decision
