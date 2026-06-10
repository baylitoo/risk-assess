"""Policy-enforced Phase 0 intake worker."""

from __future__ import annotations

from dataclasses import dataclass, field

from riskos.gateway import StructuredGenerationGateway
from riskos.intake.extractor import extract_inventory
from riskos.intake.inventory import materialize_inventory
from riskos.intake.completeness import assess_completeness
from riskos.runtime.harness import AgentHarness
from riskos.schemas.artifacts import DocumentCorpus, Producer


@dataclass
class IntakeWorkerConfig:
    route: str = "inventory-extraction"
    prompt_version: str = "1"
    minimum_confidence: float = 0.0
    max_output_tokens: int = 8192
    timeout_seconds: float = 120.0


@dataclass
class IntakeResult:
    extraction_artifact_id: str
    inventory_artifact_id: str
    completeness_artifact_id: str
    complete: bool
    missing_requirements: list[str] = field(default_factory=list)
    audit_event_count: int = 0


class IntakeWorker:
    def __init__(
        self,
        gateway: StructuredGenerationGateway,
        harness: AgentHarness,
        config: IntakeWorkerConfig | None = None,
    ) -> None:
        self._gateway = gateway
        self._harness = harness
        self._config = config or IntakeWorkerConfig()

    def run(self, corpus: DocumentCorpus) -> IntakeResult:
        config = self._config
        extraction_producer = Producer(
            agent="intake_worker",
            generation_route=config.route,
            prompt_version=config.prompt_version,
        )
        extraction = extract_inventory(
            corpus,
            self._gateway,
            extraction_producer,
            route=config.route,
            prompt_version=config.prompt_version,
            max_output_tokens=config.max_output_tokens,
            timeout_seconds=config.timeout_seconds,
        )
        inventory = materialize_inventory(
            corpus,
            extraction,
            Producer(agent="intake_worker"),
            minimum_confidence=config.minimum_confidence,
        )
        completeness = assess_completeness(inventory, Producer(agent="intake_worker"))
        self._harness.write_artifact(extraction)
        self._harness.write_artifact(inventory)
        self._harness.write_artifact(completeness)
        audit_count = len(self._harness.audit_log.read_all())
        return IntakeResult(
            extraction_artifact_id=extraction.artifact_id,
            inventory_artifact_id=inventory.artifact_id,
            completeness_artifact_id=completeness.artifact_id,
            complete=completeness.complete,
            missing_requirements=[
                f"{r.rule_id}: {r.description}" for r in completeness.requirements
            ],
            audit_event_count=audit_count,
        )
