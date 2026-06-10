"""Policy-enforced synthesis worker.

Consumes an AssetInventory, a threat RiskRegister, optional
VulnerabilityFindings, and an AssessmentScope; emits a final RiskRegister
through the AgentHarness.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from riskos.critic import check_coverage
from riskos.gateway import StructuredGenerationGateway
from riskos.ids import new_id, stable_id
from riskos.runtime.harness import AgentHarness
from riskos.schemas.artifacts import (
    AssetInventory,
    AssessmentScope,
    Producer,
    RiskRegister,
    VulnerabilityFindings,
)
from riskos.scoring.scorer import RiskScorer
from riskos.synthesis.synthesizer import synthesize_register


@dataclass
class SynthesisConfig:
    route: str = "synthesis"
    prompt_version: str = "1"
    max_challenge_iterations: int = 2
    risk_matrix_path: str = "config/risk_matrix.yaml"


@dataclass
class SynthesisResult:
    register_artifact_id: str
    challenge_iterations: int
    coverage_resolved: bool
    remaining_gap_count: int
    audit_event_count: int = 0


class SynthesisWorker:
    """Orchestrate the synthesis phase under policy enforcement."""

    def __init__(
        self,
        gateway: StructuredGenerationGateway,
        harness: AgentHarness,
        config: SynthesisConfig | None = None,
    ) -> None:
        self._gateway = gateway
        self._harness = harness
        self._config = config or SynthesisConfig()

    def run(
        self,
        inventory: AssetInventory,
        threat_register: RiskRegister,
        vuln_findings: VulnerabilityFindings | None,
        scope: AssessmentScope,
    ) -> SynthesisResult:
        config = self._config
        scorer = RiskScorer.load(config.risk_matrix_path)
        producer = Producer(
            agent="risk_synthesizer",
            generation_route=config.route,
            prompt_version=config.prompt_version,
        )

        final_register, challenge_result = synthesize_register(
            inventory=inventory,
            threat_register=threat_register,
            vuln_findings=vuln_findings,
            scope=scope,
            gateway=self._gateway,
            scorer=scorer,
            producer=producer,
            route=config.route,
            prompt_version=config.prompt_version,
            max_challenge_iterations=config.max_challenge_iterations,
        )

        # Stamp the final register with synthesis provenance
        output_register = final_register.model_copy(
            update={"producer": producer}
        )

        self._harness.write_artifact(output_register)

        audit_count = len(self._harness.audit_log.read_all())

        remaining_gaps = check_coverage(inventory, output_register.findings)

        return SynthesisResult(
            register_artifact_id=output_register.artifact_id,
            challenge_iterations=challenge_result.iterations,
            coverage_resolved=challenge_result.resolved,
            remaining_gap_count=len(remaining_gaps),
            audit_event_count=audit_count,
        )
