"""LLM-backed revision callable for the coverage challenge loop."""

from __future__ import annotations

from riskos.critic import CoverageGap
from riskos.gateway import (
    GenerationGatewayError,
    StructuredGenerationGateway,
    StructuredGenerationRequest,
)
from riskos.ids import stable_id
from riskos.schemas.artifacts import (
    AssetInventory,
    FindingCategory,
    FindingStatus,
    RiskFinding,
    RiskRegister,
)
from riskos.schemas.generation import ThreatGeneration
from riskos.scoring.scorer import RiskScorer
from riskos.workflow.challenge import Revision


class ChallengeReviser:
    """Wraps a gateway to produce a Revision callable for the challenge loop."""

    def __init__(
        self,
        gateway: StructuredGenerationGateway,
        assessment_id: str,
        inventory: AssetInventory,
        scorer: RiskScorer,
        route: str = "threat_modeler",
        prompt_version: str = "1",
    ) -> None:
        self._gateway = gateway
        self._assessment_id = assessment_id
        self._inventory = inventory
        self._scorer = scorer
        self._route = route
        self._prompt_version = prompt_version

    def __call__(
        self,
        current: RiskRegister,
        gaps: list[CoverageGap],
        iteration: int,
    ) -> RiskRegister:
        gap_summary = "; ".join(
            f"{g.rule_id}({g.entity_id})" for g in gaps[:10]
        )
        request = StructuredGenerationRequest(
            route=self._route,
            system_prompt=(
                "You are the threat modeler addressing coverage gaps. "
                "Propose additional findings that cover the missing "
                "entity/category combinations listed below. "
                "Do not re-emit already-present findings."
            ),
            user_message=(
                f"Coverage gaps (iteration {iteration}): {gap_summary}\n"
                f"Assessment: {self._assessment_id}"
            ),
            prompt_version=self._prompt_version,
        )
        try:
            generation: ThreatGeneration = self._gateway.generate_structured(
                request, ThreatGeneration
            )
        except GenerationGatewayError:
            return current.model_copy(update={"version": current.version + 1})

        extra: list[RiskFinding] = []
        inventory_ids = {
            e.id
            for collection in (
                self._inventory.components,
                self._inventory.data_assets,
                self._inventory.third_parties,
                self._inventory.systems,
            )
            for e in collection
        }
        inventory_names = {
            e.name: e.id
            for collection in (
                self._inventory.components,
                self._inventory.data_assets,
                self._inventory.third_parties,
                self._inventory.systems,
            )
            for e in collection
        }
        for pf in generation.findings:
            asset_ids = []
            for key in pf.affected_asset_keys:
                if key in inventory_ids:
                    asset_ids.append(key)
                elif key in inventory_names:
                    asset_ids.append(inventory_names[key])
                else:
                    asset_ids.append(stable_id("component", key))
            finding = RiskFinding(
                finding_id=stable_id("finding", pf.key),
                title=pf.name,
                category=FindingCategory(pf.category),
                scenario=pf.scenario,
                affected_asset_ids=asset_ids,
                threat_refs=pf.threat_refs,
                factors=pf.factors,
                confidence=pf.confidence,
                status=FindingStatus.DRAFT,
                remediation=pf.remediation,
            )
            try:
                finding = self._scorer.score(finding)
            except Exception:  # noqa: BLE001
                pass
            extra.append(finding)

        existing_ids = {f.finding_id for f in current.findings}
        new_findings = [f for f in extra if f.finding_id not in existing_ids]
        merged = current.findings + new_findings
        return current.model_copy(
            update={"version": current.version + 1, "findings": merged}
        )


def make_reviser(
    gateway: StructuredGenerationGateway,
    assessment_id: str,
    inventory: AssetInventory,
    scorer: RiskScorer,
    route: str = "threat_modeler",
    prompt_version: str = "1",
) -> Revision:
    """Return a Revision callable backed by the given gateway."""
    return ChallengeReviser(
        gateway=gateway,
        assessment_id=assessment_id,
        inventory=inventory,
        scorer=scorer,
        route=route,
        prompt_version=prompt_version,
    )
