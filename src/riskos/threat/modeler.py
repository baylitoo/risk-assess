"""Threat modeler: DocumentCorpus + AssetInventory + scope → RiskRegister."""

from __future__ import annotations

from dataclasses import dataclass

from riskos.gateway import (
    GenerationGatewayError,
    StructuredGenerationGateway,
    StructuredGenerationRequest,
)
from riskos.ids import new_id, stable_id
from riskos.runtime.harness import AgentHarness
from riskos.schemas.artifacts import (
    AssetInventory,
    AssessmentScope,
    DocumentCorpus,
    FindingCategory,
    FindingStatus,
    Producer,
    RiskFinding,
    RiskRegister,
)
from riskos.schemas.generation import ThreatGeneration
from riskos.scoring.scorer import RiskScorer


def _resolve_asset_ids(
    asset_keys: list[str],
    inventory: AssetInventory,
) -> list[str]:
    """Map proposed asset keys to stable entity IDs using best-effort matching."""
    inventory_ids = {
        e.id
        for collection in (
            inventory.components,
            inventory.data_assets,
            inventory.third_parties,
            inventory.systems,
        )
        for e in collection
    }
    inventory_names = {
        e.name: e.id
        for collection in (
            inventory.components,
            inventory.data_assets,
            inventory.third_parties,
            inventory.systems,
        )
        for e in collection
    }
    result = []
    for key in asset_keys:
        if key in inventory_ids:
            result.append(key)
        elif key in inventory_names:
            result.append(inventory_names[key])
        else:
            result.append(stable_id("component", key))
    return result


def extract_threats(
    corpus: DocumentCorpus,
    inventory: AssetInventory,
    scope: AssessmentScope,
    gateway: StructuredGenerationGateway,
    producer: Producer,
    route: str = "threat_modeler",
    prompt_version: str = "1",
    risk_matrix_path: str = "config/risk_matrix.yaml",
) -> RiskRegister:
    """Call the gateway and turn ThreatGeneration into a scored RiskRegister."""
    scorer = RiskScorer.load(risk_matrix_path)

    request = StructuredGenerationRequest(
        route=route,
        system_prompt=(
            "You are the threat modeler for an EU bank risk assessment. "
            "Analyse the document corpus and asset inventory. "
            "Identify risk findings for all in-scope assets. "
            "Return a ThreatGeneration with findings covering every entity "
            "that has a coverage rule (internet-facing components, PII data "
            "assets, third parties, admin interfaces, GenAI components)."
        ),
        user_message=(
            f"Assessment: {inventory.assessment_id}\n"
            f"Corpus documents: {len(corpus.documents)}\n"
            f"Inventory: {len(inventory.systems)} systems, "
            f"{len(inventory.components)} components, "
            f"{len(inventory.data_assets)} data assets, "
            f"{len(inventory.third_parties)} third parties\n"
            f"Scope depth: {scope.depth}\n"
            f"Modules: {[m for m in scope.modules]}"
        ),
        prompt_version=prompt_version,
    )

    try:
        generation: ThreatGeneration = gateway.generate_structured(
            request, ThreatGeneration
        )
    except GenerationGatewayError:
        generation = ThreatGeneration()

    findings: list[RiskFinding] = []
    for pf in generation.findings:
        asset_ids = _resolve_asset_ids(pf.affected_asset_keys, inventory)
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
            finding = scorer.score(finding)
        except Exception:  # noqa: BLE001
            pass
        findings.append(finding)

    return RiskRegister(
        artifact_id=stable_id("artifact", inventory.assessment_id, "risk_register", "1"),
        assessment_id=inventory.assessment_id,
        phase="threat_modeling",
        producer=producer,
        methodology_version=scorer.methodology_version,
        findings=findings,
    )


@dataclass
class ThreatModelerConfig:
    route: str = "threat_modeler"
    prompt_version: str = "1"
    risk_matrix_path: str = "config/risk_matrix.yaml"


class ThreatWorker:
    """Orchestrate the threat-modeling phase under policy enforcement."""

    def __init__(
        self,
        gateway: StructuredGenerationGateway,
        harness: AgentHarness,
        config: ThreatModelerConfig | None = None,
    ) -> None:
        self._gateway = gateway
        self._harness = harness
        self._config = config or ThreatModelerConfig()

    def run(
        self,
        corpus: DocumentCorpus,
        inventory: AssetInventory,
        scope: AssessmentScope,
    ) -> RiskRegister:
        config = self._config
        producer = Producer(
            agent="threat_modeler",
            generation_route=config.route,
            prompt_version=config.prompt_version,
        )
        register = extract_threats(
            corpus=corpus,
            inventory=inventory,
            scope=scope,
            gateway=self._gateway,
            producer=producer,
            route=config.route,
            prompt_version=config.prompt_version,
            risk_matrix_path=config.risk_matrix_path,
        )
        self._harness.write_artifact(register)
        return register
