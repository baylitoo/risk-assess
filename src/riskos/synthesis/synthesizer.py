"""Synthesis phase: merge threat + vuln findings, run challenge loop.

This module is the single entry point for the risk_synthesizer agent.
It never calls out to threat-generation services itself — gap-filling during
the challenge loop uses a minimal inline reviser that calls the gateway with
a ThreatGeneration response model when available, or returns the register
unchanged (stub path) when the gateway has no configured response.
"""

from __future__ import annotations

from riskos.critic import CoverageGap
from riskos.gateway import GenerationGatewayError, StructuredGenerationGateway
from riskos.ids import new_id, stable_id
from riskos.schemas.artifacts import (
    AssetInventory,
    AssessmentScope,
    FindingCategory,
    FindingStatus,
    Producer,
    RiskFinding,
    RiskRegister,
    VulnerabilityFindings,
)
from riskos.schemas.generation import ThreatGeneration
from riskos.scoring.scorer import RiskScorer
from riskos.workflow.challenge import ChallengeResult, run_challenge_loop


def _deduplicate_findings(findings: list[RiskFinding]) -> list[RiskFinding]:
    """Remove duplicates by finding_id; last writer wins on same ID."""
    seen: dict[str, RiskFinding] = {}
    for f in findings:
        seen[f.finding_id] = f
    return list(seen.values())


def _score_findings(findings: list[RiskFinding], scorer: RiskScorer) -> list[RiskFinding]:
    """Apply deterministic scoring to findings that have sufficient factors.

    Findings that lack required scoring factors are returned unchanged
    (they may have been imported from vuln findings with a different factor set).
    """
    scored = []
    for f in findings:
        try:
            scored.append(scorer.score(f))
        except Exception:  # noqa: BLE001  (ScoringError or similar)
            scored.append(f)
    return scored


def _build_reviser(
    assessment_id: str,
    inventory: AssetInventory,
    scope: AssessmentScope,
    gateway: StructuredGenerationGateway,
    scorer: RiskScorer,
    producer: Producer,
    route: str,
    prompt_version: str,
):
    """Return a Revision callable for the challenge loop.

    The callable tries to call the gateway for gap-filling.  If no
    ThreatGeneration response is configured (e.g. in test stubs), it returns
    the register with an incremented version so the challenge loop can
    progress without raising.
    """
    from riskos.gateway import StructuredGenerationRequest

    def revise(
        current: RiskRegister,
        gaps: list[CoverageGap],
        iteration: int,
    ) -> RiskRegister:
        gap_summary = "; ".join(
            f"{g.rule_id}({g.entity_id})" for g in gaps[:10]
        )
        request = StructuredGenerationRequest(
            route=route,
            system_prompt=(
                "You are the risk synthesizer.  Address the coverage gaps listed "
                "by proposing additional risk findings.  Return a ThreatGeneration "
                "with findings that cover the missing entity/category combinations."
            ),
            user_message=(
                f"Coverage gaps (iteration {iteration}): {gap_summary}\n"
                f"Assessment: {assessment_id}"
            ),
            prompt_version=prompt_version,
        )
        try:
            generation: ThreatGeneration = gateway.generate_structured(
                request, ThreatGeneration
            )
        except GenerationGatewayError:
            # Stub path: no response configured — increment version and return.
            return current.model_copy(update={"version": current.version + 1})

        # Convert ProposedFindings → RiskFindings
        extra_findings = []
        for pf in generation.findings:
            asset_ids = [
                stable_id("component", key) for key in pf.affected_asset_keys
            ] or pf.affected_asset_keys  # fallback to raw keys if needed
            finding = RiskFinding(
                finding_id=stable_id("finding", pf.key),
                title=pf.name,
                category=FindingCategory(pf.category),
                scenario=pf.scenario,
                affected_asset_ids=asset_ids,
                threat_refs=pf.threat_refs,
                factors=pf.factors,
                status=FindingStatus.DRAFT,
                remediation=pf.remediation,
            )
            extra_findings.append(finding)

        merged = _deduplicate_findings(current.findings + extra_findings)
        scored = _score_findings(merged, scorer)
        return current.model_copy(
            update={"version": current.version + 1, "findings": scored}
        )

    return revise


def synthesize_register(
    inventory: AssetInventory,
    threat_register: RiskRegister,
    vuln_findings: VulnerabilityFindings | None,
    scope: AssessmentScope,
    gateway: StructuredGenerationGateway,
    scorer: RiskScorer,
    producer: Producer,
    route: str = "synthesis",
    prompt_version: str = "1",
    max_challenge_iterations: int = 2,
) -> tuple[RiskRegister, ChallengeResult]:
    """Merge threat and vuln findings, deduplicate, score, and run the challenge loop.

    Returns (final_register, challenge_result).
    """
    # 1. Merge
    all_findings: list[RiskFinding] = list(threat_register.findings)
    if vuln_findings is not None:
        all_findings.extend(vuln_findings.findings)

    # 2. Deduplicate
    merged = _deduplicate_findings(all_findings)

    # 3. Score what we can
    scored = _score_findings(merged, scorer)

    # 4. Build the starting register
    starting_register = threat_register.model_copy(
        update={"findings": scored, "version": 1}
    )

    # 5. Build reviser callable
    revise = _build_reviser(
        assessment_id=threat_register.assessment_id,
        inventory=inventory,
        scope=scope,
        gateway=gateway,
        scorer=scorer,
        producer=producer,
        route=route,
        prompt_version=prompt_version,
    )

    # 6. Run challenge loop
    challenge_result = run_challenge_loop(
        inventory,
        starting_register,
        revise,
        max_challenge_iterations,
    )

    return challenge_result.register, challenge_result
