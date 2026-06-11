"""Deterministic DORA ICT risk rule checker.

DORA (Digital Operational Resilience Act) has been live since January 2025.
These rules mirror the coverage.py pattern but target DORA-specific obligations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from riskos.schemas.artifacts import AssetInventory, FindingCategory, RiskFinding


@dataclass(frozen=True)
class DoraRule:
    rule_id: str
    article_ref: str
    description: str
    trigger: Callable[[AssetInventory], list[str]]
    required_categories: frozenset[FindingCategory]


@dataclass(frozen=True)
class DoraGap:
    rule_id: str
    article_ref: str
    description: str
    entity_id: str
    required_categories: frozenset[FindingCategory]


def _third_parties_no_exit(inv: AssetInventory) -> list[str]:
    return [t.id for t in inv.third_parties if t.has_exit_plan is not True]


def _third_parties_concentration(inv: AssetInventory) -> list[str]:
    return [t.id for t in inv.third_parties if t.concentration_risk]


def _critical_systems(inv: AssetInventory) -> list[str]:
    return [s.id for s in inv.systems if s.supports_critical_function]


def _any_system_for_logging(inv: AssetInventory) -> list[str]:
    if inv.systems:
        return [inv.systems[0].id]
    return ["inventory"]


def _admin_interfaces(inv: AssetInventory) -> list[str]:
    return [c.id for c in inv.components if c.is_admin_interface]


def _genai_with_pii(inv: AssetInventory) -> list[str]:
    genai_system_ids = {
        c.system_id for c in inv.components if c.is_genai
    }
    pii_system_ids = {
        d.system_id for d in inv.data_assets if d.contains_pii and hasattr(d, "system_id")
    }
    overlapping_systems = genai_system_ids & pii_system_ids
    result = []
    for c in inv.components:
        if c.is_genai and c.system_id in overlapping_systems:
            result.append(c.id)
    return result


DORA_RULES: tuple[DoraRule, ...] = (
    DoraRule(
        "DR-001",
        "Art. 30.2",
        "Third-party ICT provider without documented exit/transition plan",
        _third_parties_no_exit,
        frozenset({FindingCategory.THIRD_PARTY}),
    ),
    DoraRule(
        "DR-002",
        "Art. 28.4",
        "Third-party provider with concentration risk requires resilience + third-party finding",
        _third_parties_concentration,
        frozenset({FindingCategory.RESILIENCE, FindingCategory.THIRD_PARTY}),
    ),
    DoraRule(
        "DR-003",
        "Art. 9.2",
        "System supporting a critical function without resilience finding",
        _critical_systems,
        frozenset({FindingCategory.RESILIENCE}),
    ),
    DoraRule(
        "DR-004",
        "Art. 10.1",
        "Logging and monitoring coverage required for ICT systems",
        _any_system_for_logging,
        frozenset({FindingCategory.LOGGING_MONITORING}),
    ),
    DoraRule(
        "DR-005",
        "Art. 9.4",
        "Administrative interface without access management finding",
        _admin_interfaces,
        frozenset({FindingCategory.ACCESS_MANAGEMENT}),
    ),
    DoraRule(
        "DR-006",
        "Art. 8.3",
        "GenAI component handling PII requires GENAI and PRIVACY findings",
        _genai_with_pii,
        frozenset({FindingCategory.GENAI, FindingCategory.PRIVACY}),
    ),
)


def check_dora_compliance(
    inventory: AssetInventory,
    findings: list[RiskFinding],
    rules: tuple[DoraRule, ...] = DORA_RULES,
) -> list[DoraGap]:
    """Return DORA gaps: entities triggered by a rule with no covering finding."""
    covered: dict[str, set[FindingCategory]] = {}
    for finding in findings:
        for entity_id in finding.affected_asset_ids:
            covered.setdefault(entity_id, set()).add(finding.category)

    gaps: list[DoraGap] = []
    for rule in rules:
        triggered = rule.trigger(inventory)
        for entity_id in triggered:
            entity_covered = covered.get(entity_id, set())
            if not rule.required_categories.issubset(entity_covered):
                gaps.append(
                    DoraGap(
                        rule_id=rule.rule_id,
                        article_ref=rule.article_ref,
                        description=rule.description,
                        entity_id=entity_id,
                        required_categories=rule.required_categories,
                    )
                )
    return gaps
