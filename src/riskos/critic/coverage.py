"""The critic's missing-risk detector.

Doctrine rule 4: a critic that checks "is every finding cited?" is a
verifier; a critic that asks "what risk should exist here but doesn't?"
is a false-safe defense. These deterministic coverage rules run BEFORE the
LLM critique pass — they inspect the inventory and demand that certain
finding categories exist whenever certain facts are true. Any gap is a
blocking input to the challenge loop.

Each rule = (predicate over inventory → triggering entities) + the finding
categories that must cover at least one of those entities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from riskos.schemas.artifacts import AssetInventory, FindingCategory, RiskFinding
from riskos.schemas.entities import Exposure


@dataclass(frozen=True)
class CoverageRule:
    rule_id: str
    description: str
    trigger: Callable[[AssetInventory], list[str]]   # → triggering entity IDs
    expected_categories: frozenset[FindingCategory]


@dataclass(frozen=True)
class CoverageGap:
    rule_id: str
    description: str
    entity_id: str
    expected_categories: frozenset[FindingCategory]


def _internet_facing(inv: AssetInventory) -> list[str]:
    return [c.id for c in inv.components if c.exposure == Exposure.INTERNET_FACING]


def _pii_assets(inv: AssetInventory) -> list[str]:
    return [d.id for d in inv.data_assets if d.contains_pii]


def _third_parties(inv: AssetInventory) -> list[str]:
    return [t.id for t in inv.third_parties]


def _admin_interfaces(inv: AssetInventory) -> list[str]:
    return [c.id for c in inv.components if c.is_admin_interface]


def _genai_components(inv: AssetInventory) -> list[str]:
    return [c.id for c in inv.components if c.is_genai]


def _unencrypted_or_unknown_flows(inv: AssetInventory) -> list[str]:
    return [
        f.id
        for f in inv.data_flows
        if f.crosses_trust_boundary and f.encrypted_in_transit is not True
    ]


DEFAULT_RULES: tuple[CoverageRule, ...] = (
    CoverageRule(
        "COV-001",
        "Internet-facing component without an abuse/rate-limit or access finding",
        _internet_facing,
        frozenset({FindingCategory.ABUSE_PREVENTION, FindingCategory.ACCESS_MANAGEMENT}),
    ),
    CoverageRule(
        "COV-002",
        "PII data asset without a privacy finding (retention/minimization/control mapping)",
        _pii_assets,
        frozenset({FindingCategory.PRIVACY}),
    ),
    CoverageRule(
        "COV-003",
        "Third-party dependency without a resilience/exit-plan or third-party scenario",
        _third_parties,
        frozenset({FindingCategory.THIRD_PARTY, FindingCategory.RESILIENCE}),
    ),
    CoverageRule(
        "COV-004",
        "Admin interface without a privileged-access/IAM finding",
        _admin_interfaces,
        frozenset({FindingCategory.ACCESS_MANAGEMENT}),
    ),
    CoverageRule(
        "COV-005",
        "GenAI component without prompt-injection/data-leakage/tool-abuse scenario",
        _genai_components,
        frozenset({FindingCategory.GENAI}),
    ),
    CoverageRule(
        "COV-006",
        "Trust-boundary-crossing flow not confirmed encrypted, no crypto/network finding",
        _unencrypted_or_unknown_flows,
        frozenset({FindingCategory.CRYPTOGRAPHY, FindingCategory.NETWORK}),
    ),
)


def check_coverage(
    inventory: AssetInventory,
    findings: list[RiskFinding],
    rules: tuple[CoverageRule, ...] = DEFAULT_RULES,
) -> list[CoverageGap]:
    """Return one gap per (rule, triggering entity) not covered by a finding.

    An entity is covered when at least one finding has a matching category
    AND references the entity in ``affected_asset_ids``.
    """
    gaps: list[CoverageGap] = []
    for rule in rules:
        for entity_id in rule.trigger(inventory):
            covered = any(
                f.category in rule.expected_categories
                and entity_id in f.affected_asset_ids
                for f in findings
            )
            if not covered:
                gaps.append(
                    CoverageGap(rule.rule_id, rule.description, entity_id,
                                rule.expected_categories)
                )
    return gaps
