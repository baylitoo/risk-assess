"""Deterministic control-to-finding matcher.

No LLM calls; purely structural matching on category overlap.
"""

from __future__ import annotations

from riskos.controls.catalog import ControlCatalog
from riskos.ids import stable_id
from riskos.schemas.artifacts import RiskFinding, RiskRegister
from riskos.schemas.entities import Control


def suggest_controls(finding: RiskFinding, catalog: ControlCatalog) -> list[Control]:
    """Return controls whose applicable_categories intersect with finding.category.

    Results are sorted by number of framework_refs descending (most
    framework-covered first), with taxonomy_ref as a tiebreaker to keep
    ordering deterministic across runs.
    """
    matching_entries = catalog.entries_for_category(finding.category)
    sorted_entries = sorted(
        matching_entries,
        key=lambda e: (-len(e.framework_refs), e.taxonomy_ref),
    )

    controls: list[Control] = []
    for entry in sorted_entries:
        controls.append(
            Control(
                id=stable_id("control", entry.taxonomy_ref),
                name=entry.name,
                description=entry.description,
                taxonomy_ref=entry.taxonomy_ref,
                framework_refs=entry.framework_refs,
                strength=entry.strength_when_present,
            )
        )
    return controls


def map_controls(register: RiskRegister, catalog: ControlCatalog) -> RiskRegister:
    """Return a new RiskRegister with mapped_control_ids populated for each finding.

    For each finding, ``mapped_control_ids`` is set to the stable IDs of the
    controls returned by :func:`suggest_controls`.  Findings that already had
    control IDs mapped are overwritten — this function is the authoritative
    mapper.

    The original register is never mutated.
    """
    updated_findings: list[RiskFinding] = []
    for finding in register.findings:
        suggested = suggest_controls(finding, catalog)
        control_ids = [c.id for c in suggested]
        updated_findings.append(
            finding.model_copy(update={"mapped_control_ids": control_ids})
        )

    return register.model_copy(update={"findings": updated_findings})
