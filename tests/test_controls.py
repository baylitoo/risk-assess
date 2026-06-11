"""Tests for the internal control catalog and deterministic matcher."""

from __future__ import annotations

from pathlib import Path

import pytest

from riskos.controls.catalog import CatalogError, ControlCatalog
from riskos.controls.matcher import map_controls, suggest_controls
from riskos.ids import stable_id
from riskos.schemas.artifacts import (
    FindingCategory,
    Producer,
    RiskFinding,
    RiskRegister,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "config" / "control_catalog.yaml"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def catalog() -> ControlCatalog:
    return ControlCatalog.load(CATALOG_PATH)


def _make_finding(category: FindingCategory) -> RiskFinding:
    return RiskFinding(
        finding_id=stable_id("finding", category.value, "test-asset"),
        title=f"Test finding: {category.value}",
        category=category,
        scenario="A test risk scenario.",
    )


def _make_register(categories: list[FindingCategory]) -> RiskRegister:
    findings = [_make_finding(cat) for cat in categories]
    return RiskRegister(
        artifact_id=stable_id("artifact", "test", "register", "1"),
        assessment_id=stable_id("assessment", "test"),
        phase="risk_register",
        producer=Producer(agent="test"),
        findings=findings,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_catalog_loads(catalog: ControlCatalog) -> None:
    """ControlCatalog.load succeeds and returns at least 20 entries."""
    assert len(catalog) >= 20


def test_all_categories_covered(catalog: ControlCatalog) -> None:
    """Every FindingCategory has at least one catalog entry."""
    missing = []
    for category in FindingCategory:
        entries = catalog.entries_for_category(category)
        if not entries:
            missing.append(category.value)
    assert not missing, f"Categories with no catalog entries: {missing}"


def test_suggest_controls_vulnerability(catalog: ControlCatalog) -> None:
    """A VULNERABILITY finding returns at least one suggested control."""
    finding = _make_finding(FindingCategory.VULNERABILITY)
    controls = suggest_controls(finding, catalog)
    assert len(controls) >= 1
    # All returned controls must be proper Control entities with stable IDs
    for ctl in controls:
        assert ctl.id.startswith("ctl-"), f"Expected ctl- prefix, got {ctl.id!r}"


def test_suggest_controls_privacy(catalog: ControlCatalog) -> None:
    """A PRIVACY finding returns controls applicable to the privacy category."""
    finding = _make_finding(FindingCategory.PRIVACY)
    controls = suggest_controls(finding, catalog)
    assert len(controls) >= 1
    # All returned controls must come from entries that list 'privacy'
    privacy_refs = {
        e.taxonomy_ref
        for e in catalog.entries_for_category(FindingCategory.PRIVACY)
    }
    for ctl in controls:
        assert ctl.taxonomy_ref in privacy_refs, (
            f"Control {ctl.taxonomy_ref} not applicable to privacy"
        )


def test_map_controls(catalog: ControlCatalog) -> None:
    """map_controls returns a new register with mapped_control_ids on all findings."""
    register = _make_register(list(FindingCategory))
    mapped = map_controls(register, catalog)

    # Should be a new object
    assert mapped is not register

    # All findings must have at least one mapped control ID
    for finding in mapped.findings:
        assert finding.mapped_control_ids, (
            f"Finding {finding.finding_id} (category={finding.category}) "
            "has no mapped_control_ids"
        )
        # IDs must use the ctl- prefix
        for cid in finding.mapped_control_ids:
            assert cid.startswith("ctl-"), (
                f"mapped_control_id {cid!r} does not have ctl- prefix"
            )

    # Original register must be unmodified
    for finding in register.findings:
        assert finding.mapped_control_ids == []


def test_controls_sorted_by_framework_coverage(catalog: ControlCatalog) -> None:
    """Controls with more framework_refs appear before those with fewer."""
    # Use VULNERABILITY which has multiple controls with differing framework counts
    finding = _make_finding(FindingCategory.VULNERABILITY)
    controls = suggest_controls(finding, catalog)
    assert len(controls) >= 2, "Need at least 2 controls to test ordering"

    # Retrieve framework counts from the catalog entries for validation
    entry_map = {
        e.taxonomy_ref: e
        for e in catalog.entries_for_category(FindingCategory.VULNERABILITY)
    }
    ref_counts = [len(entry_map[c.taxonomy_ref].framework_refs) for c in controls]

    # Sequence must be non-increasing
    for i in range(len(ref_counts) - 1):
        assert ref_counts[i] >= ref_counts[i + 1], (
            f"Controls not sorted by framework coverage at position {i}: "
            f"{ref_counts[i]} < {ref_counts[i + 1]}"
        )


def test_catalog_error_unknown_category(tmp_path: Path) -> None:
    """CatalogError is raised for an unknown FindingCategory value."""
    bad_yaml = tmp_path / "bad_catalog.yaml"
    bad_yaml.write_text(
        "- taxonomy_ref: CTL-BAD-001\n"
        "  name: Bad Control\n"
        "  description: Test\n"
        "  framework_refs: {}\n"
        "  applicable_categories:\n"
        "    - not_a_real_category\n"
        "  strength_when_present: moderate\n",
        encoding="utf-8",
    )
    with pytest.raises(CatalogError, match="unknown category"):
        ControlCatalog.load(bad_yaml)


def test_catalog_error_missing_file() -> None:
    """CatalogError is raised when the catalog file does not exist."""
    with pytest.raises(CatalogError, match="not found"):
        ControlCatalog.load("/nonexistent/path/catalog.yaml")
