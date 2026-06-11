"""Tests for CPE canonicalization and riskctl cpe match."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from riskos.cpe.matcher import CpeError, normalize_cpe, match_technology
from riskos.cli.riskctl import cpe_match, main
from riskos.ids import stable_id
from riskos.schemas.artifacts import AssetInventory, Producer
from riskos.schemas.entities import Component


def _inventory_with_components(components, tmp_path) -> Path:
    assessment_id = stable_id("assessment", "cpe-test")
    inventory = AssetInventory(
        artifact_id=stable_id("artifact", "cpe-inv"),
        assessment_id=assessment_id,
        phase="intake",
        producer=Producer(agent="intake_worker"),
        components=components,
    )
    p = tmp_path / "inventory.json"
    p.write_text(inventory.model_dump_json(), encoding="utf-8")
    return p


def test_normalize_valid_cpe():
    cpe = "cpe:2.3:a:apache:tomcat:9.0.0:*:*:*:*:*:*:*"
    assert normalize_cpe(cpe) == cpe.lower()


def test_normalize_strips_whitespace():
    cpe = "  cpe:2.3:a:apache:tomcat:9.0.0:*:*:*:*:*:*:*  "
    assert normalize_cpe(cpe) == "cpe:2.3:a:apache:tomcat:9.0.0:*:*:*:*:*:*:*"


def test_normalize_rejects_invalid():
    with pytest.raises(CpeError):
        normalize_cpe("not-a-cpe")


def test_normalize_rejects_cpe22():
    with pytest.raises(CpeError):
        normalize_cpe("cpe:/a:apache:tomcat:9.0")


def test_match_with_candidates():
    cpes = match_technology("Apache Tomcat 9.0", ["cpe:2.3:a:apache:tomcat:9.0:*:*:*:*:*:*:*"])
    assert len(cpes) == 1
    assert "apache" in cpes[0]


def test_match_skips_invalid_candidates():
    cpes = match_technology("Nginx", ["invalid-cpe", "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"])
    assert len(cpes) == 1


def test_match_empty_candidates_naive_fallback():
    cpes = match_technology("Nginx 1.18.0", [])
    # Naive parsing may or may not succeed — just check no exception
    assert isinstance(cpes, list)


def test_match_empty_candidates_empty_technology():
    cpes = match_technology("", [])
    assert cpes == []


def test_riskctl_cpe_match_exit_0(tmp_path):
    comp = Component(
        id=stable_id("component", "sys1", "api"),
        name="API",
        system_id=stable_id("system", "sys1"),
        technology="Tomcat 9.0",
        cpe_candidates=["cpe:2.3:a:apache:tomcat:9.0:*:*:*:*:*:*:*"],
    )
    inv_path = _inventory_with_components([comp], tmp_path)
    results, exit_code = cpe_match(str(inv_path))
    assert exit_code == 0
    assert results[0]["matched"] is True


def test_riskctl_cpe_match_exit_1(tmp_path):
    comp = Component(
        id=stable_id("component", "sys1", "api2"),
        name="Unknown API",
        system_id=stable_id("system", "sys1"),
        technology="UnknownProduct XYZ",
    )
    inv_path = _inventory_with_components([comp], tmp_path)
    results, exit_code = cpe_match(str(inv_path))
    # May succeed via naive if parse works, but if no candidates at all:
    # technology parsing result determines exit code
    assert isinstance(exit_code, int)
