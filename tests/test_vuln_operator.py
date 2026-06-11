"""Tests for the vuln operator mirror, correlate, and worker."""

import json
from pathlib import Path

import pytest

from riskos.schemas.artifacts import FindingCategory
from riskos.vuln.mirror import CveRecord, EpssScoreMirror, KevMirror, NvdMirror


@pytest.fixture()
def mirror_dir(tmp_path) -> Path:
    """Minimal mirror with two CVEs: one CVSS 9.8 (critical), one 5.0 (medium)."""
    nvd_dir = tmp_path / "nvd"
    nvd_dir.mkdir()

    (nvd_dir / "CVE-2026-0001.json").write_text(
        json.dumps({
            "description": "Critical RCE in ExampleHTTPd",
            "cvss_v3": 9.8,
            "published": "2026-01-01T00:00:00Z",
            "cpe_uris": ["cpe:2.3:a:example:httpdaemon:2.4:*:*:*:*:*:*:*"],
        }),
        encoding="utf-8",
    )
    (nvd_dir / "CVE-2026-0002.json").write_text(
        json.dumps({
            "description": "Medium XSS in ExampleHTTPd",
            "cvss_v3": 5.0,
            "published": "2026-02-01T00:00:00Z",
            "cpe_uris": ["cpe:2.3:a:example:httpdaemon:2.4:*:*:*:*:*:*:*"],
        }),
        encoding="utf-8",
    )

    kev_entries = [{"cveID": "CVE-2026-0001", "vendorProject": "Example", "product": "HTTPd"}]
    (tmp_path / "kev.json").write_text(
        json.dumps({"vulnerabilities": kev_entries}), encoding="utf-8"
    )

    epss_data = {
        "CVE-2026-0001": {"epss": 0.85, "percentile": 0.98},
        "CVE-2026-0002": {"epss": 0.02, "percentile": 0.30},
    }
    (tmp_path / "epss.json").write_text(json.dumps(epss_data), encoding="utf-8")

    return tmp_path


class TestNvdMirror:
    def test_get_existing_cve(self, mirror_dir):
        nvd = NvdMirror(root=mirror_dir)
        record = nvd.get("CVE-2026-0001")
        assert record is not None
        assert record.cve_id == "CVE-2026-0001"
        assert record.cvss_v3 == 9.8

    def test_get_missing_cve_returns_none(self, mirror_dir):
        nvd = NvdMirror(root=mirror_dir)
        assert nvd.get("CVE-9999-9999") is None

    def test_check_freshness_missing_meta_returns_false(self, mirror_dir):
        nvd = NvdMirror(root=mirror_dir)
        assert nvd.check_freshness() is False


class TestKevMirror:
    def test_is_listed_true(self, mirror_dir):
        kev = KevMirror(root=mirror_dir)
        assert kev.is_listed("CVE-2026-0001") is True

    def test_is_listed_false(self, mirror_dir):
        kev = KevMirror(root=mirror_dir)
        assert kev.is_listed("CVE-2026-0002") is False

    def test_get_entry_returns_dict(self, mirror_dir):
        kev = KevMirror(root=mirror_dir)
        entry = kev.get_entry("CVE-2026-0001")
        assert entry is not None
        assert entry["cveID"] == "CVE-2026-0001"


class TestEpssScoreMirror:
    def test_score_returns_float(self, mirror_dir):
        epss = EpssScoreMirror(root=mirror_dir)
        assert epss.score("CVE-2026-0001") == pytest.approx(0.85)

    def test_score_missing_returns_none(self, mirror_dir):
        epss = EpssScoreMirror(root=mirror_dir)
        assert epss.score("CVE-9999-9999") is None


class TestCorrelateInventory:
    def test_critical_cve_produces_finding(self, inventory, mirror_dir):
        from riskos.vuln.correlate import correlate_inventory
        api = inventory.components[0]
        api_with_cpe = api.model_copy(update={
            "cpe_candidates": ["cpe:2.3:a:example:httpdaemon:2.4:*:*:*:*:*:*:*"]
        })
        inv = inventory.model_copy(update={"components": [api_with_cpe] + inventory.components[1:]})

        nvd = NvdMirror(root=mirror_dir)
        kev = KevMirror(root=mirror_dir)
        epss = EpssScoreMirror(root=mirror_dir)
        findings, evidence = correlate_inventory(inv, nvd, kev, epss, cvss_threshold=7.0)

        assert len(findings) == 1
        assert findings[0].category == FindingCategory.VULNERABILITY
        assert "CVE-2026-0001" in findings[0].threat_refs
        assert findings[0].band == "critical"

    def test_medium_cve_skipped_below_threshold(self, inventory, mirror_dir):
        from riskos.vuln.correlate import correlate_inventory
        api = inventory.components[0]
        api_with_cpe = api.model_copy(update={
            "cpe_candidates": ["cpe:2.3:a:example:httpdaemon:2.4:*:*:*:*:*:*:*"]
        })
        inv = inventory.model_copy(update={"components": [api_with_cpe] + inventory.components[1:]})

        nvd = NvdMirror(root=mirror_dir)
        kev = KevMirror(root=mirror_dir)
        epss = EpssScoreMirror(root=mirror_dir)
        findings, _ = correlate_inventory(inv, nvd, kev, epss, cvss_threshold=7.0)

        cve_ids = [r for f in findings for r in f.threat_refs]
        assert "CVE-2026-0002" not in cve_ids

    def test_no_cpe_candidates_produces_no_findings(self, inventory, mirror_dir):
        from riskos.vuln.correlate import correlate_inventory
        nvd = NvdMirror(root=mirror_dir)
        kev = KevMirror(root=mirror_dir)
        epss = EpssScoreMirror(root=mirror_dir)
        findings, evidence = correlate_inventory(inventory, nvd, kev, epss)

        assert findings == []
        assert evidence == []

    def test_kev_listed_cve_included_regardless_of_cvss(self, inventory, mirror_dir, tmp_path):
        """CVE in KEV with low CVSS is still emitted."""
        from riskos.vuln.correlate import correlate_inventory

        nvd_dir = tmp_path / "nvd"
        nvd_dir.mkdir(exist_ok=True)
        (nvd_dir / "CVE-2026-LOW.json").write_text(
            json.dumps({
                "description": "Low CVSS but in KEV",
                "cvss_v3": 4.0,
                "cpe_uris": ["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"],
            }),
            encoding="utf-8",
        )
        (tmp_path / "kev.json").write_text(
            json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-LOW"}]}),
            encoding="utf-8",
        )
        (tmp_path / "epss.json").write_text(json.dumps({}), encoding="utf-8")

        api = inventory.components[0]
        api_with_cpe = api.model_copy(update={
            "cpe_candidates": ["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"]
        })
        inv = inventory.model_copy(update={"components": [api_with_cpe] + inventory.components[1:]})

        nvd = NvdMirror(root=tmp_path)
        kev = KevMirror(root=tmp_path)
        epss = EpssScoreMirror(root=tmp_path)
        findings, _ = correlate_inventory(inv, nvd, kev, epss, cvss_threshold=7.0)

        assert any("CVE-2026-LOW" in f.threat_refs for f in findings)


class TestVulnWorker:
    def test_worker_emits_artifact(self, inventory, mirror_dir, tmp_path):
        from riskos.vuln.worker import VulnConfig, VulnWorker
        from riskos.runtime import AgentHarness, ArtifactWorkspace, JsonlAuditLog
        from riskos.policy import PolicyEngine
        from tests.conftest import REPO_ROOT

        api = inventory.components[0]
        api_with_cpe = api.model_copy(update={
            "cpe_candidates": ["cpe:2.3:a:example:httpdaemon:2.4:*:*:*:*:*:*:*"]
        })
        inv = inventory.model_copy(update={"components": [api_with_cpe] + inventory.components[1:]})

        workspace = ArtifactWorkspace(tmp_path / "workspace", inv.assessment_id)
        audit = JsonlAuditLog(tmp_path / "audit.jsonl")
        policy = PolicyEngine.load_dir(REPO_ROOT / "policies")
        harness = AgentHarness("vuln_operator", policy, workspace, audit)

        worker = VulnWorker(harness, VulnConfig(mirror_root=str(mirror_dir)))
        result = worker.run(inv)

        assert result.finding_count == 1
        assert result.vuln_artifact_id != ""
