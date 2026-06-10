import json

import pytest

from riskos.cli import riskctl
from riskos.cli.riskctl import main
from tests.conftest import REPO_ROOT


@pytest.fixture(autouse=True)
def _mirror(monkeypatch):
    monkeypatch.setenv("RISKOS_MIRROR_DIR", str(REPO_ROOT / "data" / "mirror"))


def _run(capsys, *argv) -> tuple[int, dict]:
    code = main(list(argv))
    out = capsys.readouterr().out
    return code, json.loads(out)


def test_cve_get(capsys):
    code, payload = _run(capsys, "cve", "get", "CVE-2026-0001")
    assert code == 0
    assert payload["found"] is True
    assert payload["record"]["cvss_v3"] == 9.8


def test_missing_cve_is_data_gap_not_error(capsys):
    code, payload = _run(capsys, "cve", "get", "CVE-1999-9999")
    assert code == 0
    assert payload == {"cve_id": "CVE-1999-9999", "found": False}


def test_kev_check(capsys):
    code, payload = _run(capsys, "kev", "check", "CVE-2026-0001")
    assert code == 0
    assert payload["listed"] is True

    code, payload = _run(capsys, "kev", "check", "CVE-2026-0002")
    assert payload["listed"] is False


def test_epss_get(capsys):
    code, payload = _run(capsys, "epss", "get", "CVE-2026-0002")
    assert code == 0
    assert payload["epss"] == 0.03


def test_triage_priority_heuristic(capsys):
    code, payload = _run(capsys, "triage",
                         "CVE-2026-0001", "CVE-2026-0002", "CVE-1999-9999")
    assert code == 0
    by_id = {r["cve_id"]: r for r in payload["results"]}
    assert by_id["CVE-2026-0001"]["priority"] == "P1_actively_exploited"
    assert by_id["CVE-2026-0002"]["priority"] == "P5_routine"
    assert by_id["CVE-1999-9999"]["priority"] == "P4_unknown_data_gap"


def test_triage_batch_limit(capsys):
    code = main(["triage"] + [f"CVE-2026-{i:04d}" for i in range(60)])
    err = capsys.readouterr().err
    assert code == 2
    assert "max 50" in json.loads(err)["error"]


def test_triage_loads_shared_mirror_files_once(monkeypatch):
    reads: list[str] = []
    original = riskctl._read_json

    def tracked_read(path):
        reads.append(path.name)
        return original(path)

    monkeypatch.setattr(riskctl, "_read_json", tracked_read)

    riskctl.triage(["CVE-2026-0001", "CVE-2026-0002", "CVE-1999-9999"])

    assert reads.count("kev.json") == 1
    assert reads.count("epss.json") == 1


def test_triage_loads_duplicate_cve_record_once(monkeypatch):
    reads: list[str] = []
    original = riskctl._read_json

    def tracked_read(path):
        reads.append(path.name)
        return original(path)

    monkeypatch.setattr(riskctl, "_read_json", tracked_read)

    result = riskctl.triage(["CVE-2026-0001", "CVE-2026-0001"])

    assert result["count"] == 2
    assert reads.count("CVE-2026-0001.json") == 1
