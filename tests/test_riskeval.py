import json

from riskos.cli.riskeval import main


def test_riskeval_cli_passes_checked_in_corpus(capsys, repo_root):
    code = main(
        [
            str(repo_root / "evals" / "corpus"),
            "--thresholds",
            str(repo_root / "config" / "eval_thresholds.yaml"),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["passed"] is True


def test_riskeval_cli_returns_one_for_quality_gate_failure(tmp_path, capsys):
    case = {
        "case_id": "missed-risk",
        "split": "regression",
        "golden_findings": [
            {
                "finding_id": "g1",
                "title": "missed privacy risk",
                "category": "privacy",
                "scenario": "test",
                "affected_asset_ids": ["dat-pii"],
            }
        ],
        "produced_findings": [],
    }
    (tmp_path / "case.json").write_text(json.dumps(case), encoding="utf-8")

    code = main([str(tmp_path)])

    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["passed"] is False
    assert payload["violations"]


def test_riskeval_cli_returns_two_for_invalid_corpus(tmp_path, capsys):
    code = main([str(tmp_path)])

    payload = json.loads(capsys.readouterr().err)
    assert code == 2
    assert "no eval cases" in payload["error"]
