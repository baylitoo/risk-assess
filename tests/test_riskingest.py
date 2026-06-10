import json

from riskos.cli.riskingest import main


def test_riskingest_outputs_document_corpus(tmp_path, capsys):
    (tmp_path / "network.md").write_text(
        "# Network\n\nInternet-facing subnet and firewall.",
        encoding="utf-8",
    )

    code = main([str(tmp_path), "--assessment-id", "asm-test"])

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["artifact_type"] == "document_corpus"
    assert payload["documents"][0]["document_type"] == "network"
    assert payload["chunks"][0]["heading"] == "Network"


def test_riskingest_writes_output_file(tmp_path, capsys):
    source = tmp_path / "source"
    source.mkdir()
    (source / "notes.txt").write_text("ordinary notes", encoding="utf-8")
    output = tmp_path / "out" / "corpus.json"

    code = main(
        [
            str(source),
            "--assessment-id",
            "asm-test",
            "--version",
            "2",
            "--output",
            str(output),
        ]
    )

    assert code == 0
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["artifact_type"] == "document_corpus"
    assert saved["version"] == 2
    assert json.loads(capsys.readouterr().out)["artifact_type"] == "document_corpus"


def test_riskingest_rejects_missing_directory(tmp_path, capsys):
    code = main([str(tmp_path / "missing"), "--assessment-id", "asm-test"])

    assert code == 2
    assert "not found" in json.loads(capsys.readouterr().err)["error"]
