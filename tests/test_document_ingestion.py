from riskos.ids import stable_id
from riskos.intake import classify_document, ingest_directory
from riskos.schemas.artifacts import DocumentType


def test_markdown_ingestion_preserves_headings_and_classifies(tmp_path):
    (tmp_path / "system-architecture.md").write_text(
        "# Overview\n\nPayments platform.\n\n"
        "## Trust boundaries\n\nThe public API crosses a trust boundary.\n",
        encoding="utf-8",
    )

    corpus = ingest_directory(tmp_path, stable_id("assessment", "docs"))

    assert len(corpus.documents) == 1
    assert corpus.documents[0].document_type == DocumentType.ARCHITECTURE
    assert [chunk.heading for chunk in corpus.chunks] == ["Overview", "Trust boundaries"]
    assert corpus.documents[0].chunk_ids == [chunk.chunk_id for chunk in corpus.chunks]


def test_chunking_respects_size_limit(tmp_path):
    (tmp_path / "technical-spec.txt").write_text("A" * 450, encoding="utf-8")

    corpus = ingest_directory(
        tmp_path, stable_id("assessment", "chunking"), max_chunk_chars=200
    )

    assert [len(chunk.text) for chunk in corpus.chunks] == [200, 200, 50]


def test_normalized_chunks_have_stable_ids_across_line_endings(tmp_path):
    path = tmp_path / "network.txt"
    path.write_bytes(b"Network design\r\n\r\nFirewall rules\r\n")
    first = ingest_directory(tmp_path, stable_id("assessment", "stable"))
    path.write_bytes(b"Network design\n\nFirewall rules\n")
    second = ingest_directory(tmp_path, stable_id("assessment", "stable"), version=2)

    assert first.artifact_id == second.artifact_id
    assert (first.version, second.version) == (1, 2)
    assert first.documents[0].document_id == second.documents[0].document_id
    assert first.documents[0].sha256 != second.documents[0].sha256
    assert first.chunks == second.chunks


def test_unsupported_and_empty_documents_become_issues(tmp_path):
    (tmp_path / "diagram.png").write_bytes(b"not-an-image")
    (tmp_path / "empty.txt").write_text(" \n", encoding="utf-8")

    corpus = ingest_directory(tmp_path, stable_id("assessment", "issues"))
    by_path = {issue.source_path: issue.code for issue in corpus.issues}

    assert corpus.documents == []
    assert by_path == {
        "diagram.png": "unsupported_media_type",
        "empty.txt": "empty_document",
    }


def test_heading_only_markdown_still_produces_a_chunk(tmp_path):
    (tmp_path / "outline.md").write_text("# Architecture", encoding="utf-8")

    corpus = ingest_directory(tmp_path, stable_id("assessment", "outline"))

    assert len(corpus.chunks) == 1
    assert corpus.chunks[0].text == "# Architecture"


def test_document_classifier_is_deterministic():
    assert classify_document("SATS.md", "Security assessment") == DocumentType.SATS
    assert classify_document("unknown.txt", "ordinary notes") == DocumentType.OTHER
