"""Tests for the parser chunker."""
from __future__ import annotations

from riskos.parsers.chunker import paragraphs_to_chunks, pdf_pages_to_chunks
from riskos.parsers.models import ParsedPage


def _page(page_num: int, text: str) -> ParsedPage:
    return ParsedPage(page_num=page_num, text=text)


def test_pdf_pages_produce_one_chunk_per_page():
    pages = [_page(1, "System A"), _page(2, "System B"), _page(3, "System C")]
    chunks = pdf_pages_to_chunks("doc-001", pages)
    assert len(chunks) == 3
    texts = {c.text for c in chunks}
    assert "System A" in texts
    assert "System C" in texts


def test_empty_pages_are_skipped():
    pages = [_page(1, ""), _page(2, "Real content here"), _page(3, "  ")]
    chunks = pdf_pages_to_chunks("doc-002", pages)
    assert len(chunks) == 1
    assert chunks[0].text == "Real content here"


def test_oversized_page_is_split():
    big_text = "Word " * 1000  # ~5000 chars
    pages = [_page(1, big_text)]
    chunks = pdf_pages_to_chunks("doc-003", pages, max_chunk_chars=2_000)
    assert len(chunks) > 1
    for c in chunks:
        assert len(c.text) <= 2_000


def test_chunk_ids_are_stable_across_calls():
    pages = [_page(1, "Stable content")]
    c1 = pdf_pages_to_chunks("doc-stable", pages)
    c2 = pdf_pages_to_chunks("doc-stable", pages)
    assert c1[0].chunk_id == c2[0].chunk_id


def test_chunk_ordinals_are_sequential():
    pages = [_page(i + 1, f"Page text {i}") for i in range(5)]
    chunks = pdf_pages_to_chunks("doc-seq", pages)
    ordinals = [c.ordinal for c in chunks]
    assert ordinals == list(range(len(chunks)))


def test_paragraphs_to_chunks_basic():
    paras = [
        "First paragraph about Kong API Gateway.",
        "Second paragraph about PostgreSQL database.",
        "Third paragraph about SWIFT adapter.",
    ]
    chunks = paragraphs_to_chunks("doc-para", paras, max_chunk_chars=500)
    assert len(chunks) >= 1
    combined = " ".join(c.text for c in chunks)
    assert "Kong" in combined
    assert "SWIFT" in combined


def test_paragraphs_respects_size_limit():
    paras = ["X" * 300] * 10  # 10 × 300 = 3000 chars, limit 500
    chunks = paragraphs_to_chunks("doc-limit", paras, max_chunk_chars=500)
    for c in chunks:
        assert len(c.text) <= 500


def test_chunk_sha256_is_consistent():
    pages = [_page(1, "SHA test content")]
    chunks = pdf_pages_to_chunks("doc-sha", pages)
    import hashlib
    expected = hashlib.sha256("SHA test content".encode()).hexdigest()
    assert chunks[0].sha256 == expected
