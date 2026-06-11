"""Document parser service — entry point.

parse_document() is the single public function. It routes a PDF or DOCX
file through text or vision extraction and returns artifact-schema chunks
ready to insert into a DocumentCorpus.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from riskos.ids import stable_id
from riskos.schemas.artifacts import DocumentChunk, ImageChunk

from .chunker import paragraphs_to_chunks, pdf_pages_to_chunks
from .config import ParseConfig
from .models import ParsedDocument
from .router import classify_pdf
from .text import extract_docx_paragraphs, extract_pdf_pages
from .vision import render_pdf_pages_to_jpeg_b64

_DEFAULT_CONFIG = ParseConfig()


def parse_document(
    path: Path,
    document_id: str,
    config: ParseConfig | None = None,
    max_chunk_chars: int = 4_000,
) -> tuple[list[DocumentChunk], list[ImageChunk]]:
    """Parse a PDF or DOCX file into artifact-schema chunk lists.

    Returns (text_chunks, image_chunks). Exactly one list will be non-empty
    depending on the path taken by the router:
      - text path  → text_chunks populated, image_chunks empty
      - vision path → image_chunks populated, text_chunks empty
    DOCX always takes the text path.
    """
    cfg = config or _DEFAULT_CONFIG
    suffix = path.suffix.casefold()

    if suffix == ".docx":
        paragraphs = extract_docx_paragraphs(path)
        chunks = paragraphs_to_chunks(document_id, paragraphs, max_chunk_chars)
        return chunks, []

    if suffix == ".pdf":
        return _parse_pdf(path, document_id, cfg, max_chunk_chars)

    raise ValueError(f"unsupported file type for parser: {path.suffix!r}")


def _parse_pdf(
    path: Path,
    document_id: str,
    config: ParseConfig,
    max_chunk_chars: int,
) -> tuple[list[DocumentChunk], list[ImageChunk]]:
    # Always extract text first for routing metrics (fast even on scanned PDFs)
    pages = extract_pdf_pages(path)
    path_choice = classify_pdf(pages, config)

    if path_choice == "text":
        chunks = pdf_pages_to_chunks(document_id, pages, max_chunk_chars)
        return chunks, []

    # Vision path: render pages to JPEG
    jpeg_b64_list = render_pdf_pages_to_jpeg_b64(path, config)
    image_chunks = _build_image_chunks(document_id, jpeg_b64_list)
    return [], image_chunks


def _build_image_chunks(
    document_id: str, jpeg_b64_list: list[str]
) -> list[ImageChunk]:
    chunks: list[ImageChunk] = []
    for page_num, b64 in enumerate(jpeg_b64_list, start=1):
        raw = base64.b64decode(b64)
        sha = hashlib.sha256(raw).hexdigest()
        chunk_id = stable_id("image_chunk", document_id, str(page_num))
        chunks.append(
            ImageChunk(
                chunk_id=chunk_id,
                document_id=document_id,
                page_num=page_num,
                media_type="image/jpeg",
                data_b64=b64,
                sha256=sha,
                size_bytes=len(raw),
            )
        )
    return chunks


__all__ = ["parse_document", "ParseConfig", "ParsedDocument"]
