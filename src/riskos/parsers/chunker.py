"""Structure-aware text → DocumentChunk conversion.

PDF pages become chunks directly (one page = one chunk, split if oversized).
DOCX paragraphs are grouped by size the same way the markdown chunker works.
"""
from __future__ import annotations

import hashlib
import re

from riskos.ids import stable_id
from riskos.schemas.artifacts import DocumentChunk

_BLANK_LINES = re.compile(r"\n\s*\n+")


def pdf_pages_to_chunks(
    document_id: str,
    pages: list,  # list[ParsedPage]
    max_chunk_chars: int = 4_000,
    ordinal_start: int = 0,
) -> list[DocumentChunk]:
    """One ParsedPage → one DocumentChunk (split if text exceeds max_chunk_chars)."""
    chunks: list[DocumentChunk] = []
    ordinal = ordinal_start
    for page in pages:
        text = page.text.strip()
        if not text:
            continue
        for part in _split_text(text, max_chunk_chars):
            heading = f"Page {page.page_num}"
            chunk_id = stable_id("chunk", document_id, str(ordinal), heading, part)
            chunks.append(
                DocumentChunk(
                    chunk_id=chunk_id,
                    document_id=document_id,
                    ordinal=ordinal,
                    heading=heading,
                    text=part,
                    sha256=_sha256(part),
                )
            )
            ordinal += 1
    return chunks


def paragraphs_to_chunks(
    document_id: str,
    paragraphs: list[str],
    max_chunk_chars: int = 4_000,
    ordinal_start: int = 0,
) -> list[DocumentChunk]:
    """Group DOCX paragraphs into chunks that respect max_chunk_chars."""
    chunks: list[DocumentChunk] = []
    ordinal = ordinal_start
    current = ""
    for para in paragraphs:
        candidate = f"{current}\n\n{para}".strip() if current else para
        if len(candidate) > max_chunk_chars and current:
            chunks.extend(_flush_chunk(document_id, ordinal, "", current, max_chunk_chars))
            ordinal += len(chunks) - ordinal_start - (ordinal - ordinal_start)
            current = para
        else:
            current = candidate
    if current:
        chunks.extend(_flush_chunk(document_id, ordinal, "", current, max_chunk_chars))
    return chunks


def _flush_chunk(
    document_id: str, ordinal: int, heading: str, text: str, max_chunk_chars: int
) -> list[DocumentChunk]:
    result = []
    for part in _split_text(text, max_chunk_chars):
        chunk_id = stable_id("chunk", document_id, str(ordinal), heading, part)
        result.append(
            DocumentChunk(
                chunk_id=chunk_id,
                document_id=document_id,
                ordinal=ordinal,
                heading=heading,
                text=part,
                sha256=_sha256(part),
            )
        )
        ordinal += 1
    return result


def _split_text(text: str, max_chars: int) -> list[str]:
    if len(text) <= max_chars:
        return [text]
    paragraphs = [p.strip() for p in _BLANK_LINES.split(text) if p.strip()]
    parts: list[str] = []
    current = ""
    for para in paragraphs:
        if len(para) > max_chars:
            if current:
                parts.append(current)
                current = ""
            parts.extend(
                para[i : i + max_chars]
                for i in range(0, len(para), max_chars)
                if para[i : i + max_chars].strip()
            )
            continue
        candidate = f"{current}\n\n{para}".strip() if current else para
        if len(candidate) > max_chars:
            parts.append(current)
            current = para
        else:
            current = candidate
    if current:
        parts.append(current)
    return parts or [text]


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
