"""Deterministic text-document normalization, classification, and chunking."""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

from riskos.ids import stable_id
from riskos.schemas.artifacts import (
    DocumentChunk,
    DocumentCorpus,
    DocumentRecord,
    DocumentType,
    ImageChunk,
    IngestionIssue,
    Producer,
)

_SUPPORTED_MEDIA_TYPES = {
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".txt": "text/plain",
}
_SUPPORTED_IMAGE_MEDIA_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
}
_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
_BLANK_LINES = re.compile(r"\n\s*\n+")
_CLASSIFIERS: tuple[tuple[DocumentType, tuple[str, ...]], ...] = (
    (DocumentType.SATS, ("sats", "security assessment", "security architecture")),
    (DocumentType.NETWORK, ("network", "firewall", "subnet", "routing")),
    (DocumentType.ARCHITECTURE, ("architecture", "data flow", "trust boundary")),
    (DocumentType.TECHNICAL_SPEC, ("technical spec", "design specification", "api spec")),
    (DocumentType.POLICY, ("policy", "standard", "control requirement")),
    (DocumentType.PAST_ASSESSMENT, ("past assessment", "risk assessment", "signed assessment")),
)


class IngestionError(Exception):
    pass


def ingest_directory(
    directory: str | Path,
    assessment_id: str,
    producer: Producer | None = None,
    max_chunk_chars: int = 2_000,
    version: int = 1,
) -> DocumentCorpus:
    """Normalize all supported documents below a directory into one corpus."""
    root = Path(directory)
    if not root.is_dir():
        raise IngestionError(f"document directory not found: {root}")
    if max_chunk_chars < 100:
        raise IngestionError("max_chunk_chars must be at least 100")
    if version < 1:
        raise IngestionError("version must be positive")

    documents: list[DocumentRecord] = []
    chunks: list[DocumentChunk] = []
    image_chunks: list[ImageChunk] = []
    issues: list[IngestionIssue] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            issues.append(
                IngestionIssue(
                    source_path=relative,
                    code="symlink_rejected",
                    message="Symbolic links are not ingested.",
                )
            )
            continue
        if not path.is_file():
            continue
        suffix = path.suffix.casefold()
        image_media_type = _SUPPORTED_IMAGE_MEDIA_TYPES.get(suffix)
        if image_media_type is not None:
            try:
                raw = path.read_bytes()
            except OSError as exc:
                issues.append(
                    IngestionIssue(
                        source_path=relative,
                        code="unreadable_document",
                        message=str(exc),
                    )
                )
                continue
            document_id = stable_id("document", assessment_id, relative)
            sha256 = _sha256(raw)
            chunk_id = stable_id("image_chunk", document_id, sha256)
            image_chunks.append(
                ImageChunk(
                    chunk_id=chunk_id,
                    document_id=document_id,
                    media_type=image_media_type,
                    data_b64=base64.b64encode(raw).decode("ascii"),
                    sha256=sha256,
                    size_bytes=len(raw),
                )
            )
            documents.append(
                DocumentRecord(
                    document_id=document_id,
                    source_path=relative,
                    filename=path.name,
                    media_type=image_media_type,
                    document_type=classify_document(relative, ""),
                    sha256=sha256,
                    size_bytes=len(raw),
                    chunk_ids=[chunk_id],
                )
            )
            continue
        media_type = _SUPPORTED_MEDIA_TYPES.get(suffix)
        if media_type is None:
            issues.append(
                IngestionIssue(
                    source_path=relative,
                    code="unsupported_media_type",
                    message=f"Unsupported file extension {path.suffix or '<none>'!r}.",
                )
            )
            continue
        try:
            raw = path.read_bytes()
            text = _normalize_text(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            issues.append(
                IngestionIssue(
                    source_path=relative,
                    code="unreadable_document",
                    message=str(exc),
                )
            )
            continue
        if not text:
            issues.append(
                IngestionIssue(
                    source_path=relative,
                    code="empty_document",
                    message="Document contains no normalized text.",
                )
            )
            continue

        document_id = stable_id("document", assessment_id, relative)
        document_chunks = _chunk_document(
            document_id, text, media_type == "text/markdown", max_chunk_chars
        )
        documents.append(
            DocumentRecord(
                document_id=document_id,
                source_path=relative,
                filename=path.name,
                media_type=media_type,
                document_type=classify_document(relative, text),
                sha256=_sha256(raw),
                size_bytes=len(raw),
                chunk_ids=[chunk.chunk_id for chunk in document_chunks],
            )
        )
        chunks.extend(document_chunks)

    return DocumentCorpus(
        artifact_id=stable_id("artifact", assessment_id, "document_corpus"),
        assessment_id=assessment_id,
        phase="intake",
        producer=producer or Producer(agent="intake_worker"),
        version=version,
        documents=documents,
        chunks=chunks,
        image_chunks=image_chunks,
        issues=issues,
    )


def classify_document(source_path: str, text: str) -> DocumentType:
    """Classify a document from deterministic filename and content signals."""
    sample = f"{source_path}\n{text[:4_000]}".casefold()
    best_type = DocumentType.OTHER
    best_score = 0
    for document_type, terms in _CLASSIFIERS:
        score = sum(term in sample for term in terms)
        if score > best_score:
            best_type = document_type
            best_score = score
    return best_type


def _chunk_document(
    document_id: str,
    text: str,
    markdown: bool,
    max_chunk_chars: int,
) -> list[DocumentChunk]:
    sections = _markdown_sections(text) if markdown else [("", text)]
    chunks: list[DocumentChunk] = []
    ordinal = 0
    for heading, body in sections:
        for part in _split_text(body, max_chunk_chars):
            chunk_id = stable_id("chunk", document_id, str(ordinal), heading, part)
            chunks.append(
                DocumentChunk(
                    chunk_id=chunk_id,
                    document_id=document_id,
                    ordinal=ordinal,
                    heading=heading,
                    text=part,
                    sha256=_sha256(part.encode("utf-8")),
                )
            )
            ordinal += 1
    if not chunks:
        for part in _split_text(text, max_chunk_chars):
            chunk_id = stable_id("chunk", document_id, str(ordinal), "", part)
            chunks.append(
                DocumentChunk(
                    chunk_id=chunk_id,
                    document_id=document_id,
                    ordinal=ordinal,
                    text=part,
                    sha256=_sha256(part.encode("utf-8")),
                )
            )
            ordinal += 1
    return chunks


def _markdown_sections(text: str) -> list[tuple[str, str]]:
    sections: list[tuple[str, str]] = []
    heading = ""
    body: list[str] = []
    for line in text.splitlines():
        match = _HEADING.match(line)
        if match:
            if body_text := "\n".join(body).strip():
                sections.append((heading, body_text))
            heading = match.group(2).strip()
            body = []
        else:
            body.append(line)
    if body_text := "\n".join(body).strip():
        sections.append((heading, body_text))
    return sections


def _split_text(text: str, max_chars: int) -> list[str]:
    paragraphs = [part.strip() for part in _BLANK_LINES.split(text) if part.strip()]
    parts: list[str] = []
    current = ""
    for paragraph in paragraphs:
        if len(paragraph) > max_chars:
            if current:
                parts.append(current)
                current = ""
            parts.extend(
                piece
                for start in range(0, len(paragraph), max_chars)
                if (piece := paragraph[start:start + max_chars].strip())
            )
            continue
        candidate = f"{current}\n\n{paragraph}".strip()
        if current and len(candidate) > max_chars:
            parts.append(current)
            current = paragraph
        else:
            current = candidate
    if current:
        parts.append(current)
    return parts


def _normalize_text(text: str) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in normalized.splitlines()).strip()


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()
