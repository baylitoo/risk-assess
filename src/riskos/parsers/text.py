"""Text extraction for the lightweight path.

PDF:  liteparse (Rust/PDFium, ~2ms per 3 pages, no OCR, no API).
DOCX: python-docx paragraph extraction.
"""
from __future__ import annotations

from pathlib import Path

from liteparse import LiteParse

from .models import ParsedItem, ParsedPage


def extract_pdf_pages(path: Path) -> list[ParsedPage]:
    """Extract per-page text and bounding-box items from a native PDF."""
    result = LiteParse(ocr_enabled=False, quiet=True).parse(path)
    pages: list[ParsedPage] = []
    # liteparse get_page() is 1-based; pages are numbered 1..num_pages
    for page_num in range(1, result.num_pages + 1):
        raw = result.get_page(page_num)
        if raw is None:
            pages.append(ParsedPage(page_num=page_num, text=""))
            continue
        items = [
            ParsedItem(
                text=it.text,
                x=it.x,
                y=it.y,
                width=it.width,
                height=it.height,
                font_size=it.font_size,
            )
            for it in (raw.text_items or [])
        ]
        pages.append(
            ParsedPage(
                page_num=page_num,
                text=raw.text,
                items=items,
                width=raw.width,
                height=raw.height,
            )
        )
    return pages


def extract_docx_paragraphs(path: Path) -> list[str]:
    """Extract non-empty paragraphs from a DOCX file."""
    from docx import Document  # noqa: PLC0415

    doc = Document(str(path))
    return [p.text for p in doc.paragraphs if p.text.strip()]
