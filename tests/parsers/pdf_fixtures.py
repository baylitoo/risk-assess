"""Helpers to generate minimal valid PDFs for parser tests without PIL/reportlab."""
from __future__ import annotations

import textwrap
from pathlib import Path


_FILLER = (
    "The system implements TLS 1.3 for all external connections. "
    "Access control is enforced via API keys and OAuth 2.0 tokens. "
    "Audit logs are retained for 90 days in tamper-evident storage. "
    "Patch management follows a 30-day SLA for critical vulnerabilities. "
)


def _pad_to(text: str, min_chars: int = 450) -> str:
    """Pad text with filler so liteparse scores it as native text, not scanned."""
    while len(text) < min_chars:
        text = text + " " + _FILLER
    return text.strip()


def make_text_pdf(tmp_path: Path, pages: list[str], filename: str = "doc.pdf") -> Path:
    """Create a minimal PDF with native text on each page."""
    objects: list[str] = []

    page_obj_ids: list[int] = []
    content_obj_ids: list[int] = []

    # Object numbering: 1=catalog, 2=pages, 3=font, then pairs (page, content)
    base = 4
    for i in range(len(pages)):
        page_obj_ids.append(base + i * 2)
        content_obj_ids.append(base + i * 2 + 1)

    kids = " ".join(f"{oid} 0 R" for oid in page_obj_ids)

    obj_strs: dict[int, str] = {}
    obj_strs[1] = f"<</Type /Catalog /Pages 2 0 R>>"
    obj_strs[2] = f"<</Type /Pages /Kids [{kids}] /Count {len(pages)}>>"
    obj_strs[3] = "<</Type /Font /Subtype /Type1 /BaseFont /Helvetica>>"

    for i, (page_id, content_id, text) in enumerate(
        zip(page_obj_ids, content_obj_ids, pages)
    ):
        text = _pad_to(text)
        escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        stream = f"BT /F1 12 Tf 72 720 Td ({escaped}) Tj ET"
        obj_strs[page_id] = (
            f"<</Type /Page /Parent 2 0 R /MediaBox[0 0 612 792]"
            f" /Contents {content_id} 0 R /Resources<</Font<</F1 3 0 R>>>>>>"
        )
        obj_strs[content_id] = f"stream\n{stream}\nendstream"

    # Build PDF bytes
    lines = [b"%PDF-1.4"]
    offsets: dict[int, int] = {}

    for obj_id in range(1, max(obj_strs) + 1):
        if obj_id not in obj_strs:
            continue
        offsets[obj_id] = sum(len(l) + 1 for l in lines)
        body = obj_strs[obj_id]
        if "stream" in body:
            # content object
            stream_part = body[body.index("stream") :]
            header = body[: body.index("stream")]
            raw_stream = stream_part[len("stream\n") : -len("\nendstream")]
            length = len(raw_stream.encode())
            lines.append(f"{obj_id} 0 obj".encode())
            lines.append(f"<<{header}/Length {length}>>".encode())
            lines.append(b"stream")
            lines.append(raw_stream.encode())
            lines.append(b"endstream")
            lines.append(b"endobj")
        else:
            lines.append(f"{obj_id} 0 obj".encode())
            lines.append(body.encode())
            lines.append(b"endobj")

    xref_offset = sum(len(l) + 1 for l in lines)
    max_id = max(obj_strs)
    xref_lines = [b"xref", f"0 {max_id + 1}".encode(), b"0000000000 65535 f "]
    for obj_id in range(1, max_id + 1):
        off = offsets.get(obj_id, 0)
        xref_lines.append(f"{off:010d} 00000 n ".encode())

    lines.extend(xref_lines)
    lines.append(b"trailer")
    lines.append(f"<</Size {max_id + 1} /Root 1 0 R>>".encode())
    lines.append(b"startxref")
    lines.append(str(xref_offset).encode())
    lines.append(b"%%EOF")

    pdf_bytes = b"\n".join(lines)
    out = tmp_path / filename
    out.write_bytes(pdf_bytes)
    return out


def make_blank_pdf(tmp_path: Path, num_pages: int = 3) -> Path:
    """Create a PDF whose pages have no text layer (simulates scanned)."""
    # Pages with a trivial content stream — no text operators
    blank_pages = [""] * num_pages
    # Use a non-text stream so liteparse sees zero chars
    path = make_text_pdf(tmp_path, blank_pages, "blank.pdf")
    return path
