"""Vision path: render PDF pages to JPEG b64 via pypdfium2.

Ported from resume/backend/src/vision.py with the same DPI cascade and
JPEG quality cascade. No LlamaIndex, no cloud API — pypdfium2 only.
"""
from __future__ import annotations

import base64
import io
from pathlib import Path

import pypdfium2
from PIL import Image

from .config import ParseConfig


def render_pdf_pages_to_jpeg_b64(path: Path, config: ParseConfig) -> list[str]:
    """Render every page of a PDF to JPEG b64, respecting size constraints.

    Tries DPI values from config.vision_dpi_list (high → low), then JPEG
    quality values from config.jpeg_quality_list (high → low), until the
    encoded string fits within config.page_max_b64_len.
    """
    pdf = pypdfium2.PdfDocument(str(path))
    results: list[str] = []
    try:
        for page_idx in range(len(pdf)):
            page = pdf[page_idx]
            b64 = _render_page(page, config)
            results.append(b64)
            page.close()
    finally:
        pdf.close()
    return results


def _render_page(page: pypdfium2.PdfPage, config: ParseConfig) -> str:
    for dpi in config.vision_dpi_list:
        scale = dpi / 72.0
        bitmap = page.render(scale=scale, rotation=0)
        pil_img = bitmap.to_pil()

        # Cap long edge
        w, h = pil_img.size
        long_edge = max(w, h)
        if long_edge > config.max_long_edge:
            factor = config.max_long_edge / long_edge
            pil_img = pil_img.resize(
                (max(1, int(w * factor)), max(1, int(h * factor))),
                resample=Image.LANCZOS,
            )

        # Strip alpha channel
        if pil_img.mode in ("RGBA", "LA", "P"):
            pil_img = pil_img.convert("RGB")
        elif pil_img.mode != "RGB":
            pil_img = pil_img.convert("RGB")

        for quality in config.jpeg_quality_list:
            buf = io.BytesIO()
            pil_img.save(buf, format="JPEG", quality=quality, optimize=True)
            b64 = base64.b64encode(buf.getvalue()).decode()
            if len(b64) <= config.page_max_b64_len:
                return b64

    # Absolute fallback: return last attempt regardless of size
    return b64  # noqa: F821
