"""Heuristic document path router — ported from resume/backend/src/router.py.

Decision logic is preserved; metric computation is adapted for liteparse
text_items (span-level) instead of PyMuPDF blocks (paragraph-level).
"""
from __future__ import annotations

import os

from .config import ParseConfig
from .models import ParsedPage

_FORCE_ENV = "RISKOS_PARSER_PATH"  # mirrors ROUTER_FORCE from resume/backend


def _page_metrics(pages: list[ParsedPage]) -> dict[str, float]:
    if not pages:
        return {"text_per_page": 0.0, "avg_item_count": 0.0, "narrow_item_ratio": 0.0}

    n = len(pages)
    total_chars = sum(len(p.text) for p in pages)
    total_items = sum(len(p.items) for p in pages)

    narrow_count = 0
    for p in pages:
        if p.width > 0:
            for item in p.items:
                if item.width / p.width < 0.15:
                    narrow_count += 1

    return {
        "text_per_page": total_chars / n,
        "avg_item_count": total_items / n,
        "narrow_item_ratio": narrow_count / total_items if total_items > 0 else 0.0,
    }


def classify_pdf(pages: list[ParsedPage], config: ParseConfig) -> str:
    """Return 'text' or 'vision' for the given set of extracted PDF pages.

    Priority order: env override → config override → heuristics.
    """
    forced = os.environ.get(_FORCE_ENV) or config.force_path
    if forced in ("text", "vision"):
        return forced

    m = _page_metrics(pages)

    scanned_like = (
        m["text_per_page"] < config.scanned_text_per_page
        and m["avg_item_count"] < config.scanned_avg_item_count
    )
    complex_layout = (
        m["narrow_item_ratio"] > config.complex_narrow_ratio
        and m["avg_item_count"] > config.complex_avg_item_count
    )

    if scanned_like or complex_layout:
        return "vision"
    return "text"
