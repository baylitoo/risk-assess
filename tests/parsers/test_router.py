"""Tests for the heuristic PDF path router."""
from __future__ import annotations

import pytest

from riskos.parsers.config import ParseConfig
from riskos.parsers.models import ParsedItem, ParsedPage
from riskos.parsers.router import classify_pdf


def _make_page(text: str, items: list[ParsedItem] | None = None, width: float = 612.0) -> ParsedPage:
    return ParsedPage(
        page_num=1,
        text=text,
        items=items or [],
        width=width,
        height=792.0,
    )


def _item(x: float, w: float, page_width: float = 612.0) -> ParsedItem:
    return ParsedItem(text="x", x=x, y=100.0, width=w, height=12.0)


def test_text_rich_pages_routed_to_text():
    pages = [
        _make_page(
            "A" * 600,
            [_item(72.0, 400.0)] * 10,
        )
    ]
    assert classify_pdf(pages, ParseConfig()) == "text"


def test_near_empty_pages_routed_to_vision():
    # Both conditions must hold: few chars AND few items → scanned
    pages = [_make_page("short", [_item(72.0, 30.0)]) for _ in range(3)]
    assert classify_pdf(pages, ParseConfig()) == "vision"


def test_force_path_config_overrides():
    pages = [_make_page("A" * 600, [_item(72.0, 400.0)] * 10)]
    cfg = ParseConfig(force_path="vision")
    assert classify_pdf(pages, cfg) == "vision"

    cfg2 = ParseConfig(force_path="text")
    assert classify_pdf(pages, cfg2) == "text"


def test_complex_layout_narrow_items_routed_to_vision():
    # Many items, most narrow → complex layout
    narrow = [_item(72.0, 30.0)] * 30  # 30/612 ≈ 0.049 < 0.15 → narrow
    pages = [_make_page("B" * 800, narrow)]
    cfg = ParseConfig(complex_avg_item_count=10.0)  # lower threshold for test
    assert classify_pdf(pages, cfg) == "vision"


def test_env_override(monkeypatch):
    monkeypatch.setenv("RISKOS_PARSER_PATH", "vision")
    pages = [_make_page("A" * 1000, [_item(72.0, 400.0)] * 20)]
    assert classify_pdf(pages, ParseConfig()) == "vision"

    monkeypatch.setenv("RISKOS_PARSER_PATH", "text")
    assert classify_pdf([], ParseConfig()) == "text"


def test_empty_pages_list_routed_to_vision():
    assert classify_pdf([], ParseConfig()) == "vision"
