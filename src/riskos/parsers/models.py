from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ParsedItem:
    """Single text span with spatial metadata (from liteparse TextItem)."""

    text: str
    x: float
    y: float
    width: float
    height: float
    font_size: float | None = None


@dataclass
class ParsedPage:
    """Per-page extraction result — populated on the text path."""

    page_num: int          # 1-based
    text: str
    items: list[ParsedItem] = field(default_factory=list)
    width: float = 0.0
    height: float = 0.0


@dataclass
class ParsedDocument:
    source_path: Path
    parse_path: str            # "text" | "vision"
    pages: list[ParsedPage]    # populated on text path; empty on vision path
    jpeg_pages: list[str]      # b64 JPEG strings, populated on vision path
    total_pages: int
