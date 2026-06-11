from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ParseConfig:
    # --- Router thresholds (adapted from resume/backend/src/router.py) ---
    # liteparse text_items are line/span-level; thresholds calibrated accordingly.
    scanned_text_per_page: int = 400        # avg chars/page below this → likely scanned
    scanned_avg_item_count: float = 3.0     # avg items/page below this → likely scanned
    complex_narrow_ratio: float = 0.35      # fraction of narrow items above this → complex
    complex_avg_item_count: float = 25.0    # avg items/page above this → complex layout
    # narrow = item width < this fraction of page width
    narrow_width_fraction: float = 0.15

    # --- Vision rendering (from resume/backend/src/config.py) ---
    vision_dpi_list: list[int] = field(
        default_factory=lambda: [350, 280, 220, 180, 150, 120]
    )
    jpeg_quality_list: list[int] = field(default_factory=lambda: [70, 60, 50, 40])
    max_long_edge: int = 1400
    page_max_b64_len: int = 1_600_000

    # --- Router override ---
    force_path: str | None = None  # "text" | "vision" | None
