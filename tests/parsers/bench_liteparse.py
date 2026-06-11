"""Performance benchmark: liteparse vs baseline for PDF text extraction.

Run directly:   python tests/parsers/bench_liteparse.py
Or via pytest:  pytest tests/parsers/bench_liteparse.py -s -v
"""
from __future__ import annotations

import statistics
import sys
import tempfile
import time
from pathlib import Path

from liteparse import LiteParse

from .pdf_fixtures import make_text_pdf


def _make_large_pdf(tmp_path: Path, num_pages: int) -> Path:
    pages = [
        f"Page {i + 1}: NEXUS Payments Hub security assessment. "
        f"Kong API Gateway 3.6 internet-facing TLS 1.3. "
        f"Payment Engine Java 21 Spring Boot 3.2. "
        f"PostgreSQL 16.3 customer PII encrypted at rest. "
        f"FraudGuard AI ONNX Runtime 1.18 anomaly detection. "
        f"SWIFTNet Link 7.5 critical third-party DORA. "
        f"Control ID CTL-{i:04d} implemented reviewed verified."
        for i in range(num_pages)
    ]
    return make_text_pdf(tmp_path, pages, f"bench_{num_pages}p.pdf")


def _bench(path: Path, runs: int = 10) -> dict:
    times_ms = []
    for _ in range(runs):
        t0 = time.perf_counter()
        result = LiteParse(ocr_enabled=False, quiet=True).parse(path)
        pages = [result.get_page(n) for n in range(1, result.num_pages + 1)]
        total_chars = sum(len(p.text) for p in pages if p)
        elapsed = (time.perf_counter() - t0) * 1000
        times_ms.append(elapsed)
    return {
        "min_ms": min(times_ms),
        "mean_ms": statistics.mean(times_ms),
        "median_ms": statistics.median(times_ms),
        "p95_ms": sorted(times_ms)[int(0.95 * len(times_ms))],
        "pages": result.num_pages,
        "total_chars": total_chars,
    }


def run_benchmarks():
    sizes = [3, 10, 30, 100]
    print(
        f"\n{'Pages':>6} {'min ms':>8} {'med ms':>8} {'p95 ms':>8} "
        f"{'chars':>8} {'ms/page':>9}"
    )
    print("-" * 58)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for n in sizes:
            path = _make_large_pdf(tmp_path, n)
            r = _bench(path)
            ms_per_page = r["median_ms"] / r["pages"]
            print(
                f"{r['pages']:>6} {r['min_ms']:>8.1f} {r['median_ms']:>8.1f} "
                f"{r['p95_ms']:>8.1f} {r['total_chars']:>8} {ms_per_page:>9.2f}"
            )
    print()


def test_liteparse_benchmark_prints_results():
    """pytest entry point — prints benchmark table, asserts reasonable speed."""
    sizes = [3, 10]
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for n in sizes:
            path = _make_large_pdf(tmp_path, n)
            r = _bench(path, runs=5)
            ms_per_page = r["median_ms"] / r["pages"]
            print(
                f"  {n:>3} pages: median={r['median_ms']:.1f}ms  "
                f"({ms_per_page:.2f}ms/page)  chars={r['total_chars']}"
            )
            # Should be under 50ms/page even on a slow machine after JIT warmup
            assert ms_per_page < 50, f"liteparse too slow: {ms_per_page:.1f}ms/page"


if __name__ == "__main__":
    run_benchmarks()
