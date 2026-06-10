"""Inventory extraction eval — entity-level precision/recall.

Measures how well the extraction pipeline identified the right entities
compared to a hand-labeled golden inventory. Matches entities by
normalised name within each entity type.

Name normalisation is intentionally loose (lowercase, remove punctuation,
collapse whitespace) because an LLM may name a system "Payments Hub" where
the golden label has "payments-hub". Exact-match on IDs is not viable here
because produced and golden inventories originate from independent runs.

DataFlows are excluded from entity P/R: they are relationships, not
countable entities, and their meaning depends on whether the endpoints
matched — a flow between two matched components is a stronger signal
than a flow between two spurious ones. DataFlow coverage is better
tracked as a downstream eval (threat-model completeness).
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from riskos.schemas.artifacts import AssetInventory


class InventoryCorpusError(Exception):
    pass


class InventorySplit(StrEnum):
    DEV = "dev"
    REGRESSION = "regression"
    HOLDOUT = "holdout"


class InventoryEvalCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"] = "1"
    case_id: str
    split: InventorySplit
    description: str = ""
    golden_inventory: AssetInventory
    produced_inventory: AssetInventory | None = None


class InventoryEvalThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_recall: float = Field(default=0.0, ge=0.0, le=1.0)
    min_precision: float = Field(default=0.0, ge=0.0, le=1.0)
    min_f1: float = Field(default=0.0, ge=0.0, le=1.0)


class InventoryCorpusEvalReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"] = "1"
    split: InventorySplit
    case_count: int
    aggregate_precision: float
    aggregate_recall: float
    aggregate_f1: float
    passed: bool
    violations: list[str] = Field(default_factory=list)
    cases: list[InventoryEvalReport] = Field(default_factory=list)


def load_inventory_corpus(directory: str | Path) -> list[InventoryEvalCase]:
    """Load all inventory eval cases from a directory tree."""
    root = Path(directory)
    if not root.is_dir():
        raise InventoryCorpusError(f"corpus directory not found: {root}")
    cases: list[InventoryEvalCase] = []
    seen: set[str] = set()
    for path in sorted(root.rglob("*.json")):
        try:
            case = InventoryEvalCase.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise InventoryCorpusError(f"invalid eval case {path}: {exc}") from exc
        if case.case_id in seen:
            raise InventoryCorpusError(f"duplicate case_id {case.case_id!r}")
        seen.add(case.case_id)
        cases.append(case)
    if not cases:
        raise InventoryCorpusError(f"no eval cases found in {root}")
    return cases


def evaluate_inventory_corpus(
    cases: list[InventoryEvalCase],
    split: InventorySplit = InventorySplit.REGRESSION,
    thresholds: InventoryEvalThresholds | None = None,
) -> InventoryCorpusEvalReport:
    """Aggregate entity P/R across all cases with a produced_inventory in the split."""
    selected = [
        c for c in cases
        if c.split == split and c.produced_inventory is not None
    ]
    if not selected:
        raise InventoryCorpusError(
            f"no scoreable cases for split {split.value!r} "
            "(cases need a produced_inventory)"
        )

    reports = [(c, evaluate_inventory(c.golden_inventory, c.produced_inventory)) for c in selected]
    thresholds = thresholds or InventoryEvalThresholds()

    total_g = sum(r.by_type[t].golden_total for _, r in reports for t in r.by_type)
    total_p = sum(r.by_type[t].produced_total for _, r in reports for t in r.by_type)
    total_m = sum(r.by_type[t].matched for _, r in reports for t in r.by_type)

    agg_precision = _ratio(total_m, total_p)
    agg_recall = _ratio(total_m, total_g, default=1.0)
    agg_f1 = _f1(agg_precision, agg_recall)

    violations: list[str] = []
    if agg_recall < thresholds.min_recall:
        violations.append(f"recall {agg_recall:.4f} < {thresholds.min_recall:.4f}")
    if agg_precision < thresholds.min_precision:
        violations.append(f"precision {agg_precision:.4f} < {thresholds.min_precision:.4f}")
    if agg_f1 < thresholds.min_f1:
        violations.append(f"f1 {agg_f1:.4f} < {thresholds.min_f1:.4f}")

    return InventoryCorpusEvalReport(
        split=split,
        case_count=len(selected),
        aggregate_precision=round(agg_precision, 4),
        aggregate_recall=round(agg_recall, 4),
        aggregate_f1=round(agg_f1, 4),
        passed=not violations,
        violations=violations,
        cases=[r for _, r in reports],
    )


class EntityEval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_type: str
    golden_total: int
    produced_total: int
    matched: int
    precision: float
    recall: float
    f1: float
    missed_names: list[str] = Field(default_factory=list)
    spurious_names: list[str] = Field(default_factory=list)


class InventoryEvalReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    by_type: dict[str, EntityEval]
    aggregate_precision: float
    aggregate_recall: float
    aggregate_f1: float


def evaluate_inventory(
    golden: AssetInventory,
    produced: AssetInventory,
) -> InventoryEvalReport:
    """Compare produced vs. golden inventory by normalised entity name.

    Precision = matched / produced_total
    Recall    = matched / golden_total  (1.0 when golden_total == 0)
    """
    groups = [
        ("system", golden.systems, produced.systems),
        ("component", golden.components, produced.components),
        ("data_asset", golden.data_assets, produced.data_assets),
        ("third_party", golden.third_parties, produced.third_parties),
        ("control", golden.controls, produced.controls),
    ]

    by_type: dict[str, EntityEval] = {}
    total_golden = 0
    total_produced = 0
    total_matched = 0

    for entity_type, golden_entities, produced_entities in groups:
        golden_names = {_normalize(e.name) for e in golden_entities}
        produced_names = {_normalize(e.name) for e in produced_entities}
        matched_names = golden_names & produced_names
        matched = len(matched_names)

        precision = _ratio(matched, len(produced_names))
        recall = _ratio(matched, len(golden_names), default=1.0)
        f1 = _f1(precision, recall)

        by_type[entity_type] = EntityEval(
            entity_type=entity_type,
            golden_total=len(golden_names),
            produced_total=len(produced_names),
            matched=matched,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1=round(f1, 4),
            missed_names=sorted(golden_names - matched_names),
            spurious_names=sorted(produced_names - matched_names),
        )
        total_golden += len(golden_names)
        total_produced += len(produced_names)
        total_matched += matched

    agg_precision = _ratio(total_matched, total_produced)
    agg_recall = _ratio(total_matched, total_golden, default=1.0)

    return InventoryEvalReport(
        by_type=by_type,
        aggregate_precision=round(agg_precision, 4),
        aggregate_recall=round(agg_recall, 4),
        aggregate_f1=round(_f1(agg_precision, agg_recall), 4),
    )


def _normalize(name: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace."""
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]", " ", name.lower())).strip()


def _ratio(num: int, den: int, default: float = 0.0) -> float:
    return num / den if den else default


def _f1(precision: float, recall: float) -> float:
    denom = precision + recall
    return 2 * precision * recall / denom if denom else 0.0
