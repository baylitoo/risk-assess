"""Control catalog — loads and indexes the internal control library.

The catalog is the authoritative source of control taxonomy refs, framework
mappings, and applicability metadata.  It is read-only at runtime; no agent
may mutate it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from riskos.ids import stable_id
from riskos.schemas.artifacts import FindingCategory
from riskos.schemas.entities import Control


class CatalogError(Exception):
    """Raised when the catalog YAML is missing, malformed, or contains
    invalid values (e.g. an unknown FindingCategory)."""


@dataclass
class ControlEntry:
    taxonomy_ref: str
    name: str
    description: str
    framework_refs: dict[str, str]
    applicable_categories: list[FindingCategory]
    strength_when_present: str


class ControlCatalog:
    """In-memory index of all catalog entries, keyed for fast category lookup."""

    def __init__(self, entries: list[ControlEntry]) -> None:
        self._entries: list[ControlEntry] = entries
        # Build category -> entries index
        self._by_category: dict[FindingCategory, list[ControlEntry]] = {}
        for entry in entries:
            for cat in entry.applicable_categories:
                self._by_category.setdefault(cat, []).append(entry)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path) -> "ControlCatalog":
        """Load and validate a YAML control catalog file.

        Raises:
            CatalogError: if the file is missing, unparseable, or contains
                an unknown FindingCategory value.
        """
        p = Path(path)
        try:
            raw = p.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise CatalogError(f"catalog file not found: {path}") from exc
        except OSError as exc:
            raise CatalogError(f"cannot read catalog file: {exc}") from exc

        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise CatalogError(f"YAML parse error in {path}: {exc}") from exc

        if not isinstance(data, list):
            raise CatalogError(
                f"catalog must be a YAML list of entries; got {type(data).__name__}"
            )

        entries: list[ControlEntry] = []
        for idx, item in enumerate(data):
            loc = f"entry[{idx}]"
            try:
                taxonomy_ref = str(item["taxonomy_ref"])
                name = str(item["name"])
                description = str(item.get("description", ""))
                framework_refs: dict[str, str] = {
                    k: str(v) for k, v in (item.get("framework_refs") or {}).items()
                }
                strength_when_present = str(item.get("strength_when_present", ""))

                raw_cats = item.get("applicable_categories") or []
                applicable_categories: list[FindingCategory] = []
                for raw_cat in raw_cats:
                    try:
                        applicable_categories.append(FindingCategory(str(raw_cat)))
                    except ValueError:
                        valid = [c.value for c in FindingCategory]
                        raise CatalogError(
                            f"{loc}: unknown category {raw_cat!r}; "
                            f"valid values: {valid}"
                        )

            except CatalogError:
                raise
            except (KeyError, TypeError) as exc:
                raise CatalogError(f"{loc}: malformed entry: {exc}") from exc

            entries.append(
                ControlEntry(
                    taxonomy_ref=taxonomy_ref,
                    name=name,
                    description=description,
                    framework_refs=framework_refs,
                    applicable_categories=applicable_categories,
                    strength_when_present=strength_when_present,
                )
            )

        return cls(entries)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._entries)

    def entries_for_category(self, category: FindingCategory) -> list[ControlEntry]:
        """Return all catalog entries applicable to the given category.

        Returns an empty list when no entries match — never raises.
        """
        return list(self._by_category.get(category, []))

    # ------------------------------------------------------------------
    # Conversion
    # ------------------------------------------------------------------

    def to_control_entities(self) -> list[Control]:
        """Convert catalog entries to Control schema entities with stable IDs.

        The stable ID is derived from ``stable_id("control", taxonomy_ref)``
        so it is deterministic across runs and consistent with the audit
        primary key.
        """
        controls: list[Control] = []
        for entry in self._entries:
            controls.append(
                Control(
                    id=stable_id("control", entry.taxonomy_ref),
                    name=entry.name,
                    description=entry.description,
                    taxonomy_ref=entry.taxonomy_ref,
                    framework_refs=entry.framework_refs,
                    strength=entry.strength_when_present,
                )
            )
        return controls
