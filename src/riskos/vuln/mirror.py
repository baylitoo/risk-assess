"""Local NVD/KEV/EPSS mirror readers — no network access, file-based cache only."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def _mirror_root(root: str | Path | None = None) -> Path:
    if root is not None:
        return Path(root)
    return Path(os.environ.get("RISKOS_MIRROR_DIR", "data/mirror"))


def _read_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


@dataclass
class CveRecord:
    cve_id: str
    description: str = ""
    cvss_v3: float | None = None
    cvss_v2: float | None = None
    published: str = ""
    modified: str = ""
    cpe_uris: list[str] = field(default_factory=list)


class MirrorFreshnessError(Exception):
    """Raised when the mirror is stale beyond the freshness threshold."""


class NvdMirror:
    """Read-only interface to the local NVD mirror."""

    def __init__(self, root: str | Path | None = None) -> None:
        self._root = _mirror_root(root)

    def get(self, cve_id: str) -> CveRecord | None:
        record = _read_json(self._root / "nvd" / f"{cve_id}.json")
        if record is None:
            return None
        return CveRecord(
            cve_id=cve_id,
            description=record.get("description", ""),
            cvss_v3=record.get("cvss_v3"),
            cvss_v2=record.get("cvss_v2"),
            published=record.get("published", ""),
            modified=record.get("modified", ""),
            cpe_uris=record.get("cpe_uris", []),
        )

    def check_freshness(self, max_age_hours: float = 48.0) -> bool:
        """Return True if the mirror was updated within max_age_hours."""
        meta = _read_json(self._root / "meta.json")
        if meta is None:
            return False
        updated = meta.get("updated_at")
        if not updated:
            return False
        try:
            ts = datetime.fromisoformat(updated)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            age = datetime.now(timezone.utc) - ts
            return age.total_seconds() / 3600 <= max_age_hours
        except (ValueError, TypeError):
            return False


class KevMirror:
    """Read-only interface to the local CISA KEV mirror."""

    def __init__(self, root: str | Path | None = None) -> None:
        self._root = _mirror_root(root)
        self._kev: dict | None = None

    def _load(self) -> dict:
        if self._kev is None:
            self._kev = _read_json(self._root / "kev.json") or {"vulnerabilities": []}
        return self._kev

    def is_listed(self, cve_id: str) -> bool:
        kev = self._load()
        return any(
            v.get("cveID") == cve_id for v in kev.get("vulnerabilities", [])
        )

    def get_entry(self, cve_id: str) -> dict | None:
        kev = self._load()
        return next(
            (v for v in kev.get("vulnerabilities", []) if v.get("cveID") == cve_id),
            None,
        )


class EpssScoreMirror:
    """Read-only interface to the local EPSS score mirror."""

    def __init__(self, root: str | Path | None = None) -> None:
        self._root = _mirror_root(root)
        self._epss: dict | None = None

    def _load(self) -> dict:
        if self._epss is None:
            self._epss = _read_json(self._root / "epss.json") or {}
        return self._epss

    def get(self, cve_id: str) -> dict | None:
        return self._load().get(cve_id)

    def score(self, cve_id: str) -> float | None:
        entry = self.get(cve_id)
        if entry is None:
            return None
        return entry.get("epss")
