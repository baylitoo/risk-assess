"""CPE 2.3 canonicalization and technology matching."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

CPE_PATTERN = re.compile(
    r"^cpe:2\.3:[aho\*\-]:[^:]+:[^:]+:[^:]+(?::[^:]*){7}$"
)


class CpeError(Exception):
    pass


def normalize_cpe(raw: str) -> str:
    """Lowercase, strip whitespace, validate CPE 2.3 format."""
    cleaned = raw.strip().lower()
    if not CPE_PATTERN.match(cleaned):
        raise CpeError(f"invalid CPE 2.3 URI: {raw!r}")
    return cleaned


def match_technology(technology: str, cpe_candidates: list[str]) -> list[str]:
    """Return normalized CPE URIs for the component.

    Candidates take priority. Falls back to naive parsing when none provided.
    """
    if cpe_candidates:
        result = []
        for c in cpe_candidates:
            try:
                result.append(normalize_cpe(c))
            except CpeError:
                pass
        return result

    # Naive: try to build CPE from "Product 1.2.3" pattern
    # Returns empty list if unparseable
    parts = technology.strip().split()
    if len(parts) >= 2:
        product = parts[0].lower().replace("-", "_")
        version = parts[-1].lower()
        candidate = f"cpe:2.3:a:*:{product}:{version}:*:*:*:*:*:*:*"
        try:
            return [normalize_cpe(candidate)]
        except CpeError:
            pass
    return []


@dataclass
class CpeMatchResult:
    component_id: str
    component_name: str
    technology: str
    cpes: list[str] = field(default_factory=list)

    @property
    def matched(self) -> bool:
        return bool(self.cpes)
