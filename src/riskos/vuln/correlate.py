"""Correlate mirrored CVE data against the asset inventory."""

from __future__ import annotations

from riskos.ids import new_id, stable_id
from riskos.schemas.artifacts import (
    AssetInventory,
    Evidence,
    EvidenceSource,
    FindingCategory,
    FindingStatus,
    RiskFinding,
)
from riskos.vuln.mirror import CveRecord, EpssScoreMirror, KevMirror, NvdMirror

_CVSS_HIGH_THRESHOLD = 7.0
_HIGH_BANDS = {"high", "very_high", "critical"}


def _priority(
    cve_id: str,
    cvss: float | None,
    kev: KevMirror,
    epss: EpssScoreMirror,
) -> str:
    if kev.is_listed(cve_id):
        return "P1_actively_exploited"
    epss_score = epss.score(cve_id)
    if epss_score is not None and epss_score >= 0.1:
        return "P2_likely_exploited"
    if cvss is not None and cvss >= 9.0:
        return "P3_critical_severity"
    return "P5_routine"


def _band_from_cvss(cvss: float | None) -> str:
    if cvss is None:
        return "medium"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _factors_from_cvss(cvss: float | None) -> dict[str, str]:
    if cvss is None or cvss < 7.0:
        return {}
    if cvss >= 9.0:
        return {
            "exposure": "internet_facing",
            "exploitability": "practical",
            "threat_activity": "high",
            "impact": "severe",
            "control_strength": "absent",
        }
    return {
        "exposure": "internal",
        "exploitability": "practical",
        "threat_activity": "moderate",
        "impact": "major",
        "control_strength": "absent",
    }


def correlate_inventory(
    inventory: AssetInventory,
    nvd: NvdMirror,
    kev: KevMirror,
    epss: EpssScoreMirror,
    cvss_threshold: float = _CVSS_HIGH_THRESHOLD,
) -> tuple[list[RiskFinding], list[Evidence]]:
    """Map CVEs from component CPE candidates to RiskFindings.

    Returns (findings, evidence). Only CVEs with CVSS >= cvss_threshold or
    in KEV are emitted.
    """
    findings: list[RiskFinding] = []
    evidence_list: list[Evidence] = []
    seen_finding_ids: set[str] = set()

    for component in inventory.components:
        cve_ids: list[str] = []

        for candidate in component.cpe_candidates:
            cpe_file = candidate.replace("cpe:2.3:", "").replace(":", "_").replace("*", "any")
            cve_ids_for_cpe = _cves_for_cpe(nvd, candidate)
            cve_ids.extend(cve_ids_for_cpe)

        for cve_id in dict.fromkeys(cve_ids):
            record = nvd.get(cve_id)
            cvss = record.cvss_v3 if record else None
            kev_listed = kev.is_listed(cve_id)

            if cvss is not None and cvss < cvss_threshold and not kev_listed:
                continue
            if cvss is None and not kev_listed:
                continue

            finding_id = stable_id("finding", "cve", cve_id, component.id)
            if finding_id in seen_finding_ids:
                continue
            seen_finding_ids.add(finding_id)

            priority = _priority(cve_id, cvss, kev, epss)
            description = record.description if record else ""

            evidence_id = stable_id("evidence", "nvd", cve_id)
            evidence_list.append(
                Evidence(
                    evidence_id=evidence_id,
                    source_type=EvidenceSource.NVD,
                    source_ref=cve_id,
                    excerpt=description[:300] if description else "",
                )
            )

            factors = _factors_from_cvss(cvss)
            band = _band_from_cvss(cvss)
            if kev_listed and band not in ("critical", "very_high"):
                band = "high"

            finding = RiskFinding(
                finding_id=finding_id,
                title=f"{cve_id} affecting {component.name}",
                category=FindingCategory.VULNERABILITY,
                scenario=(
                    f"{cve_id} (CVSS {cvss or 'N/A'}, priority {priority}) "
                    f"affects {component.name} ({component.technology or 'unknown technology'})."
                ),
                affected_asset_ids=[component.id],
                threat_refs=[cve_id],
                factors=factors,
                band=band,
                status=FindingStatus.DRAFT,
            )
            findings.append(finding)

    return findings, evidence_list


def _cves_for_cpe(nvd: NvdMirror, cpe_uri: str) -> list[str]:
    """Return CVE IDs whose NVD record includes this CPE URI.

    Reads all NVD records in the mirror and filters by cpe_uris field.
    Designed for small test mirrors; production would use an index.
    """
    nvd_dir = nvd._root / "nvd"
    if not nvd_dir.exists():
        return []
    results = []
    for path in sorted(nvd_dir.glob("CVE-*.json")):
        import json as _json
        try:
            record = _json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        cpe_uris = record.get("cpe_uris", [])
        if cpe_uri in cpe_uris:
            cve_id = path.stem
            results.append(cve_id)
    return results
