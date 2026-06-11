"""riskctl — the vuln-operator agent's CLI.

Design contract (ROADMAP §3): this help text is written for an LLM
operator. Read it carefully; it is the authoritative usage guide.

USAGE
  riskctl cve get CVE-2026-0001          Full mirrored NVD record (JSON).
  riskctl kev check CVE-2026-0001        Is this CVE in CISA KEV? {"listed": bool, ...}
  riskctl epss get CVE-2026-0001         EPSS probability + percentile.
  riskctl triage CVE-A CVE-B ...         One combined record per CVE:
                                         nvd summary + kev + epss + priority hint.

OUTPUT
  Always a single JSON document on stdout. Parse it; never regex stdout.
  Errors go to stderr as JSON {"error": ...} with exit code 2. A missing
  CVE is NOT an error: you get {"found": false} with exit code 0 — treat
  "not in mirror" as a data gap to report, not a failure to retry.

DATA SOURCE
  Reads the local intel mirror only (no network). Mirror root resolves
  from $RISKOS_MIRROR_DIR, else ./data/mirror. Mirror freshness is in
  mirror/meta.json — ALWAYS report stale data (>48h) in your findings.

PITFALLS
  - NVD enrichment is selective since 2026: a CVE may exist with no CVSS.
    Fall back on `priority` from triage (KEV > EPSS > CVSS heuristic).
  - Do not loop one `cve get` per CVE if you have many — use `triage`
    with up to 50 IDs per call.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _mirror_root() -> Path:
    return Path(os.environ.get("RISKOS_MIRROR_DIR", "data/mirror"))


def _read_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _emit(payload: dict) -> int:
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def _fail(message: str) -> int:
    json.dump({"error": message}, sys.stderr)
    sys.stderr.write("\n")
    return 2


# -- data access --------------------------------------------------------------


def get_cve(cve_id: str) -> dict:
    record = _read_json(_mirror_root() / "nvd" / f"{cve_id}.json")
    if record is None:
        return {"cve_id": cve_id, "found": False}
    return {"cve_id": cve_id, "found": True, "record": record}


def check_kev(cve_id: str) -> dict:
    kev = _read_json(_mirror_root() / "kev.json") or {"vulnerabilities": []}
    entry = next(
        (v for v in kev.get("vulnerabilities", []) if v.get("cveID") == cve_id),
        None,
    )
    return {"cve_id": cve_id, "listed": entry is not None, "entry": entry}


def get_epss(cve_id: str) -> dict:
    epss = _read_json(_mirror_root() / "epss.json") or {}
    entry = epss.get(cve_id)
    if entry is None:
        return {"cve_id": cve_id, "found": False}
    return {"cve_id": cve_id, "found": True, **entry}


def triage(cve_ids: list[str]) -> dict:
    """KEV > EPSS > CVSS priority heuristic, one combined record per CVE."""
    mirror = _mirror_root()
    kev = _read_json(mirror / "kev.json") or {"vulnerabilities": []}
    kev_ids = {
        entry.get("cveID")
        for entry in kev.get("vulnerabilities", [])
        if entry.get("cveID")
    }
    epss = _read_json(mirror / "epss.json") or {}
    records = {
        cve_id: _read_json(mirror / "nvd" / f"{cve_id}.json")
        for cve_id in dict.fromkeys(cve_ids)
    }

    results = []
    for cve_id in cve_ids:
        record = records[cve_id]
        in_mirror = record is not None
        kev_listed = cve_id in kev_ids
        epss_entry = epss.get(cve_id)
        cvss = None
        if record is not None:
            cvss = record.get("cvss_v3")
        epss_score = epss_entry.get("epss") if epss_entry is not None else None

        if kev_listed:
            priority = "P1_actively_exploited"
        elif epss_score is not None and epss_score >= 0.1:
            priority = "P2_likely_exploited"
        elif cvss is not None and cvss >= 9.0:
            priority = "P3_critical_severity"
        elif not in_mirror:
            priority = "P4_unknown_data_gap"
        else:
            priority = "P5_routine"

        results.append({
            "cve_id": cve_id,
            "in_mirror": in_mirror,
            "kev_listed": kev_listed,
            "epss": epss_score,
            "cvss_v3": cvss,
            "priority": priority,
        })
    return {"count": len(results), "results": results}


# -- CLI ----------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="riskctl",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    cve = sub.add_parser("cve", help="NVD record operations")
    cve_sub = cve.add_subparsers(dest="subcommand", required=True)
    cve_get = cve_sub.add_parser("get", help="fetch one mirrored NVD record")
    cve_get.add_argument("cve_id")

    kev = sub.add_parser("kev", help="CISA KEV operations")
    kev_sub = kev.add_subparsers(dest="subcommand", required=True)
    kev_check = kev_sub.add_parser("check", help="check KEV listing for a CVE")
    kev_check.add_argument("cve_id")

    epss = sub.add_parser("epss", help="EPSS score operations")
    epss_sub = epss.add_subparsers(dest="subcommand", required=True)
    epss_get = epss_sub.add_parser("get", help="EPSS probability for a CVE")
    epss_get.add_argument("cve_id")

    tri = sub.add_parser("triage", help="combined kev+epss+cvss priority, many CVEs")
    tri.add_argument("cve_ids", nargs="+", metavar="CVE-ID")

    cpe = sub.add_parser("cpe", help="CPE canonicalization operations")
    cpe_sub = cpe.add_subparsers(dest="subcommand", required=True)
    cpe_match_p = cpe_sub.add_parser("match", help="match CPEs for all components in an inventory")
    cpe_match_p.add_argument("inventory_json", help="path to AssetInventory JSON file")

    return parser


def cpe_match(inventory_json_path: str) -> tuple[list[dict], int]:
    """Match CPEs for all components. Returns (results, exit_code)."""
    from riskos.cpe.matcher import CpeMatchResult, match_technology
    from riskos.schemas.artifacts import AssetInventory

    inventory = AssetInventory.model_validate_json(
        Path(inventory_json_path).read_text(encoding="utf-8")
    )
    results = []
    all_matched = True
    for comp in inventory.components:
        if not comp.technology and not comp.cpe_candidates:
            continue
        cpes = match_technology(comp.technology or "", comp.cpe_candidates)
        r = CpeMatchResult(
            component_id=comp.id,
            component_name=comp.name,
            technology=comp.technology or "",
            cpes=cpes,
        )
        results.append(r)
        if not r.matched:
            all_matched = False

    return [
        {
            "component_id": r.component_id,
            "component_name": r.component_name,
            "technology": r.technology,
            "matched_cpes": r.cpes if r.cpes else ["NONE"],
            "matched": r.matched,
        }
        for r in results
    ], (0 if all_matched else 1)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "cve":
            return _emit(get_cve(args.cve_id))
        if args.command == "kev":
            return _emit(check_kev(args.cve_id))
        if args.command == "epss":
            return _emit(get_epss(args.cve_id))
        if args.command == "triage":
            if len(args.cve_ids) > 50:
                return _fail("max 50 CVE ids per triage call — split the batch")
            return _emit(triage(args.cve_ids))
        if args.command == "cpe":
            if args.subcommand == "match":
                results, exit_code = cpe_match(args.inventory_json)
                _emit({"count": len(results), "results": results})
                return exit_code
        return _fail(f"unknown command {args.command!r}")
    except (json.JSONDecodeError, OSError) as exc:
        return _fail(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
