"""Report writer: render a RiskRegister as structured Markdown + CSV."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from riskos.schemas.artifacts import Evidence, RiskFinding, RiskRegister

if TYPE_CHECKING:
    from riskos.dora.checker import DoraGap

_BAND_ORDER = ["critical", "very_high", "high", "medium", "low"]
_HIGH_BANDS = {"critical", "very_high", "high"}


@dataclass
class ReportSections:
    markdown: str
    findings_csv: str
    evidence_json: str


def _sort_key(f: RiskFinding) -> tuple[int, str]:
    try:
        return (_BAND_ORDER.index(f.band), f.finding_id)
    except ValueError:
        return (len(_BAND_ORDER), f.finding_id)


def write_report(
    register: RiskRegister,
    evidence: list[Evidence] | None = None,
    dora_gaps: list[Any] | None = None,
    assessment_title: str = "Risk Assessment Report",
) -> ReportSections:
    """Render register contents as Markdown, CSV, and evidence JSON."""
    sorted_findings = sorted(register.findings, key=_sort_key)
    high_critical = [f for f in sorted_findings if f.band in _HIGH_BANDS]

    md = _render_markdown(
        register=register,
        sorted_findings=sorted_findings,
        high_critical=high_critical,
        dora_gaps=dora_gaps or [],
        title=assessment_title,
    )
    csv_str = _render_csv(sorted_findings)
    evidence_json = _render_evidence_json(evidence or [])

    return ReportSections(
        markdown=md,
        findings_csv=csv_str,
        evidence_json=evidence_json,
    )


def _render_markdown(
    register: RiskRegister,
    sorted_findings: list[RiskFinding],
    high_critical: list[RiskFinding],
    dora_gaps: list[Any],
    title: str,
) -> str:
    lines: list[str] = []

    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"**Assessment ID:** {register.assessment_id}")
    lines.append(f"**Methodology:** {register.methodology_version or 'N/A'}")
    lines.append(f"**Total findings:** {len(register.findings)}")
    lines.append(f"**HIGH/CRITICAL findings:** {len(high_critical)}")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    if high_critical:
        lines.append(
            f"This assessment identified **{len(high_critical)} HIGH or CRITICAL** "
            f"risk findings out of {len(register.findings)} total. "
            "Immediate action is required on findings marked CRITICAL."
        )
    else:
        lines.append(
            f"This assessment identified {len(register.findings)} findings. "
            "No HIGH or CRITICAL risks were identified."
        )
    lines.append("")

    lines.append("## Findings Table")
    lines.append("")
    lines.append("| ID | Title | Category | Band | Score | Status |")
    lines.append("|---|---|---|---|---|---|")
    for f in sorted_findings:
        lines.append(
            f"| {f.finding_id} | {f.title} | {f.category} "
            f"| **{f.band or 'N/A'}** | {f.residual_score or 'N/A'} | {f.status} |"
        )
    lines.append("")

    lines.append("## Control Gap Table")
    lines.append("")
    lines.append("| Finding ID | Title | Remediation |")
    lines.append("|---|---|---|")
    for f in sorted_findings:
        if f.remediation:
            lines.append(f"| {f.finding_id} | {f.title} | {f.remediation} |")
    lines.append("")

    if dora_gaps:
        lines.append("## DORA Compliance Gaps")
        lines.append("")
        lines.append("| Rule | Article | Description | Entity |")
        lines.append("|---|---|---|---|")
        for gap in dora_gaps:
            lines.append(
                f"| {gap.rule_id} | {gap.article_ref} "
                f"| {gap.description} | {gap.entity_id} |"
            )
        lines.append("")

    return "\n".join(lines)


def _render_csv(findings: list[RiskFinding]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=[
            "finding_id",
            "title",
            "category",
            "band",
            "inherent_score",
            "residual_score",
            "status",
            "remediation",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for f in findings:
        writer.writerow({
            "finding_id": f.finding_id,
            "title": f.title,
            "category": f.category,
            "band": f.band or "",
            "inherent_score": f.inherent_score or "",
            "residual_score": f.residual_score or "",
            "status": f.status,
            "remediation": f.remediation,
        })
    return buf.getvalue()


def _render_evidence_json(evidence: list[Evidence]) -> str:
    return json.dumps(
        [
            {
                "evidence_id": e.evidence_id,
                "source_type": e.source_type,
                "source_ref": e.source_ref,
                "excerpt": e.excerpt[:200] if e.excerpt else "",
                "reliability": e.effective_reliability(),
            }
            for e in evidence
        ],
        indent=2,
    )
