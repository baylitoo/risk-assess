"""VulnWorker: policy-enforced vuln operator pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from riskos.ids import stable_id
from riskos.runtime.harness import AgentHarness
from riskos.schemas.artifacts import (
    AssetInventory,
    Producer,
    VulnerabilityFindings,
)
from riskos.vuln.correlate import correlate_inventory
from riskos.vuln.mirror import EpssScoreMirror, KevMirror, NvdMirror


@dataclass
class VulnConfig:
    mirror_root: str | None = None
    cvss_threshold: float = 7.0


@dataclass
class VulnResult:
    vuln_artifact_id: str
    finding_count: int
    evidence_count: int
    audit_event_count: int = 0


class VulnWorker:
    """Correlate CVE mirror data against inventory and emit VulnerabilityFindings."""

    def __init__(
        self,
        harness: AgentHarness,
        config: VulnConfig | None = None,
    ) -> None:
        self._harness = harness
        self._config = config or VulnConfig()

    def run(self, inventory: AssetInventory) -> VulnResult:
        config = self._config
        root = config.mirror_root
        nvd = NvdMirror(root=root)
        kev = KevMirror(root=root)
        epss = EpssScoreMirror(root=root)

        findings, evidence = correlate_inventory(
            inventory=inventory,
            nvd=nvd,
            kev=kev,
            epss=epss,
            cvss_threshold=config.cvss_threshold,
        )

        producer = Producer(agent="vuln_operator")
        artifact = VulnerabilityFindings(
            artifact_id=stable_id(
                "artifact", inventory.assessment_id, "vulnerability_findings", "1"
            ),
            assessment_id=inventory.assessment_id,
            phase="vuln_analysis",
            producer=producer,
            findings=findings,
            evidence=evidence,
        )
        self._harness.write_artifact(artifact)
        audit_count = len(self._harness.audit_log.read_all())

        return VulnResult(
            vuln_artifact_id=artifact.artifact_id,
            finding_count=len(findings),
            evidence_count=len(evidence),
            audit_event_count=audit_count,
        )
