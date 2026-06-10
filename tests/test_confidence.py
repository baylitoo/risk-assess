import pytest
import yaml

from riskos.schemas.artifacts import Citation, FindingCategory, FindingStatus
from riskos.scoring import ConfidenceInputs, compute_confidence
from tests.conftest import REPO_ROOT, make_finding


@pytest.fixture(scope="module")
def config() -> dict:
    return yaml.safe_load((REPO_ROOT / "config" / "risk_matrix.yaml").read_text())


def test_confidence_is_computed_from_evidence(config, evidence_doc):
    f = make_finding(
        FindingCategory.ABUSE_PREVENTION, ["cmp-x"], band="medium",
        citations=[Citation(evidence_id=evidence_doc.evidence_id)],
    )
    out = compute_confidence(
        f, {evidence_doc.evidence_id: evidence_doc},
        ConfidenceInputs(extraction_confidence=0.9, mapping_confidence=1.0,
                         validation_status="tool_corroborated"),
        config,
    )
    # document reliability 0.8 × 0.9 × 1.0 × 1.0
    assert out.confidence == pytest.approx(0.72)
    assert out.status == FindingStatus.DRAFT  # medium band: no gate


def test_uncited_finding_has_zero_confidence(config):
    f = make_finding(FindingCategory.VULNERABILITY, ["cmp-x"], band="critical")
    out = compute_confidence(
        f, {}, ConfidenceInputs(1.0, 1.0, "human_confirmed"), config,
    )
    assert out.confidence == 0.0
    assert out.status == FindingStatus.REQUIRES_CONFIRMATION


def test_high_severity_low_confidence_requires_confirmation(config, evidence_doc):
    f = make_finding(
        FindingCategory.VULNERABILITY, ["cmp-x"], band="high",
        citations=[Citation(evidence_id=evidence_doc.evidence_id)],
    )
    out = compute_confidence(
        f, {evidence_doc.evidence_id: evidence_doc},
        ConfidenceInputs(extraction_confidence=0.6, mapping_confidence=0.9,
                         validation_status="unvalidated"),
        config,
    )
    # 0.8 × 0.6 × 0.9 × 0.8 = 0.3456 < 0.6 gate on a high finding
    assert out.confidence < 0.6
    assert out.status == FindingStatus.REQUIRES_CONFIRMATION


def test_unknown_validation_status_rejected(config, evidence_doc):
    f = make_finding(FindingCategory.VULNERABILITY, ["cmp-x"], band="low",
                     citations=[Citation(evidence_id=evidence_doc.evidence_id)])
    with pytest.raises(ValueError, match="validation_status"):
        compute_confidence(
            f, {evidence_doc.evidence_id: evidence_doc},
            ConfidenceInputs(1.0, 1.0, "i_feel_confident"), config,
        )
