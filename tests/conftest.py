from pathlib import Path

import pytest

from riskos.ids import stable_id
from riskos.schemas.artifacts import (
    AssetInventory,
    Citation,
    Evidence,
    EvidenceSource,
    FindingCategory,
    Producer,
    RiskFinding,
)
from riskos.schemas.entities import Component, DataAsset, Exposure, System, ThirdParty

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture()
def producer() -> Producer:
    return Producer(agent="test", prompt_version="0")


@pytest.fixture()
def inventory(producer: Producer) -> AssetInventory:
    """A small but representative inventory: internet-facing API with PII,
    a GenAI helper, an admin console, and a third-party processor."""
    sys_id = stable_id("system", "payments-hub")
    api = Component(
        id=stable_id("component", "payments-hub", "public-api"),
        name="public-api", system_id=sys_id, exposure=Exposure.INTERNET_FACING,
        technology="ExampleHTTPd 2.4",
    )
    admin = Component(
        id=stable_id("component", "payments-hub", "admin-console"),
        name="admin-console", system_id=sys_id, is_admin_interface=True,
    )
    bot = Component(
        id=stable_id("component", "payments-hub", "support-copilot"),
        name="support-copilot", system_id=sys_id, is_genai=True,
    )
    pii = DataAsset(
        id=stable_id("data_asset", "payments-hub", "customer-records"),
        name="customer-records", system_id=sys_id, contains_pii=True,
    )
    vendor = ThirdParty(
        id=stable_id("third_party", "acme-kyc"),
        name="acme-kyc", service="KYC checks",
    )
    return AssetInventory(
        artifact_id=stable_id("artifact", "test", "inventory", "1"),
        assessment_id=stable_id("assessment", "test"),
        phase="intake",
        producer=producer,
        systems=[System(id=sys_id, name="payments-hub")],
        components=[api, admin, bot],
        data_assets=[pii],
        third_parties=[vendor],
    )


def make_finding(
    category: FindingCategory,
    asset_ids: list[str],
    factors: dict[str, str] | None = None,
    citations: list[Citation] | None = None,
    finding_id: str | None = None,
    band: str = "",
) -> RiskFinding:
    return RiskFinding(
        finding_id=finding_id or stable_id("finding", category.value, *asset_ids),
        title=f"test {category.value}",
        category=category,
        scenario="test scenario",
        affected_asset_ids=asset_ids,
        factors=factors or {},
        citations=citations or [],
        band=band,
    )


@pytest.fixture()
def evidence_doc() -> Evidence:
    return Evidence(
        evidence_id=stable_id("evidence", "doc", "sats", "4.2"),
        source_type=EvidenceSource.DOCUMENT,
        source_ref="SATS §4.2",
        excerpt="The API is exposed to the internet without rate limiting.",
    )
