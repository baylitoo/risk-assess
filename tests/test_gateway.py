import pytest
from pydantic import ValidationError

from riskos.gateway import (
    FakeStructuredGenerationGateway,
    GenerationGatewayError,
    ImageContent,
    StructuredGenerationRequest,
)
from riskos.schemas.generation import InventoryGeneration


def _request(route: str = "inventory-extraction") -> StructuredGenerationRequest:
    return StructuredGenerationRequest(
        route=route,
        system_prompt="system",
        user_message="user",
        prompt_version="1",
    )


def test_fake_returns_configured_response():
    gateway = FakeStructuredGenerationGateway()
    response = InventoryGeneration()
    gateway.set_response(InventoryGeneration, response)

    result = gateway.generate_structured(_request(), InventoryGeneration)

    assert result is response


def test_fake_records_serializable_requests():
    gateway = FakeStructuredGenerationGateway()
    gateway.set_response(InventoryGeneration, InventoryGeneration())

    gateway.generate_structured(_request("inventory-extraction"), InventoryGeneration)
    gateway.generate_structured(_request("risk-synthesis"), InventoryGeneration)

    assert gateway.calls[0].route == "inventory-extraction"
    assert gateway.calls[1].route == "risk-synthesis"
    assert StructuredGenerationRequest.model_validate_json(
        gateway.calls[0].model_dump_json()
    ) == gateway.calls[0]


def test_fake_raises_on_unconfigured_type():
    gateway = FakeStructuredGenerationGateway()

    with pytest.raises(GenerationGatewayError, match="InventoryGeneration"):
        gateway.generate_structured(_request(), InventoryGeneration)


def test_request_records_budgets_and_prompt_version():
    request = StructuredGenerationRequest(
        route="inventory-extraction",
        system_prompt="system",
        user_message="user",
        prompt_version="2",
        max_output_tokens=1234,
        timeout_seconds=30,
    )

    assert request.prompt_version == "2"
    assert request.max_output_tokens == 1234
    assert request.timeout_seconds == 30


def test_request_rejects_model_or_provider_fields():
    with pytest.raises(ValidationError, match="extra_forbidden"):
        StructuredGenerationRequest.model_validate(
            {
                "route": "inventory-extraction",
                "system_prompt": "system",
                "user_message": "user",
                "prompt_version": "1",
                "model_id": "forbidden",
            }
        )


def test_request_with_images_serializes_and_round_trips():
    img = ImageContent(media_type="image/png", data_b64="aGVsbG8=")
    req = StructuredGenerationRequest(
        route="inventory-extraction",
        system_prompt="system",
        user_message="user",
        prompt_version="1",
        images=[img],
    )

    assert req.images[0].media_type == "image/png"
    assert req.images[0].data_b64 == "aGVsbG8="
    assert StructuredGenerationRequest.model_validate_json(req.model_dump_json()) == req


def test_request_images_defaults_to_empty():
    req = _request()
    assert req.images == []


def test_fake_gateway_records_images_per_call():
    gateway = FakeStructuredGenerationGateway()
    gateway.set_response(InventoryGeneration, InventoryGeneration())

    img = ImageContent(media_type="image/png", data_b64="aGVsbG8=")
    req = StructuredGenerationRequest(
        route="inventory-extraction",
        system_prompt="system",
        user_message="user",
        prompt_version="1",
        images=[img],
    )
    gateway.generate_structured(req, InventoryGeneration)

    assert len(gateway.calls[0].images) == 1
    assert gateway.calls[0].images[0].media_type == "image/png"


def test_image_content_rejects_empty_fields():
    with pytest.raises(ValidationError):
        ImageContent(media_type="", data_b64="aGVsbG8=")
