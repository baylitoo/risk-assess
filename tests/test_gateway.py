import pytest

from riskos.gateway import FakeLLMGateway, GatewayError
from riskos.schemas.generation import InventoryGeneration


def test_fake_returns_configured_response():
    gateway = FakeLLMGateway()
    response = InventoryGeneration()
    gateway.set_response(InventoryGeneration, response)

    result = gateway.generate_structured(
        system_prompt="sys", user_message="usr",
        response_model=InventoryGeneration, model_id="test",
    )

    assert result is response


def test_fake_records_calls():
    gateway = FakeLLMGateway()
    gateway.set_response(InventoryGeneration, InventoryGeneration())

    gateway.generate_structured("sys", "usr", InventoryGeneration, "m1")
    gateway.generate_structured("sys2", "usr2", InventoryGeneration, "m2")

    assert len(gateway.calls) == 2
    assert gateway.calls[0]["model_id"] == "m1"
    assert gateway.calls[1]["model_id"] == "m2"


def test_fake_raises_on_unconfigured_type():
    gateway = FakeLLMGateway()

    with pytest.raises(KeyError, match="InventoryGeneration"):
        gateway.generate_structured("sys", "usr", InventoryGeneration, "test")


def test_fake_call_contains_full_context():
    gateway = FakeLLMGateway()
    gateway.set_response(InventoryGeneration, InventoryGeneration())

    gateway.generate_structured(
        system_prompt="my-sys",
        user_message="my-usr",
        response_model=InventoryGeneration,
        model_id="claude-test",
        max_tokens=1234,
    )

    call = gateway.calls[0]
    assert call["system_prompt"] == "my-sys"
    assert call["user_message"] == "my-usr"
    assert call["max_tokens"] == 1234
