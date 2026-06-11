"""Tests for the LiteLLM proxy gateway adapter — all HTTP calls are mocked."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch

import pytest

from riskos.adapters.gateway import LiteLLMProxyConfig, LiteLLMProxyGateway
from riskos.gateway import GenerationGatewayError, ImageContent, StructuredGenerationRequest
from riskos.schemas.generation import InventoryGeneration

_API_KEY = "sentinel-key-xyz"
_PROXY_URL = "http://proxy.example.com/v1/chat/completions"


def _config() -> LiteLLMProxyConfig:
    return LiteLLMProxyConfig(proxy_url=_PROXY_URL, api_key=_API_KEY, max_retries=2)


def _request(**kwargs) -> StructuredGenerationRequest:
    defaults = dict(
        route="inventory-extraction",
        system_prompt="system",
        user_message="user",
        prompt_version="1",
        timeout_seconds=5.0,
    )
    defaults.update(kwargs)
    return StructuredGenerationRequest(**defaults)


def _openai_response(payload: dict) -> MagicMock:
    """Wrap a payload dict in the OpenAI chat completion envelope."""
    envelope = {
        "id": "chatcmpl-test",
        "choices": [{"message": {"role": "assistant", "content": json.dumps(payload)}}],
    }
    mock = MagicMock()
    mock.__enter__ = lambda s: s
    mock.__exit__ = MagicMock(return_value=False)
    mock.read.return_value = json.dumps(envelope).encode("utf-8")
    return mock


def _valid_payload() -> dict:
    return InventoryGeneration().model_dump()


# ---------------------------------------------------------------------------
# success
# ---------------------------------------------------------------------------

def test_success_returns_validated_instance():
    gateway = LiteLLMProxyGateway(_config())

    with patch("urllib.request.urlopen", return_value=_openai_response(_valid_payload())):
        result = gateway.generate_structured(_request(), InventoryGeneration)

    assert isinstance(result, InventoryGeneration)


def test_request_uses_route_as_model():
    gateway = LiteLLMProxyGateway(_config())

    with patch("urllib.request.urlopen", return_value=_openai_response(_valid_payload())) as mock_open:
        gateway.generate_structured(_request(route="threat_modeler"), InventoryGeneration)

    body = json.loads(mock_open.call_args[0][0].data)
    assert body["model"] == "threat_modeler"


def test_request_contains_system_and_user_messages():
    gateway = LiteLLMProxyGateway(_config())

    with patch("urllib.request.urlopen", return_value=_openai_response(_valid_payload())) as mock_open:
        gateway.generate_structured(
            _request(system_prompt="be a risk analyst", user_message="analyse this"),
            InventoryGeneration,
        )

    body = json.loads(mock_open.call_args[0][0].data)
    assert body["messages"][0] == {"role": "system", "content": "be a risk analyst"}
    assert body["messages"][1] == {"role": "user", "content": "analyse this"}


def test_response_format_carries_json_schema():
    gateway = LiteLLMProxyGateway(_config())

    with patch("urllib.request.urlopen", return_value=_openai_response(_valid_payload())) as mock_open:
        gateway.generate_structured(_request(), InventoryGeneration)

    body = json.loads(mock_open.call_args[0][0].data)
    rf = body["response_format"]
    assert rf["type"] == "json_schema"
    assert rf["json_schema"]["name"] == "InventoryGeneration"
    assert "properties" in rf["json_schema"]["schema"]


# ---------------------------------------------------------------------------
# images
# ---------------------------------------------------------------------------

def test_images_expand_user_content_to_multimodal():
    gateway = LiteLLMProxyGateway(_config())
    img = ImageContent(media_type="image/png", data_b64="aGVsbG8=")

    with patch("urllib.request.urlopen", return_value=_openai_response(_valid_payload())) as mock_open:
        gateway.generate_structured(_request(images=[img]), InventoryGeneration)

    body = json.loads(mock_open.call_args[0][0].data)
    user_content = body["messages"][1]["content"]
    assert isinstance(user_content, list)
    assert user_content[0] == {"type": "text", "text": "user"}
    assert user_content[1]["type"] == "image_url"
    assert "data:image/png;base64,aGVsbG8=" in user_content[1]["image_url"]["url"]


def test_no_images_keeps_user_content_as_string():
    gateway = LiteLLMProxyGateway(_config())

    with patch("urllib.request.urlopen", return_value=_openai_response(_valid_payload())) as mock_open:
        gateway.generate_structured(_request(), InventoryGeneration)

    body = json.loads(mock_open.call_args[0][0].data)
    assert isinstance(body["messages"][1]["content"], str)


# ---------------------------------------------------------------------------
# retries
# ---------------------------------------------------------------------------

def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url=_PROXY_URL, code=code, msg=f"HTTP {code}", hdrs={}, fp=None)  # type: ignore[arg-type]


def test_retries_on_5xx_then_succeeds():
    gateway = LiteLLMProxyGateway(_config())
    side_effects = [_http_error(503), _http_error(503), _openai_response(_valid_payload())]

    with patch("urllib.request.urlopen", side_effect=side_effects) as mock_open:
        result = gateway.generate_structured(_request(), InventoryGeneration)

    assert isinstance(result, InventoryGeneration)
    assert mock_open.call_count == 3


def test_4xx_raises_immediately_no_retry():
    gateway = LiteLLMProxyGateway(_config())

    with patch("urllib.request.urlopen", side_effect=_http_error(400)) as mock_open:
        with pytest.raises(GenerationGatewayError):
            gateway.generate_structured(_request(), InventoryGeneration)

    mock_open.assert_called_once()


def test_timeout_raises_generation_gateway_error():
    gateway = LiteLLMProxyGateway(_config())

    with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
        with pytest.raises(GenerationGatewayError):
            gateway.generate_structured(_request(), InventoryGeneration)


def test_all_retries_exhausted_raises():
    gateway = LiteLLMProxyGateway(_config())

    with patch("urllib.request.urlopen", side_effect=[_http_error(503)] * 3):
        with pytest.raises(GenerationGatewayError, match="after retries"):
            gateway.generate_structured(_request(), InventoryGeneration)


# ---------------------------------------------------------------------------
# malformed responses
# ---------------------------------------------------------------------------

def test_malformed_json_raises():
    gateway = LiteLLMProxyGateway(_config())
    bad = MagicMock()
    bad.__enter__ = lambda s: s
    bad.__exit__ = MagicMock(return_value=False)
    bad.read.return_value = b"not-valid-json{"

    with patch("urllib.request.urlopen", return_value=bad):
        with pytest.raises(GenerationGatewayError):
            gateway.generate_structured(_request(), InventoryGeneration)


def test_missing_choices_key_raises():
    gateway = LiteLLMProxyGateway(_config())
    bad_envelope = MagicMock()
    bad_envelope.__enter__ = lambda s: s
    bad_envelope.__exit__ = MagicMock(return_value=False)
    bad_envelope.read.return_value = json.dumps({"error": "something"}).encode()

    with patch("urllib.request.urlopen", return_value=bad_envelope):
        with pytest.raises(GenerationGatewayError):
            gateway.generate_structured(_request(), InventoryGeneration)


def test_schema_violation_raises():
    gateway = LiteLLMProxyGateway(_config())
    bad_payload = {**_valid_payload(), "unexpected_extra_field": "boom"}

    with patch("urllib.request.urlopen", return_value=_openai_response(bad_payload)):
        with pytest.raises(GenerationGatewayError):
            gateway.generate_structured(_request(), InventoryGeneration)


# ---------------------------------------------------------------------------
# api_key never leaks into error messages
# ---------------------------------------------------------------------------

def test_api_key_not_in_timeout_error():
    gateway = LiteLLMProxyGateway(_config())
    with patch("urllib.request.urlopen", side_effect=TimeoutError()):
        with pytest.raises(GenerationGatewayError) as exc_info:
            gateway.generate_structured(_request(), InventoryGeneration)
    assert _API_KEY not in str(exc_info.value)


def test_api_key_not_in_4xx_error():
    gateway = LiteLLMProxyGateway(_config())
    with patch("urllib.request.urlopen", side_effect=_http_error(400)):
        with pytest.raises(GenerationGatewayError) as exc_info:
            gateway.generate_structured(_request(), InventoryGeneration)
    assert _API_KEY not in str(exc_info.value)


def test_api_key_not_in_5xx_exhausted_error():
    gateway = LiteLLMProxyGateway(_config())
    with patch("urllib.request.urlopen", side_effect=[_http_error(503)] * 3):
        with pytest.raises(GenerationGatewayError) as exc_info:
            gateway.generate_structured(_request(), InventoryGeneration)
    assert _API_KEY not in str(exc_info.value)


def test_api_key_not_in_schema_error():
    gateway = LiteLLMProxyGateway(_config())
    bad = {**_valid_payload(), "forbidden_field": True}
    with patch("urllib.request.urlopen", return_value=_openai_response(bad)):
        with pytest.raises(GenerationGatewayError) as exc_info:
            gateway.generate_structured(_request(), InventoryGeneration)
    assert _API_KEY not in str(exc_info.value)


# ---------------------------------------------------------------------------
# from_env
# ---------------------------------------------------------------------------

def test_from_env_missing_both_raises(monkeypatch):
    monkeypatch.delenv("RISKOS_PROXY_URL", raising=False)
    monkeypatch.delenv("RISKOS_PROXY_API_KEY", raising=False)
    with pytest.raises(GenerationGatewayError) as exc_info:
        LiteLLMProxyConfig.from_env()
    assert "RISKOS_PROXY_URL" in str(exc_info.value)
    assert "RISKOS_PROXY_API_KEY" in str(exc_info.value)


def test_from_env_success(monkeypatch):
    monkeypatch.setenv("RISKOS_PROXY_URL", "http://proxy.example.com/v1/chat/completions")
    monkeypatch.setenv("RISKOS_PROXY_API_KEY", "test-key-abc")
    config = LiteLLMProxyConfig.from_env()
    assert config.proxy_url == "http://proxy.example.com/v1/chat/completions"
    assert config.api_key == "test-key-abc"
