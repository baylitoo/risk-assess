"""Tests for the HTTP proxy gateway adapter — all HTTP calls are mocked."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from riskos.adapters.gateway import LiteLLMProxyConfig, LiteLLMProxyGateway
from riskos.gateway import GenerationGatewayError, StructuredGenerationRequest
from riskos.schemas.generation import InventoryGeneration

_API_KEY = "sentinel-key-xyz"
_PROXY_URL = "http://proxy.example.com/generate"


def _config() -> LiteLLMProxyConfig:
    return LiteLLMProxyConfig(
        proxy_url=_PROXY_URL,
        api_key=_API_KEY,
        max_retries=2,
    )


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


def _make_response(payload: dict) -> MagicMock:
    """Return a urlopen-compatible mock that yields JSON bytes."""
    mock = MagicMock()
    mock.read.return_value = json.dumps(payload).encode("utf-8")
    return mock


def _valid_payload() -> dict:
    return InventoryGeneration().model_dump()


# ---------------------------------------------------------------------------
# success
# ---------------------------------------------------------------------------


def test_success_returns_validated_instance():
    gateway = LiteLLMProxyGateway(_config())
    resp_mock = _make_response(_valid_payload())

    with patch("urllib.request.urlopen", return_value=resp_mock) as mock_open:
        result = gateway.generate_structured(_request(), InventoryGeneration)

    assert isinstance(result, InventoryGeneration)
    mock_open.assert_called_once()


# ---------------------------------------------------------------------------
# timeout
# ---------------------------------------------------------------------------


def test_timeout_raises_generation_gateway_error():
    gateway = LiteLLMProxyGateway(_config())

    with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
        with pytest.raises(GenerationGatewayError):
            gateway.generate_structured(_request(), InventoryGeneration)


# ---------------------------------------------------------------------------
# retry on 5xx: two 503s then 200 → success
# ---------------------------------------------------------------------------


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url=_PROXY_URL,
        code=code,
        msg=f"HTTP {code}",
        hdrs={},  # type: ignore[arg-type]
        fp=None,
    )


def test_retries_on_5xx_then_succeeds():
    gateway = LiteLLMProxyGateway(_config())
    resp_mock = _make_response(_valid_payload())

    side_effects = [_http_error(503), _http_error(503), resp_mock]

    with patch("urllib.request.urlopen", side_effect=side_effects) as mock_open:
        result = gateway.generate_structured(_request(), InventoryGeneration)

    assert isinstance(result, InventoryGeneration)
    assert mock_open.call_count == 3


# ---------------------------------------------------------------------------
# 400 → no retry, called exactly once
# ---------------------------------------------------------------------------


def test_4xx_raises_immediately_no_retry():
    gateway = LiteLLMProxyGateway(_config())

    with patch("urllib.request.urlopen", side_effect=_http_error(400)) as mock_open:
        with pytest.raises(GenerationGatewayError):
            gateway.generate_structured(_request(), InventoryGeneration)

    mock_open.assert_called_once()


# ---------------------------------------------------------------------------
# malformed JSON
# ---------------------------------------------------------------------------


def test_malformed_json_raises_generation_gateway_error():
    gateway = LiteLLMProxyGateway(_config())
    bad_resp = MagicMock()
    bad_resp.read.return_value = b"not-valid-json{"

    with patch("urllib.request.urlopen", return_value=bad_resp):
        with pytest.raises(GenerationGatewayError):
            gateway.generate_structured(_request(), InventoryGeneration)


# ---------------------------------------------------------------------------
# valid JSON that violates Pydantic schema (extra field → extra="forbid")
# ---------------------------------------------------------------------------


def test_schema_violation_raises_generation_gateway_error():
    gateway = LiteLLMProxyGateway(_config())
    bad_payload = {**_valid_payload(), "unexpected_extra_field": "boom"}
    bad_resp = _make_response(bad_payload)

    with patch("urllib.request.urlopen", return_value=bad_resp):
        with pytest.raises(GenerationGatewayError):
            gateway.generate_structured(_request(), InventoryGeneration)


# ---------------------------------------------------------------------------
# from_env missing variables
# ---------------------------------------------------------------------------


def test_from_env_missing_both_vars_raises(monkeypatch):
    monkeypatch.delenv("RISKOS_PROXY_URL", raising=False)
    monkeypatch.delenv("RISKOS_PROXY_API_KEY", raising=False)

    with pytest.raises(GenerationGatewayError) as exc_info:
        LiteLLMProxyConfig.from_env()

    msg = str(exc_info.value)
    assert "RISKOS_PROXY_URL" in msg
    assert "RISKOS_PROXY_API_KEY" in msg


def test_from_env_missing_url_only_raises(monkeypatch):
    monkeypatch.delenv("RISKOS_PROXY_URL", raising=False)
    monkeypatch.setenv("RISKOS_PROXY_API_KEY", "some-key")

    with pytest.raises(GenerationGatewayError) as exc_info:
        LiteLLMProxyConfig.from_env()

    assert "RISKOS_PROXY_URL" in str(exc_info.value)


def test_from_env_missing_key_only_raises(monkeypatch):
    monkeypatch.setenv("RISKOS_PROXY_URL", "http://proxy.example.com")
    monkeypatch.delenv("RISKOS_PROXY_API_KEY", raising=False)

    with pytest.raises(GenerationGatewayError) as exc_info:
        LiteLLMProxyConfig.from_env()

    assert "RISKOS_PROXY_API_KEY" in str(exc_info.value)


def test_from_env_success(monkeypatch):
    monkeypatch.setenv("RISKOS_PROXY_URL", "http://proxy.example.com/gen")
    monkeypatch.setenv("RISKOS_PROXY_API_KEY", "test-key-abc")

    config = LiteLLMProxyConfig.from_env()

    assert config.proxy_url == "http://proxy.example.com/gen"
    assert config.api_key == "test-key-abc"


# ---------------------------------------------------------------------------
# api_key never leaks into error messages
# ---------------------------------------------------------------------------


def test_api_key_not_in_timeout_error():
    gateway = LiteLLMProxyGateway(_config())

    with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
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
    # Three 503s exhausts the max_retries=2 budget
    side_effects = [_http_error(503)] * 3

    with patch("urllib.request.urlopen", side_effect=side_effects):
        with pytest.raises(GenerationGatewayError) as exc_info:
            gateway.generate_structured(_request(), InventoryGeneration)

    assert _API_KEY not in str(exc_info.value)


def test_api_key_not_in_malformed_json_error():
    gateway = LiteLLMProxyGateway(_config())
    bad_resp = MagicMock()
    bad_resp.read.return_value = b"{{bad"

    with patch("urllib.request.urlopen", return_value=bad_resp):
        with pytest.raises(GenerationGatewayError) as exc_info:
            gateway.generate_structured(_request(), InventoryGeneration)

    assert _API_KEY not in str(exc_info.value)


def test_api_key_not_in_schema_error():
    gateway = LiteLLMProxyGateway(_config())
    bad_resp = _make_response({**_valid_payload(), "forbidden_field": True})

    with patch("urllib.request.urlopen", return_value=bad_resp):
        with pytest.raises(GenerationGatewayError) as exc_info:
            gateway.generate_structured(_request(), InventoryGeneration)

    assert _API_KEY not in str(exc_info.value)
