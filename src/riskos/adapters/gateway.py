"""HTTP adapter that forwards structured-generation requests to a LiteLLM proxy.

LiteLLM exposes an OpenAI-compatible /v1/chat/completions endpoint.
The `route` field in StructuredGenerationRequest maps to LiteLLM's `model`
parameter — LiteLLM's routing config resolves that to the actual deployment.

Set:
  RISKOS_PROXY_URL     e.g. http://my-litellm-instance/v1/chat/completions
  RISKOS_PROXY_API_KEY your proxy key (never logged or included in errors)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import TypeVar

from pydantic import BaseModel, ConfigDict, ValidationError

from riskos.gateway import GenerationGatewayError, StructuredGenerationRequest

T = TypeVar("T", bound=BaseModel)


class LiteLLMProxyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proxy_url: str
    api_key: str
    max_retries: int = 2

    @classmethod
    def from_env(cls) -> "LiteLLMProxyConfig":
        proxy_url = os.environ.get("RISKOS_PROXY_URL")
        api_key = os.environ.get("RISKOS_PROXY_API_KEY")
        missing = [k for k, v in [("RISKOS_PROXY_URL", proxy_url), ("RISKOS_PROXY_API_KEY", api_key)] if not v]
        if missing:
            raise GenerationGatewayError(f"Missing env vars: {', '.join(missing)}")
        return cls(proxy_url=proxy_url, api_key=api_key)  # type: ignore[arg-type]


class LiteLLMProxyGateway:
    """Sends structured-generation requests to a LiteLLM /v1/chat/completions endpoint."""

    def __init__(self, config: LiteLLMProxyConfig) -> None:
        self._config = config

    def generate_structured(
        self,
        request: StructuredGenerationRequest,
        response_model: type[T],
    ) -> T:
        """POST to LiteLLM, parse the assistant message, validate against response_model.

        - route → model  (LiteLLM resolves route to deployment)
        - system_prompt + user_message → messages[]
        - response_model schema → response_format (json_schema)
        - Retries on 5xx / connection errors; never retries 4xx.
        - API key is never included in raised exceptions.
        """
        body = json.dumps(self._build_payload(request, response_model)).encode("utf-8")

        req = urllib.request.Request(
            url=self._config.proxy_url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._config.api_key}",
            },
            method="POST",
        )

        raw = self._send_with_retry(req, request.timeout_seconds)
        return self._parse_response(raw, response_model)

    # ------------------------------------------------------------------

    @staticmethod
    def _build_payload(
        request: StructuredGenerationRequest,
        response_model: type[BaseModel],
    ) -> dict:
        # User content: text only, or multimodal if images are present
        if request.images:
            user_content: str | list = [{"type": "text", "text": request.user_message}]
            for img in request.images:
                user_content.append({
                    "type": "image_url",
                    "image_url": {
                        "url": f"data:{img.media_type};base64,{img.data_b64}"
                    },
                })
        else:
            user_content = request.user_message

        return {
            "model": request.route,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": user_content},
            ],
            "max_tokens": request.max_output_tokens,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": response_model.__name__,
                    "schema": response_model.model_json_schema(),
                    "strict": True,
                },
            },
        }

    def _send_with_retry(self, req: urllib.request.Request, timeout: float) -> bytes:
        last_error: Exception | None = None
        for _ in range(self._config.max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.read()
            except TimeoutError as exc:
                raise GenerationGatewayError("Proxy request timed out") from exc
            except urllib.error.HTTPError as exc:
                if 400 <= exc.code < 500:
                    body = ""
                    try:
                        body = exc.read().decode("utf-8", errors="replace")
                    except Exception:  # noqa: BLE001
                        pass
                    raise GenerationGatewayError(
                        f"Proxy returned {exc.code}: {body[:200]}"
                    ) from exc
                last_error = exc
            except urllib.error.URLError as exc:
                last_error = exc
        raise GenerationGatewayError("Proxy request failed after retries") from last_error

    @staticmethod
    def _parse_response(raw: bytes, response_model: type[T]) -> T:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GenerationGatewayError("Proxy returned non-JSON response") from exc

        # Standard OpenAI chat completion shape
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise GenerationGatewayError(
                f"Unexpected proxy response shape: {list(data.keys()) if isinstance(data, dict) else type(data)}"
            ) from exc

        # content may be a JSON string or already a dict (some LiteLLM versions)
        if isinstance(content, str):
            try:
                content = json.loads(content)
            except json.JSONDecodeError as exc:
                raise GenerationGatewayError(
                    "Assistant message content is not valid JSON"
                ) from exc

        try:
            return response_model.model_validate(content)
        except ValidationError as exc:
            raise GenerationGatewayError(
                f"Response did not match {response_model.__name__} schema: {exc.error_count()} error(s)"
            ) from exc
