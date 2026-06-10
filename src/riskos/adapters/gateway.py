"""HTTP adapter that forwards structured-generation requests to a managed proxy."""

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
    """Connection settings for the managed generation proxy."""

    model_config = ConfigDict(extra="forbid")

    proxy_url: str
    api_key: str
    max_retries: int = 2

    @classmethod
    def from_env(cls) -> "LiteLLMProxyConfig":
        """Build config from environment variables.

        Raises:
            GenerationGatewayError: if RISKOS_PROXY_URL or RISKOS_PROXY_API_KEY
                are not set.
        """
        proxy_url = os.environ.get("RISKOS_PROXY_URL")
        api_key = os.environ.get("RISKOS_PROXY_API_KEY")

        missing = []
        if not proxy_url:
            missing.append("RISKOS_PROXY_URL")
        if not api_key:
            missing.append("RISKOS_PROXY_API_KEY")
        if missing:
            raise GenerationGatewayError(
                f"Required environment variable(s) not set: {', '.join(missing)}"
            )

        return cls(proxy_url=proxy_url, api_key=api_key)  # type: ignore[arg-type]


class LiteLLMProxyGateway:
    """Forwards structured-generation requests to a managed HTTP proxy."""

    def __init__(self, config: LiteLLMProxyConfig) -> None:
        self._config = config

    def generate_structured(
        self,
        request: StructuredGenerationRequest,
        response_model: type[T],
    ) -> T:
        """POST the request to the proxy and return a validated response instance.

        Retries up to config.max_retries times on 5xx or connection errors.
        Never retries on 4xx responses.

        Raises:
            GenerationGatewayError: on any failure (timeout, HTTP error,
                invalid JSON, schema mismatch).
        """
        body = json.dumps(
            {
                "request": request.model_dump(),
                "response_schema": response_model.model_json_schema(),
            }
        ).encode("utf-8")

        req = urllib.request.Request(
            url=self._config.proxy_url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._config.api_key}",
            },
            method="POST",
        )

        last_error: Exception | None = None

        for attempt in range(self._config.max_retries + 1):
            try:
                response = urllib.request.urlopen(
                    req, timeout=request.timeout_seconds
                )
                raw = response.read()
                break

            except TimeoutError as exc:
                raise GenerationGatewayError(
                    "Request to proxy timed out"
                ) from exc

            except urllib.error.HTTPError as exc:
                if 400 <= exc.code < 500:
                    raise GenerationGatewayError(
                        f"Proxy returned client error: {exc.code}"
                    ) from exc
                # 5xx — retryable
                last_error = exc
                continue

            except urllib.error.URLError as exc:
                last_error = exc
                continue

        else:
            raise GenerationGatewayError(
                "Proxy request failed after retries"
            ) from last_error

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GenerationGatewayError(
                "Proxy returned non-JSON response"
            ) from exc

        try:
            return response_model.model_validate(payload)
        except ValidationError as exc:
            raise GenerationGatewayError(
                "Proxy response did not match expected schema"
            ) from exc
