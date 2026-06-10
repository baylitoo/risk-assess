"""Provider-abstracted LLM gateway Protocol.

All LLM calls in the platform go through this Protocol. Swapping providers
(Bedrock / direct API / stub) is a config change — one concrete adapter per
environment, injected by the harness.

Why a Protocol (structural subtyping) rather than an ABC:
- Provider adapters live in a different deployment layer (they pull in the
  Anthropic SDK, Bedrock client, etc.); forcing them to inherit from a base
  class would create a coupling across the dependency boundary.
- The fake test double can be in this module without importing any provider
  SDK, and it satisfies the Protocol at runtime.
"""

from __future__ import annotations

from typing import Protocol, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class LLMGateway(Protocol):
    """Minimal structured-generation contract.

    Returns a *validated* Pydantic model instance. The concrete adapter is
    responsible for prompting, parsing, retrying, and raising ``GatewayError``
    on unrecoverable failure. The caller never sees raw model output.
    """

    def generate_structured(
        self,
        system_prompt: str,
        user_message: str,
        response_model: type[T],
        model_id: str,
        max_tokens: int = 8192,
    ) -> T:
        ...


class GatewayError(Exception):
    """Raised by concrete adapters on unrecoverable generation failure."""


class FakeLLMGateway:
    """Deterministic test double — returns pre-configured responses by type.

    Supports optional call recording so tests can assert on prompts
    without coupling to internal implementation details.
    """

    def __init__(self) -> None:
        self._responses: dict[type[BaseModel], BaseModel] = {}
        self.calls: list[dict] = []

    def set_response(self, response_model: type[BaseModel], response: BaseModel) -> None:
        self._responses[response_model] = response

    def generate_structured(
        self,
        system_prompt: str,
        user_message: str,
        response_model: type[BaseModel],
        model_id: str,
        max_tokens: int = 8192,
    ) -> BaseModel:
        self.calls.append(
            dict(
                system_prompt=system_prompt,
                user_message=user_message,
                response_model=response_model,
                model_id=model_id,
                max_tokens=max_tokens,
            )
        )
        if response_model not in self._responses:
            raise KeyError(
                f"FakeLLMGateway: no response configured for {response_model.__name__!r}"
            )
        return self._responses[response_model]
