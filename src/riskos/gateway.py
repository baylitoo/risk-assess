"""Model-agnostic structured-generation boundary.

Application code selects a task-level route. A company-managed LiteLLM proxy
resolves that route to its configured deployment. Providers and model names
never enter domain code, prompts, or workflow artifacts.
"""

from __future__ import annotations

from typing import Protocol, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T", bound=BaseModel)


class ImageContent(BaseModel):
    """A base64-encoded image to include alongside text in a generation request."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    media_type: str = Field(min_length=1)  # e.g. "image/png", "image/jpeg"
    data_b64: str = Field(min_length=1)    # standard base64, no data-URI prefix


class StructuredGenerationRequest(BaseModel):
    """Serializable request sent through the managed generation proxy."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    route: str = Field(min_length=1)
    system_prompt: str = Field(min_length=1)
    user_message: str = Field(min_length=1)
    prompt_version: str = Field(min_length=1)
    max_output_tokens: int = Field(default=8192, ge=1)
    timeout_seconds: float = Field(default=120.0, gt=0)
    images: list[ImageContent] = Field(default_factory=list)


class StructuredGenerationGateway(Protocol):
    """Return only validated structured output for a proxy-routed request."""

    def generate_structured(
        self,
        request: StructuredGenerationRequest,
        response_model: type[T],
    ) -> T:
        ...


class GenerationGatewayError(Exception):
    """Raised when the managed generation proxy cannot satisfy a request."""


class FakeStructuredGenerationGateway:
    """Deterministic test double with serialized request recording."""

    def __init__(self) -> None:
        self._responses: dict[type[BaseModel], BaseModel] = {}
        self.calls: list[StructuredGenerationRequest] = []

    def set_response(self, response_model: type[BaseModel], response: BaseModel) -> None:
        self._responses[response_model] = response

    def generate_structured(
        self,
        request: StructuredGenerationRequest,
        response_model: type[BaseModel],
    ) -> BaseModel:
        self.calls.append(request)
        if response_model not in self._responses:
            raise GenerationGatewayError(
                f"no response configured for {response_model.__name__!r}"
            )
        return self._responses[response_model]
