"""Schemas for the bounded SOC assistant chat."""
from pydantic import BaseModel, ConfigDict, Field


class AssistantChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=2000)
    context: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class AssistantChatResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answer: str
    provider: str
    model: str | None
    warning: str | None = None
