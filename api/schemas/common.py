from typing import Any, Generic, TypeVar
from pydantic import BaseModel, ConfigDict, Field


T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    model_config = ConfigDict(extra="forbid")
    items: list[T] = Field(default_factory=list)
    total: int
    limit: int
    offset: int


class Items(BaseModel, Generic[T]):
    model_config = ConfigDict(extra="forbid")
    items: list[T] = Field(default_factory=list)
    total: int


class IncidentPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str | None = Field(default=None, max_length=32)
    notes: str | None = Field(default=None, max_length=4000)


class InvestigateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    force: bool = False


class ErrorResponse(BaseModel):
    error: dict[str, str]


class HealthResponse(BaseModel):
    status: str
    service: str


class ReadyResponse(BaseModel):
    status: str
    database: str
    schema_version: int | None = None


class SystemStatusResponse(BaseModel):
    status: str
    environment: str
    application_version: str
    schema_version: int | None
    database: str
    ai_provider: str
    ai_provider_status: str
