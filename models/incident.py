"""Incident aggregate and lifecycle models."""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
from models.timestamps import to_utc_iso

INCIDENT_STATUSES = {"NEW", "TRIAGED", "INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED"}


@dataclass
class Incident:
    title: str
    description: str = ""
    incident_id: str = field(default_factory=lambda: f"INC-{uuid4().hex[:12].upper()}")
    created_at: str | None = field(default_factory=lambda: to_utc_iso(datetime.now(timezone.utc)))
    updated_at: str | None = None
    status: str = "NEW"
    severity: str = "LOW"
    risk_score: int = 0
    confidence: float | None = None
    source_ip: str | None = None
    hostname: str | None = None
    username: str | None = None
    alert_ids: list[str] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    mitre: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    status_history: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.created_at = to_utc_iso(self.created_at or self.updated_at or datetime.now(timezone.utc))
        self.updated_at = to_utc_iso(self.updated_at or self.created_at)
        if self.status not in INCIDENT_STATUSES:
            raise ValueError(f"Unsupported incident status: {self.status}")
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
