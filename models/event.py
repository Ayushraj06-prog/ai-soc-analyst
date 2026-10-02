"""Normalized, dependency-free telemetry event model."""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from typing import Any
from models.ids import make_id
from models.timestamps import to_utc_iso


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SecurityEvent:
    event_id: str = ""
    timestamp: str = field(default_factory=utc_now)
    source: str | None = None
    hostname: str | None = None
    username: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    event_type: str | None = None
    action: str | None = None
    status: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    file_hash: str | None = None
    url: str | None = None
    domain: str | None = None
    user_agent: str | None = None
    raw_event: Any = None
    raw_record: str | None = None
    packet_count: int | None = None
    confidence: float | None = None
    source_type: str | None = None
    raw_ref: str | None = None
    ingest_batch_id: str | None = None
    original_event_type: str | None = None
    raw_truncated: bool = False
    target_user: str | None = None
    group_name: str | None = None
    service_name: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.timestamp = to_utc_iso(self.timestamp)
        if not self.event_id:
            identity = self.to_dict()
            identity.pop("event_id", None)
            canonical_identity = json.dumps(identity, sort_keys=True, default=str, separators=(",", ":"))
            self.event_id = make_id("event", canonical_identity)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


NormalizedEvent = SecurityEvent
