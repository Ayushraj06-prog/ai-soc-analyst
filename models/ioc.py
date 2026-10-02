"""IOC representation used by ingestion and enrichment stages."""
from dataclasses import asdict, dataclass, field
from typing import Any
from models.ids import make_id


@dataclass
class IOC:
    value: str
    type: str
    first_seen: str | None = None
    last_seen: str | None = None
    source: str | None = None
    confidence: float | None = None
    associated_alerts: list[str] = field(default_factory=list)
    reputation: dict[str, Any] | None = None
    ioc_id: str = ""

    def __post_init__(self) -> None:
        if not self.ioc_id:
            self.ioc_id = make_id("ioc", self.type.strip().lower(), self.value.strip().lower())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
