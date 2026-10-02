"""Inventory record for a monitored asset."""
from dataclasses import asdict, dataclass
from uuid import uuid4


@dataclass
class Asset:
    hostname: str
    asset_id: str = ""
    criticality: str = "MEDIUM"
    owner: str | None = None
    environment: str | None = None
    ip_address: str | None = None

    def __post_init__(self) -> None:
        if not self.asset_id:
            self.asset_id = str(uuid4())

    def to_dict(self) -> dict:
        return asdict(self)
