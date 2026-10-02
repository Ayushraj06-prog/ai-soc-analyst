"""Analyst identity and feedback model (no authentication secrets stored here)."""
from dataclasses import asdict, dataclass
from uuid import uuid4


@dataclass
class Analyst:
    username: str
    display_name: str | None = None
    role: str = "analyst"
    user_id: str = ""

    def __post_init__(self) -> None:
        if not self.user_id:
            self.user_id = str(uuid4())

    def to_dict(self) -> dict:
        return asdict(self)
