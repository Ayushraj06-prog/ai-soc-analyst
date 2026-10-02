"""Backward-compatible import path for the Phase 2 adapter contract."""
from dataclasses import dataclass, field

from ingestion.base import EventAdapter

LogAdapter = EventAdapter


@dataclass
class ParseErrorPolicy:
    """Skip record-level errors, count all, and retain only the first N diagnostics."""
    max_recorded_errors: int = 100
    errors_count: int = 0
    errors: list[str] = field(default_factory=list)

    def record(self, error: Exception | str, location: str | int | None = None) -> None:
        self.errors_count += 1
        if len(self.errors) < max(0, self.max_recorded_errors):
            prefix = f"{location}: " if location is not None else ""
            self.errors.append(f"{prefix}{error}")

    @property
    def batch_status(self) -> str:
        return "completed_with_errors" if self.errors_count else "completed"
