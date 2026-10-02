"""Deterministic file-level batch identity and status helpers."""
from pathlib import Path
from datetime import datetime, timezone

from database.repositories import IngestBatchRepository
from models.ids import make_id
from models.timestamps import to_utc_iso


def build_batch(path: str | Path, started_at=None) -> dict:
    source = Path(path)
    content_hash = IngestBatchRepository.hash_file(source)
    source_file = str(source.resolve())
    return {
        "id": make_id("batch", source_file, content_hash),
        "source_file": source_file,
        "file_hash": content_hash,
        "started_at": to_utc_iso(started_at if started_at is not None else datetime.now(timezone.utc)),
        "event_count": 0,
        "status": "running",
        "errors_count": 0,
        "errors": [],
    }


def finalize_batch(batch: dict, event_count: int, errors_count: int, errors: list[str], *, failed: bool = False) -> dict:
    result = dict(batch)
    result.update(event_count=event_count, errors_count=errors_count, errors=list(errors),
                  status="failed" if failed else ("completed_with_errors" if errors_count else "completed"))
    return result
