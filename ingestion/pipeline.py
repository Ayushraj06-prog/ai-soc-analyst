"""Safe, streaming, batch-aware normalization and persistence pipeline."""
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import stat
from typing import Iterable

from app.config import settings
from database.database import Database
from database.repositories import EventRepository, IngestBatchRepository
from ingestion.adapters import (AuthLogAdapter, JsonAdapter, PcapMetadataAdapter,
                                SyslogAdapter, WindowsEventsAdapter)
from ingestion.base import EventAdapter, clean_text, read_bounded_lines
from ingestion.constants import EVENT_TYPES
from ingestion.errors import IngestionError, NoAdapterError, UnsafeSourceError
from models.event import NormalizedEvent
from models.ids import stable_id
from models.timestamps import to_utc_iso


DEFAULT_ADAPTER_ORDER = ("auth_log", "windows_events", "json", "syslog", "pcap_metadata")


class IngestionPipeline:
    def __init__(self, database: Database | None = None, *, adapters: Iterable[EventAdapter] | None = None,
                 max_file_bytes: int | None = None, max_line_length: int | None = None,
                 max_raw_bytes: int | None = None, detection_lines: int | None = None,
                 invalid_threshold_percent: float | None = None, default_chunk_size: int | None = None):
        self.database = database or Database(settings.database_path)
        self.database.initialize()
        self.events = EventRepository(self.database)
        self.batches = IngestBatchRepository(self.database)
        self.max_file_bytes = max_file_bytes or settings.ingest_max_file_bytes
        self.max_line_length = max_line_length or settings.ingest_max_line_length
        self.max_raw_bytes = max_raw_bytes or settings.ingest_max_raw_bytes
        self.detection_lines = detection_lines or settings.ingest_detection_lines
        self.invalid_threshold_percent = (settings.ingest_invalid_threshold_percent if invalid_threshold_percent is None
                                           else invalid_threshold_percent)
        self.default_chunk_size = default_chunk_size or settings.ingest_chunk_size
        self.adapters = list(adapters) if adapters is not None else [
            AuthLogAdapter(max_line_length=self.max_line_length),
            WindowsEventsAdapter(max_line_length=self.max_line_length),
            JsonAdapter(max_line_length=self.max_line_length),
            SyslogAdapter(max_line_length=self.max_line_length),
            PcapMetadataAdapter(max_line_length=self.max_line_length),
        ]

    def select_adapter(self, source: str | Path, adapter_name: str | None = None) -> EventAdapter:
        if adapter_name:
            for adapter in self.adapters:
                if adapter.name == adapter_name:
                    return adapter
            raise NoAdapterError(f"Unknown adapter {adapter_name!r}; choose from {', '.join(a.name for a in self.adapters)}")
        for adapter in self.adapters:
            if adapter.can_handle(source):
                return adapter
        raise NoAdapterError(f"No ingestion adapter recognized {Path(source).name!r}")

    def ingest(self, source: str | Path, *, adapter_name: str | None = None,
               max_errors: int | None = None, chunk_size: int | None = None) -> dict:
        path = Path(source).expanduser()
        resolved = path.resolve(strict=False)
        source_name = str(resolved)
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            self._validate_source_path(path)
            size = path.stat().st_size
            if size > self.max_file_bytes:
                raise UnsafeSourceError(f"File size {size} exceeds limit {self.max_file_bytes} bytes")
            file_hash = self.batches.hash_file(path)
        except (OSError, ValueError, UnsafeSourceError) as exc:
            file_hash = hashlib.sha256(source_name.encode("utf-8", errors="replace")).hexdigest()
            batch = self._new_batch(source_name, file_hash, started_at)
            return self._finish_failure(batch, str(exc), source_name)

        batch = self._new_batch(source_name, file_hash, started_at)
        if self.batches.already_ingested(source_name, file_hash):
            batch.update(status="skipped_duplicate_file", errors=[], errors_count=0,
                         events_created=0, events_duplicate=0, events_invalid=0, event_count=0)
            self.batches.save(batch)
            return self._summary(batch, source_name)

        try:
            adapter = self.select_adapter(path, adapter_name)
        except NoAdapterError as exc:
            return self._finish_failure(batch, str(exc), source_name)

        batch["adapter"] = adapter.name
        batch["status"] = "running"
        self.batches.save(batch)
        limit_errors = settings.ingest_error_limit if max_errors is None else max(0, int(max_errors))
        if hasattr(adapter, "error_limit"):
            adapter.error_limit = limit_errors
        chunk_limit = max(1, int(chunk_size or self.default_chunk_size))
        counts = {"events_created": 0, "events_duplicate": 0, "events_invalid": 0, "errors": 0}
        diagnostics: list[str] = []
        occurrences: dict[tuple[str, str, str], int] = defaultdict(int)
        chunk: list[NormalizedEvent] = []

        def note_error(message: str) -> None:
            counts["errors"] += 1
            if len(diagnostics) < limit_errors:
                diagnostics.append(clean_text(message, 500) or "invalid record")

        def flush() -> None:
            if not chunk:
                return
            created, duplicates = self.events.save_many(chunk)
            counts["events_created"] += created
            counts["events_duplicate"] += duplicates
            chunk.clear()

        try:
            for event in adapter.parse(path):
                try:
                    raw_line = self._canonical_raw_line(event)
                    self._validate_event(event, adapter.name, batch["id"])
                    occurrence_key = (event.source_type or adapter.name, event.timestamp, raw_line)
                    occurrence = occurrences[occurrence_key]
                    occurrences[occurrence_key] += 1
                    event.event_id = stable_id("evt", occurrence_key[0], event.timestamp, raw_line, occurrence)
                    event.raw_record = None  # Identity uses the full line; persistence stores only capped raw_event.
                    chunk.append(event)
                    if len(chunk) >= chunk_limit:
                        flush()
                except (ValueError, TypeError, OSError) as exc:
                    counts["events_invalid"] += 1
                    note_error(f"{event.raw_ref or source_name}: {exc}")
            flush()
            adapter_errors = getattr(adapter, "errors", [])
            adapter_error_count = int(getattr(adapter, "error_count", len(adapter_errors)))
            counts["events_invalid"] += adapter_error_count
            counts["errors"] += adapter_error_count
            for line_number, message in adapter_errors:
                if len(diagnostics) < limit_errors:
                    diagnostics.append(f"{source_name}:{line_number}: {message}")
        except Exception as exc:
            note_error(f"batch read/parse failure: {exc}")
            flush()
            batch.update(status="failed", errors=diagnostics, errors_count=counts["errors"],
                         parse_error_count=counts["errors"], error_summary=" | ".join(diagnostics),
                         events_created=counts["events_created"], events_duplicate=counts["events_duplicate"],
                         events_invalid=counts["events_invalid"], event_count=counts["events_created"] + counts["events_duplicate"])
            self.batches.save(batch)
            return self._summary(batch, source_name)

        processed = counts["events_created"] + counts["events_duplicate"] + counts["events_invalid"]
        invalid_percent = (100.0 * counts["events_invalid"] / processed) if processed else (100.0 if counts["errors"] else 0.0)
        if invalid_percent > self.invalid_threshold_percent:
            status = "failed"
            if len(diagnostics) < limit_errors:
                diagnostics.append(f"invalid record rate {invalid_percent:.1f}% exceeds configured threshold")
        else:
            status = "completed_with_errors" if counts["errors"] else "completed"
        batch.update(status=status, event_count=counts["events_created"] + counts["events_duplicate"],
                     events_created=counts["events_created"], events_duplicate=counts["events_duplicate"],
                     events_invalid=counts["events_invalid"], errors_count=counts["errors"],
                     parse_error_count=counts["errors"], errors=diagnostics,
                     error_summary=" | ".join(diagnostics))
        self.batches.save(batch)
        return self._summary(batch, source_name)

    def _validate_source_path(self, path: Path) -> None:
        absolute = path.absolute()
        for component in (absolute, *absolute.parents):
            if component.is_symlink():
                raise UnsafeSourceError(f"Symbolic links are not accepted as ingestion sources: {component}")
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise UnsafeSourceError("Ingestion source must be a regular file")

    def _validate_event(self, event: NormalizedEvent, adapter_name: str, batch_id: str) -> None:
        if not event.timestamp:
            raise ValueError("missing timestamp")
        event.timestamp = to_utc_iso(event.timestamp, settings.ingest_assume_tz)
        event.source_type = clean_text(event.source_type or adapter_name, 64)
        event.source = clean_text(event.source or event.source_type, 64)
        event.hostname = clean_text(event.hostname, 255)
        event.username = clean_text(event.username, 256)
        event.event_type = event.event_type if event.event_type in EVENT_TYPES else "unknown"
        event.original_event_type = clean_text(event.original_event_type, 256)
        event.raw_ref = clean_text(event.raw_ref, 4096)
        event.ingest_batch_id = batch_id
        event.source_ip = self._validate_ip(event.source_ip)
        event.destination_ip = self._validate_ip(event.destination_ip)
        for attr in ("source_port", "destination_port"):
            port = getattr(event, attr)
            if port is not None and not 0 <= int(port) <= 65535:
                raise ValueError(f"{attr} outside 0..65535")
        if event.packet_count is not None and int(event.packet_count) < 0:
            raise ValueError("packet_count must be non-negative")
        event.protocol = clean_text(event.protocol, 32)
        event.raw_event = self._sanitize_raw(event.raw_event)
        encoded = json.dumps(event.raw_event, default=str, ensure_ascii=False, separators=(",", ":"))
        raw_bytes = encoded.encode("utf-8")
        if len(raw_bytes) > self.max_raw_bytes:
            truncated = raw_bytes[:self.max_raw_bytes].decode("utf-8", errors="ignore")
            event.raw_event = truncated
            event.raw_truncated = True

    @staticmethod
    def _validate_ip(value: str | None) -> str | None:
        if value is None:
            return None
        import ipaddress
        return str(ipaddress.ip_address(value))

    def _sanitize_raw(self, value):
        if isinstance(value, dict):
            return {clean_text(key, 256) or "": self._sanitize_raw(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._sanitize_raw(item) for item in value]
        if isinstance(value, str):
            return clean_text(value, self.max_raw_bytes) or ""
        return value

    @staticmethod
    def _canonical_raw_line(event: NormalizedEvent) -> str:
        if event.raw_record is not None:
            return event.raw_record
        raw = event.raw_event
        if isinstance(raw, dict) and isinstance(raw.get("line"), str):
            return raw["line"]
        return json.dumps(raw, sort_keys=True, default=str, ensure_ascii=False, separators=(",", ":"))

    def _new_batch(self, source: str, file_hash: str, started_at: str) -> dict:
        return {"id": stable_id("batch", source, file_hash), "source_file": source, "file_hash": file_hash,
                "started_at": started_at, "event_count": 0, "status": "running", "events_created": 0,
                "events_duplicate": 0, "events_invalid": 0, "errors_count": 0,
                "parse_error_count": 0, "errors": []}

    def _finish_failure(self, batch: dict, message: str, source: str) -> dict:
        safe = clean_text(message, 500) or "ingestion failed"
        batch.update(status="failed", errors=[safe], errors_count=1, parse_error_count=1,
                     events_invalid=0, error_summary=safe)
        self.batches.save(batch)
        return self._summary(batch, source)

    @staticmethod
    def _summary(batch: dict, source: str) -> dict:
        return {"batch_id": batch["id"], "source": source,
                "events_created": batch.get("events_created", 0),
                "events_duplicate": batch.get("events_duplicate", 0),
                "events_invalid": batch.get("events_invalid", 0),
                "errors": batch.get("errors_count", 0), "status": batch["status"],
                "adapter": batch.get("adapter"), "error_summary": batch.get("error_summary", "")}
