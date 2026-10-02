"""Shared adapter contract and bounded record streaming helpers."""
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Protocol, runtime_checkable
import unicodedata
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.config import settings
from ingestion.errors import RecordParseError
from models.event import NormalizedEvent
from models.timestamps import to_utc_iso


@runtime_checkable
class EventAdapter(Protocol):
    name: str
    def can_handle(self, source: str | Path) -> bool: ...
    def parse(self, source: str | Path) -> Iterator[NormalizedEvent]: ...


def clean_text(value: object, limit: int = 65536) -> str | None:
    if value is None:
        return None
    text = str(value)
    text = "".join(char for char in text if unicodedata.category(char) != "Cc")
    text = text.strip()
    return text[:limit] if text else None


def parse_syslog_timestamp(value: str, assume_tz: str | None = None,
                           assume_year: int | None = None, now: datetime | None = None) -> str:
    """Parse RFC3164 month/day timestamps, correcting future dates across year rollover."""
    processing_now = now or datetime.now(timezone.utc)
    if processing_now.tzinfo is None:
        processing_now = processing_now.replace(tzinfo=timezone.utc)
    zone_name = assume_tz or settings.ingest_assume_tz
    if zone_name.strip().upper() in {"UTC", "GMT", "Z"}:
        zone = timezone.utc
    else:
        try:
            zone = ZoneInfo(zone_name)
        except ZoneInfoNotFoundError as exc:
            raise RecordParseError(f"timezone database does not contain {zone_name!r}") from exc
    year = assume_year or settings.ingest_assume_year or processing_now.astimezone(zone).year
    try:
        local = datetime.strptime(f"{year} {value.strip()}", "%Y %b %d %H:%M:%S").replace(tzinfo=zone)
    except ValueError as exc:
        raise RecordParseError(f"invalid syslog timestamp: {value!r}") from exc
    month_distance = (local.month - processing_now.astimezone(zone).month) % 12
    if month_distance > 6 and local.astimezone(timezone.utc) > processing_now.astimezone(timezone.utc):
        local = local.replace(year=year - 1)
    return to_utc_iso(local)


def read_bounded_lines(source: Path, max_line_length: int | None = None):
    limit = max_line_length or settings.ingest_max_line_length
    with source.open("r", encoding="utf-8", errors="replace", newline="") as stream:
        line_number = 0
        while True:
            chunk = stream.readline(limit + 2)
            if chunk == "":
                break
            line_number += 1
            too_long = len(chunk.rstrip("\r\n")) > limit or (not chunk.endswith(("\n", "\r")) and len(chunk) > limit)
            if too_long:
                while chunk and not chunk.endswith(("\n", "\r")):
                    chunk = stream.readline(limit + 2)
                yield line_number, None, "record exceeds configured maximum line length"
            else:
                yield line_number, chunk.rstrip("\r\n"), None


class BaseEventAdapter(ABC):
    name = "base"

    def __init__(self, *, assume_tz: str | None = None, assume_year: int | None = None,
                 max_line_length: int | None = None):
        self.assume_tz = assume_tz or settings.ingest_assume_tz
        self.assume_year = assume_year if assume_year is not None else settings.ingest_assume_year
        self.max_line_length = max_line_length or settings.ingest_max_line_length
        self.error_limit = settings.ingest_error_limit
        self.errors: list[tuple[int, str]] = []
        self.error_count = 0
        self._source: Path | None = None

    @abstractmethod
    def can_handle(self, source: str | Path) -> bool: ...

    @abstractmethod
    def parse_record(self, line: str, line_number: int) -> NormalizedEvent: ...

    def parse(self, source: str | Path) -> Iterator[NormalizedEvent]:
        self.errors = []
        self.error_count = 0
        self._source = Path(source).resolve(strict=True)
        for line_number, line, error in read_bounded_lines(self._source, self.max_line_length):
            if error:
                self._record_error(line_number, error)
                continue
            if not line or not line.strip():
                continue
            try:
                event = self.parse_record(line, line_number)
                event.raw_ref = f"{self._source}:{line_number}"
                event.raw_record = line
                yield event
            except (ValueError, TypeError, KeyError) as exc:
                self._record_error(line_number, str(exc))

    def _record_error(self, line_number: int, message: str) -> None:
        self.error_count += 1
        if len(self.errors) < self.error_limit:
            self.errors.append((line_number, clean_text(message, 500) or "invalid record"))

    def timestamp(self, value: object) -> str:
        if isinstance(value, str) and len(value.strip()) >= 15 and value.strip()[0:3].isalpha():
            return parse_syslog_timestamp(value, self.assume_tz, self.assume_year)
        if isinstance(value, str):
            numeric = value.strip()
            if numeric.replace(".", "", 1).isdigit():
                return to_utc_iso(float(numeric), self.assume_tz)
        return to_utc_iso(value, self.assume_tz)
