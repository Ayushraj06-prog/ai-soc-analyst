"""Linux authentication log adapter (RFC3164-style timestamps)."""
from pathlib import Path
import re

from ingestion.adapters.common import normalize_ip
from ingestion.base import BaseEventAdapter, clean_text
from ingestion.constants import map_event_type
from ingestion.errors import RecordParseError
from app.config import settings
from models.event import NormalizedEvent

HEADER = re.compile(r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[^:\s]+)(?:\[\d+\])?:\s*(?P<message>.*)$")
FAILURE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)", re.I)
SUCCESS = re.compile(r"Accepted (?:password|publickey|keyboard-interactive) for (?P<user>\S+) from (?P<ip>\S+)", re.I)


class AuthLogAdapter(BaseEventAdapter):
    name = "auth_log"

    def can_handle(self, source: str | Path) -> bool:
        path = Path(source)
        if path.name.lower() in {"auth.log", "secure"}:
            return True
        try:
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                sample = "\n".join(stream.readline(8192) for _ in range(settings.ingest_detection_lines)).lower()
            return "sshd" in sample and any(token in sample for token in ("failed password", "accepted password", "accepted publickey"))
        except OSError:
            return False

    def parse_record(self, line: str, line_number: int) -> NormalizedEvent:
        header = HEADER.match(line)
        if not header:
            raise RecordParseError("not a recognized authentication syslog record")
        message = header.group("message")
        match = FAILURE.search(message)
        event_type = "auth_failure"
        if match is None:
            match = SUCCESS.search(message)
            event_type = "auth_success"
        user = match.group("user") if match else None
        source_ip = normalize_ip(match.group("ip")) if match else None
        raw = {"line": line, "process": header.group("proc"), "message": message}
        return NormalizedEvent(timestamp=self.timestamp(header.group("stamp")), source_type=self.name,
            source=self.name, hostname=clean_text(header.group("host")), username=clean_text(user),
            source_ip=source_ip, process_name=clean_text(header.group("proc")), event_type=event_type if match else "unknown",
            original_event_type=message[:200], raw_event=raw)
