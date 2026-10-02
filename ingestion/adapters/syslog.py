"""General RFC3164-style syslog adapter."""
from pathlib import Path
import re

from ingestion.adapters.common import normalize_ip
from ingestion.base import BaseEventAdapter, clean_text
from ingestion.constants import map_event_type
from ingestion.errors import RecordParseError
from app.config import settings
from models.event import NormalizedEvent

HEADER = re.compile(r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[^:\s]+)(?:\[\d+\])?:\s*(?P<message>.*)$")
RFC5424 = re.compile(r"^<\d{1,3}>\d\s+(?P<stamp>\S+)\s+(?P<host>\S+)\s+(?P<proc>\S+)\s+\S+\s+\S+\s+(?P<message>.*)$")
IP_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?!\d)|(?<![\w:])[0-9a-fA-F]*:[0-9a-fA-F:]+(?![\w:])")
USER_RE = re.compile(r"\b(?:user|for|account)[= :]+['\"]?([\w.@$-]+)", re.I)


def classify_message(message: str) -> str:
    lower = message.lower()
    if any(s in lower for s in ("failed password", "authentication failure", "login failed", "invalid password")):
        return "auth_failure"
    if any(s in lower for s in ("accepted password", "accepted publickey", "login successful", "logged in")):
        return "auth_success"
    if "logged out" in lower or "session closed" in lower or "logoff" in lower:
        return "logoff"
    if "account created" in lower or "new user" in lower:
        return "account_created"
    if "sudo" in lower or "privilege" in lower:
        return "privilege_assigned"
    if "account" in lower and "created" in lower:
        return "account_created"
    if "account" in lower and "enabled" in lower:
        return "account_enabled"
    if "account" in lower and "disabled" in lower:
        return "account_disabled"
    if "account" in lower and "deleted" in lower:
        return "account_deleted"
    if "account" in lower and ("locked" in lower or "lockout" in lower):
        return "account_lockout"
    if "password" in lower and "changed" in lower:
        return "password_change"
    if "membership" in lower and ("added" in lower or "changed" in lower):
        return "group_membership_change"
    if "audit log" in lower and "cleared" in lower:
        return "audit_log_cleared"
    if "service" in lower and "created" in lower:
        return "service_created"
    if "connection" in lower and any(s in lower for s in ("accepted", "opened", "connected")):
        return "network_connection"
    return "unknown"


class SyslogAdapter(BaseEventAdapter):
    name = "syslog"

    def can_handle(self, source: str | Path) -> bool:
        try:
            with Path(source).open("r", encoding="utf-8", errors="replace") as stream:
                for _ in range(settings.ingest_detection_lines):
                    line = stream.readline(8192)
                    if not line:
                        break
                    if HEADER.match(line.rstrip("\r\n")) or RFC5424.match(line.rstrip("\r\n")):
                        return True
        except OSError:
            return False
        return False

    def parse_record(self, line: str, line_number: int) -> NormalizedEvent:
        header = HEADER.match(line) or RFC5424.match(line)
        if not header:
            raise RecordParseError("not a recognized syslog record")
        message = header.group("message")
        stamp = header.group("stamp")
        ip_match = IP_RE.search(message)
        src_ip = normalize_ip(ip_match.group(0)) if ip_match else None
        user_match = USER_RE.search(message)
        event_type = classify_message(message)
        timestamp = self.timestamp(stamp) if stamp.startswith(tuple("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())) else stamp
        return NormalizedEvent(timestamp=self.timestamp(timestamp), source_type=self.name,
            source=self.name, hostname=clean_text(header.group("host")), username=clean_text(user_match.group(1)) if user_match else None,
            source_ip=src_ip, process_name=clean_text(header.group("proc")), event_type=event_type, original_event_type=message[:200],
            raw_event={"line": line, "process": clean_text(header.group("proc")), "message": message})
