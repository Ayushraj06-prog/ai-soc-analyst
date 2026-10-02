"""Windows Security Event JSON/XML adapter with DTD/entity rejection."""
from pathlib import Path
import json
import xml.etree.ElementTree as ET
from app.config import settings

from ingestion.adapters.common import decode_json, first, normalize_ip, safe_raw
from ingestion.base import BaseEventAdapter, clean_text
from ingestion.constants import WINDOWS_EVENT_TYPES
from ingestion.errors import RecordParseError
from models.event import NormalizedEvent


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].split(":")[-1]


class WindowsEventsAdapter(BaseEventAdapter):
    name = "windows_events"

    def can_handle(self, source: str | Path) -> bool:
        path = Path(source)
        if path.name.lower().startswith("windows") or path.suffix.lower() in {".evtx.json", ".xml"}:
            return True
        try:
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                for _ in range(settings.ingest_detection_lines):
                    line = stream.readline(8192)
                    if not line:
                        break
                    lower = line.lower()
                    if "eventid" in lower and ("computer" in lower or "timecreated" in lower or "<event" in lower):
                        return True
        except OSError:
            return False
        return False

    def parse(self, source: str | Path):
        path = Path(source)
        if path.suffix.lower() != ".xml":
            yield from super().parse(source)
            return
        self.errors = []
        self.error_count = 0
        self._source = path.resolve(strict=True)
        tail = b""
        current_line_bytes = 0
        with self._source.open("rb") as stream:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                combined = (tail + chunk).lower()
                if b"<!doctype" in combined or b"<!entity" in combined:
                    raise RecordParseError("Windows XML DTDs and entities are not permitted")
                pieces = chunk.split(b"\n")
                if len(pieces) == 1:
                    current_line_bytes += len(chunk)
                else:
                    if current_line_bytes + len(pieces[0]) > self.max_line_length:
                        raise RecordParseError("Windows XML line exceeds configured maximum length")
                    if any(len(piece) > self.max_line_length for piece in pieces[1:-1]):
                        raise RecordParseError("Windows XML line exceeds configured maximum length")
                    current_line_bytes = len(pieces[-1])
                tail = combined[-16:]
        try:
            event_number = 0
            for _, element in ET.iterparse(self._source, events=("end",)):
                if _local(element.tag) != "Event":
                    continue
                event_number += 1
                xml_record = ET.tostring(element, encoding="unicode")
                try:
                    event = self._parse_xml(xml_record)
                    event.raw_ref = f"{self._source}:event:{event_number}"
                    event.raw_record = xml_record
                    yield event
                except (ValueError, TypeError, KeyError) as exc:
                    self._record_error(event_number, str(exc))
                element.clear()
            if event_number == 0:
                raise RecordParseError("Windows XML document contains no Event records")
        except ET.ParseError as exc:
            raise RecordParseError(f"invalid Windows XML document: {exc}") from exc

    def parse_record(self, line: str, line_number: int) -> NormalizedEvent:
        if line.lstrip().startswith("<"):
            return self._parse_xml(line)
        return self._parse_json(decode_json(line))

    def _parse_json(self, data: dict) -> NormalizedEvent:
        wrapper = data.get("Event") if isinstance(data.get("Event"), dict) else {}
        system = data.get("System") or data.get("system") or wrapper.get("System") or wrapper.get("system") or {}
        event_data = data.get("EventData") or data.get("event_data") or wrapper.get("EventData") or wrapper.get("event_data") or {}
        event_id = first(data, "EventID", "EventId", "event_id", "eventId")
        if isinstance(event_id, dict):
            event_id = event_id.get("#text") or event_id.get("value")
        if event_id is None:
            event_id = first(system, "EventID", "EventId", "event_id")
        timestamp = first(data, "TimeCreated", "timestamp", "time", "event_time")
        if isinstance(timestamp, dict):
            timestamp = first(timestamp, "SystemTime", "system_time", "value", "@SystemTime")
        if timestamp is None:
            timestamp = first(system, "TimeCreated", "timestamp")
            if isinstance(timestamp, dict):
                timestamp = first(timestamp, "SystemTime", "@SystemTime")
        host = first(data, "Computer", "computer", "hostname", "host") or first(system, "Computer")
        fields = {}
        if isinstance(event_data, dict):
            fields.update(event_data)
            values = event_data.get("Data")
            if isinstance(values, list):
                for entry in values:
                    if isinstance(entry, dict):
                        name = entry.get("Name") or entry.get("name")
                        value = entry.get("#text") or entry.get("value")
                        if name:
                            fields[name] = value
        if wrapper:
            fields.update({k: v for k, v in wrapper.items() if k not in {"System", "EventData"}})
        username = first(data, "TargetUserName", "SubjectUserName", "User", "username", "user", "account")
        username = username or first(fields, "TargetUserName", "SubjectUserName", "AccountName", "UserName")
        target_user = first(fields, "TargetUserName", "TargetAccountName")
        actor_user = first(fields, "SubjectUserName", "SubjectAccountName")
        source_ip = first(data, "IpAddress", "SourceAddress", "source_ip", "src_ip") or first(fields, "IpAddress", "SourceAddress", "ClientAddress")
        if source_ip in {"-", "::1", "127.0.0.1"}:
            source_ip = None if source_ip == "-" else source_ip
        if timestamp is None:
            raise RecordParseError("Windows event is missing a timestamp")
        if event_id is None:
            raise RecordParseError("Windows event is missing EventID")
        try:
            numeric_id = int(event_id)
        except (TypeError, ValueError) as exc:
            raise RecordParseError("invalid Windows EventID") from exc
        return NormalizedEvent(timestamp=self.timestamp(timestamp), source_type=self.name, source=self.name,
            hostname=clean_text(host), username=clean_text(username), target_user=clean_text(target_user), source_ip=normalize_ip(source_ip),
            group_name=clean_text(first(fields, "GroupName", "TargetGroupName")),
            service_name=clean_text(first(fields, "ServiceName", "ServiceFileName")),
            attributes={**safe_raw(fields), "actor_user": clean_text(actor_user), "windows_event_id": numeric_id},
            event_type=WINDOWS_EVENT_TYPES.get(numeric_id, "unknown"), original_event_type=str(numeric_id),
            raw_event=safe_raw(data))

    def _parse_xml(self, xml_text: str) -> NormalizedEvent:
        lowered = xml_text.lower()
        if "<!doctype" in lowered or "<!entity" in lowered:
            raise RecordParseError("Windows XML DTDs and entities are not permitted")
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise RecordParseError(f"invalid Windows XML: {exc}") from exc
        values: dict[str, str] = {}
        for node in root.iter():
            tag = _local(node.tag)
            if tag == "EventID":
                values["EventID"] = node.text or node.attrib.get("Qualifiers", "")
            elif tag == "Computer":
                values["Computer"] = node.text or ""
            elif tag == "TimeCreated":
                values["TimeCreated"] = node.attrib.get("SystemTime", "")
            elif tag == "Data":
                name = node.attrib.get("Name")
                if name:
                    values[name] = node.text or ""
        return self._parse_json(values)
