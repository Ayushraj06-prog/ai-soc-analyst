"""JSON-lines security event adapter with common field-name aliases."""
from pathlib import Path
import json

from ingestion.adapters.common import decode_json, first, flatten_fields, normalize_ip, safe_raw
from ingestion.base import BaseEventAdapter
from ingestion.constants import map_event_type
from ingestion.errors import RecordParseError
from models.event import NormalizedEvent
from app.config import settings

PCAP_KEYS = {"src_ip", "source_ip", "ip.src", "id.orig_h", "src", "source"}


class JsonAdapter(BaseEventAdapter):
    name = "json"

    def can_handle(self, source: str | Path) -> bool:
        path = Path(source)
        if path.suffix.lower() in {".json", ".jsonl", ".ndjson"}:
            return True
        try:
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                for _ in range(settings.ingest_detection_lines):
                    line = stream.readline(8192)
                    if not line:
                        break
                    if line.strip():
                        return line.lstrip().startswith(("{", "["))
        except OSError:
            return False
        return False

    def parse_record(self, line: str, line_number: int) -> NormalizedEvent:
        item = decode_json(line)
        fields = {**item, **flatten_fields(item)}
        timestamp = first(fields, "timestamp", "time", "event_time", "ts", "_time", "frame.time_epoch", "frame.time")
        if timestamp is None:
            raise RecordParseError("missing timestamp")
        src = first(fields, "source_ip", "src_ip", "client_ip", "src", "id.orig_h", "ip.src")
        dst = first(fields, "destination_ip", "dst_ip", "server_ip", "dst", "id.resp_h", "ip.dst")
        raw_type = first(fields, "event_type", "event", "type", "EventID", "EventId")
        is_pcap = any(key in fields for key in PCAP_KEYS) and any(key in fields for key in ("dst_ip", "destination_ip", "id.resp_h", "ip.dst"))
        event_type = "network_connection" if is_pcap else map_event_type(raw_type)
        return NormalizedEvent(timestamp=self.timestamp(timestamp), source_type="pcap_metadata" if is_pcap else self.name,
            source="pcap_metadata" if is_pcap else self.name,
            hostname=first(fields, "hostname", "host", "computer"), username=first(fields, "username", "user", "account"),
            target_user=first(fields, "target_user", "target_username", "TargetUserName"),
            group_name=first(fields, "group_name", "group", "GroupName"),
            service_name=first(fields, "service_name", "service", "ServiceName"),
            attributes=safe_raw(fields),
            source_ip=normalize_ip(src), destination_ip=normalize_ip(dst),
            source_port=self._port(first(fields, "source_port", "src_port", "id.orig_p", "tcp.srcport", "udp.srcport")),
            destination_port=self._port(first(fields, "destination_port", "dst_port", "id.resp_p", "tcp.dstport", "udp.dstport")),
            protocol=first(fields, "protocol", "proto", "network.transport", "frame.protocols"), event_type=event_type,
            packet_count=self._count(first(fields, "packet_count", "packets")),
            original_event_type=str(raw_type)[:200] if raw_type is not None else None,
            raw_event=safe_raw(item))

    def parse(self, source: str | Path):
        path = Path(source).resolve(strict=True)
        with path.open("r", encoding="utf-8", errors="replace", newline="") as stream:
            prefix = ""
            while True:
                char = stream.read(1)
                if not char or not char.isspace():
                    prefix = char
                    break
            if prefix != "[":
                yield from super().parse(path)
                return
            self.errors = []
            self.error_count = 0
            self._source = path
            decoder = json.JSONDecoder()
            buffer = "[" + stream.read(65536)
            position = 1
            eof = False
            record_number = 0
            while True:
                while position < len(buffer) and (buffer[position].isspace() or buffer[position] == ","):
                    position += 1
                if position >= len(buffer) and not eof:
                    buffer = buffer[position:] + stream.read(65536)
                    position = 0
                    eof = not bool(buffer)
                    continue
                if position >= len(buffer):
                    raise RecordParseError("unterminated JSON array")
                if buffer[position] == "]":
                    return
                try:
                    value, end = decoder.raw_decode(buffer, position)
                except json.JSONDecodeError as exc:
                    if eof:
                        raise RecordParseError(f"invalid JSON array: {exc.msg}") from exc
                    if len(buffer) - position > self.max_line_length:
                        raise RecordParseError("JSON array member exceeds configured maximum length") from exc
                    more = stream.read(65536)
                    if more:
                        buffer += more
                    else:
                        eof = True
                    continue
                record_number += 1
                try:
                    if not isinstance(value, dict):
                        raise RecordParseError("JSON array members must be objects")
                    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
                    event = self.parse_record(raw, record_number)
                    event.raw_ref = f"{path}:record:{record_number}"
                    event.raw_record = raw
                    yield event
                except (ValueError, TypeError, KeyError) as exc:
                    self._record_error(record_number, str(exc))
                position = end
                if position > 65536:
                    buffer = buffer[position:]
                    position = 0

    @staticmethod
    def _port(value):
        if value is None:
            return None
        try:
            port = int(value)
        except (TypeError, ValueError) as exc:
            raise RecordParseError("invalid port") from exc
        if not 0 <= port <= 65535:
            raise RecordParseError("port outside 0..65535")
        return port

    @staticmethod
    def _count(value):
        if value is None:
            return None
        try:
            count = int(value)
        except (TypeError, ValueError) as exc:
            raise RecordParseError("invalid packet count") from exc
        if count < 0:
            raise RecordParseError("packet count must be non-negative")
        return count
