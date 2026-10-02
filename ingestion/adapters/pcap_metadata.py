"""Offline adapter for CSV or Zeek-style pre-extracted PCAP metadata only."""
from pathlib import Path
import csv
from datetime import datetime

from ingestion.adapters.common import normalize_ip
from ingestion.adapters.json_adapter import JsonAdapter
from ingestion.base import BaseEventAdapter, clean_text
from ingestion.errors import RecordParseError
from models.event import NormalizedEvent
from ingestion.base import read_bounded_lines
from app.config import settings

PCAP_HEADER_KEYS = {"src_ip", "source_ip", "ip.src", "id.orig_h", "id.resp_h", "src"}


class PcapMetadataAdapter(BaseEventAdapter):
    name = "pcap_metadata"

    def can_handle(self, source: str | Path) -> bool:
        path = Path(source)
        if path.suffix.lower() in {".pcap", ".pcapng"}:
            return False  # Binary capture parsing is intentionally out of scope.
        try:
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                sample = "\n".join(stream.readline(8192) for _ in range(settings.ingest_detection_lines)).lower()
            return any(key in sample for key in PCAP_HEADER_KEYS) and any(key in sample for key in ("dst", "resp_h", "protocol", "proto"))
        except OSError:
            return False

    def parse_record(self, line: str, line_number: int) -> NormalizedEvent:
        raise NotImplementedError("PCAP CSV is parsed as a table by parse()")

    def parse(self, source: str | Path):
        self.errors = []
        self.error_count = 0
        source_path = Path(source)
        if source_path.suffix.lower() in {".pcap", ".pcapng"}:
            raise RecordParseError("binary PCAP parsing is disabled; provide pre-extracted offline metadata")
        self._source = source_path.resolve(strict=True)
        rows = read_bounded_lines(self._source, self.max_line_length)
        fields = None
        delimiter = ","
        zeek_header = False
        for row_number, text, line_error in rows:
            if line_error:
                self._record_error(row_number, line_error)
                continue
            if text is None or not text.strip():
                continue
            if fields is None:
                if text.startswith("#separator"):
                    zeek_header = True
                    delimiter = "\t"
                    continue
                if text.startswith("#fields"):
                    fields = text.strip().split("\t")[1:]
                    continue
                if text.startswith("#"):
                    continue
                fields = next(csv.reader([text]))
                if zeek_header:
                    delimiter = "\t"
                    continue
                continue
            if text.startswith("#"):
                continue
            try:
                row = next(csv.reader([text], delimiter=delimiter))
                if len(row) != len(fields):
                    raise RecordParseError("PCAP metadata column count does not match header")
                event = self._event(dict(zip(fields, row)), row_number, row)
                event.raw_ref = f"{self._source}:{row_number}"
                event.raw_record = text
                yield event
            except (ValueError, TypeError, KeyError) as exc:
                self._record_error(row_number, str(exc))

    def _event(self, item, line_number, raw_row):
        timestamp = item.get("timestamp") or item.get("time") or item.get("ts") or item.get("frame.time") or item.get("frame.time_epoch")
        if timestamp is None:
            raise RecordParseError("PCAP metadata row missing timestamp")
        if isinstance(timestamp, str) and timestamp and not timestamp[0].isdigit():
            # Common tshark display-time rendering; truncate nanoseconds to Python's microsecond precision.
            candidate = timestamp.replace(" UTC", "+0000").replace(" GMT", "+0000")
            if "." in candidate:
                head, tail = candidate.split(".", 1)
                digits = "".join(char for char in tail if char.isdigit())[:6]
                suffix = "+0000" if "+0000" in tail else ""
                candidate = f"{head}.{digits}{suffix}"
            try:
                timestamp = datetime.strptime(candidate, "%b %d, %Y %H:%M:%S.%f%z")
            except ValueError as exc:
                try:
                    timestamp = datetime.strptime(candidate, "%b %d, %Y %H:%M:%S%z")
                except ValueError:
                    raise RecordParseError("unsupported tshark display timestamp") from exc
        src = item.get("source_ip") or item.get("src_ip") or item.get("id.orig_h") or item.get("ip.src") or item.get("src")
        dst = item.get("destination_ip") or item.get("dst_ip") or item.get("id.resp_h") or item.get("ip.dst") or item.get("dst")
        return NormalizedEvent(timestamp=self.timestamp(timestamp), source_type=self.name, source=self.name,
            source_ip=normalize_ip(src), destination_ip=normalize_ip(dst),
            source_port=JsonAdapter._port(item.get("source_port") or item.get("src_port") or item.get("id.orig_p") or item.get("tcp.srcport") or item.get("udp.srcport")),
            destination_port=JsonAdapter._port(item.get("destination_port") or item.get("dst_port") or item.get("id.resp_p") or item.get("tcp.dstport") or item.get("udp.dstport")),
            protocol=clean_text(item.get("protocol") or item.get("proto") or item.get("frame.protocols")), event_type="network_connection",
            packet_count=JsonAdapter._count(item.get("packet_count") or item.get("packets")),
            raw_event={"fields": item, "row": raw_row})
