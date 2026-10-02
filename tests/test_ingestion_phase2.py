"""Phase 2 adapter and ingestion pipeline integration tests."""
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from database.database import Database
from database.repositories import EventRepository, IngestBatchRepository
from ingestion.adapters import (AuthLogAdapter, JsonAdapter, PcapMetadataAdapter,
                                SyslogAdapter, WindowsEventsAdapter)
from ingestion.base import EventAdapter, parse_syslog_timestamp
from ingestion.constants import EVENT_TYPES, WINDOWS_EVENT_TYPES
from ingestion.errors import RecordParseError
from ingestion.pipeline import DEFAULT_ADAPTER_ORDER, IngestionPipeline
from models.ids import stable_id
from models.timestamps import to_utc_iso


ROOT = Path(__file__).parent
FIXTURES = ROOT / "fixtures"


class PhaseTwoIngestionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = Database(self.root / "soc.db")
        self.pipeline = IngestionPipeline(self.db)

    def write(self, name: str, content: bytes | str) -> Path:
        path = self.root / name
        path.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
        return path

    def test_adapter_order_protocol_and_explicit_override(self):
        auth = FIXTURES / "auth.log"
        self.assertEqual(DEFAULT_ADAPTER_ORDER, ("auth_log", "windows_events", "json", "syslog", "pcap_metadata"))
        self.assertIsInstance(AuthLogAdapter(), EventAdapter)
        self.assertEqual(self.pipeline.select_adapter(auth).name, "auth_log")
        self.assertEqual(self.pipeline.select_adapter(auth, "syslog").name, "syslog")

    def test_auth_log_parses_failures_and_successes(self):
        adapter = AuthLogAdapter(assume_year=2026)
        events = list(adapter.parse(FIXTURES / "auth.log"))
        self.assertEqual([event.event_type for event in events], ["auth_failure", "auth_success"])
        self.assertEqual(events[0].username, "alice")
        self.assertEqual(events[0].source_ip, "192.0.2.10")
        self.assertTrue(events[0].raw_ref.endswith(":1"))

    def test_syslog_adapter_unknown_and_recognized_types(self):
        path = self.write("syslog.log", "Oct 01 10:00:00 node sshd[22]: Failed password for demo from 2001:db8::2 port 2\nOct 01 10:00:01 node app[1]: custom audit record\n")
        events = list(SyslogAdapter(assume_year=2026).parse(path))
        self.assertEqual(events[0].event_type, "auth_failure")
        self.assertEqual(events[0].source_ip, "2001:db8::2")
        self.assertEqual(events[1].event_type, "unknown")
        self.assertIsNone(events[1].username)
        rfc5424 = self.write("rfc5424.log", "<34>1 2026-10-01T10:00:00Z node sshd 2001 ID47 - Accepted password for demo from 192.0.2.61 port 22\n")
        event = list(SyslogAdapter().parse(rfc5424))[0]
        self.assertEqual(event.event_type, "auth_success")

    def test_timestamp_timezone_epoch_milliseconds_and_year_rollover(self):
        self.assertEqual(to_utc_iso(1_782_865_200_000), to_utc_iso(1_782_865_200))
        rollover = parse_syslog_timestamp("Dec 31 23:59:59", now=datetime(2026, 1, 2, tzinfo=timezone.utc))
        self.assertTrue(rollover.startswith("2025-12-31T23:59:59"))
        same_month_future_time = parse_syslog_timestamp("Jan 02 23:59:59", now=datetime(2026, 1, 2, 12, tzinfo=timezone.utc))
        self.assertTrue(same_month_future_time.startswith("2026-01-02T"))

    def test_json_aliases_unknown_vocabulary_and_normalization(self):
        result = self.pipeline.ingest(FIXTURES / "security.json")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["events_created"], 3)
        repository = EventRepository(self.db)
        rows = repository.list()
        self.assertEqual({event["event_type"] for event in rows}, {"auth_failure", "network_connection", "unknown"})
        failed = next(event for event in rows if event["event_type"] == "auth_failure")
        self.assertEqual(failed["source_ip"], "192.0.2.20")
        self.assertEqual(failed["hostname"], "lab-web-01")
        unknown = next(event for event in rows if event["event_type"] == "unknown")
        self.assertEqual(unknown["original_event_type"], "vendor_custom_alert")
        array_path = self.write("array.json", '[{"timestamp":"2026-10-01T11:00:00Z","event":"password changed"},{"timestamp":"2026-10-01T11:01:00Z","event":"account lockout"}]')
        array_result = self.pipeline.ingest(array_path)
        self.assertEqual(array_result["events_created"], 2)

    def test_windows_event_mappings_and_unknown_id(self):
        adapter = WindowsEventsAdapter()
        events = list(adapter.parse(FIXTURES / "windows_events.json"))
        self.assertEqual(events[0].event_type, "auth_failure")
        self.assertEqual(events[0].username, "demo-user")
        self.assertEqual(events[1].event_type, "unknown")
        self.assertEqual(events[1].original_event_type, "9999")
        self.assertEqual(WINDOWS_EVENT_TYPES[1102], "audit_log_cleared")
        self.assertEqual(set(event.event_type for event in events).issubset(EVENT_TYPES), True)

    def test_windows_xml_and_dtd_rejection(self):
        adapter = WindowsEventsAdapter()
        xml = '<Event><System><EventID>4624</EventID><TimeCreated SystemTime="2026-10-01T10:00:00Z"/><Computer>LAB-WIN</Computer></System><EventData><Data Name="TargetUserName">demo</Data><Data Name="IpAddress">192.0.2.40</Data></EventData></Event>'
        event = adapter.parse_record(xml, 1)
        self.assertEqual(event.event_type, "auth_success")
        self.assertEqual(event.source_ip, "192.0.2.40")
        with self.assertRaises(RecordParseError):
            adapter.parse_record('<!DOCTYPE Event [<!ENTITY x SYSTEM "file:///secret">]><Event/>', 1)
        xml_path = self.write("events.xml", "<Events>\n" + xml.replace("<Event>", "<Event>\n  ").replace("</Event>", "\n</Event>") + "\n</Events>")
        self.assertEqual(len(list(adapter.parse(xml_path))), 1)
        unsafe = self.write("unsafe.xml", '<!DOCTYPE Events [<!ENTITY x SYSTEM "file:///secret">]><Events/>')
        with self.assertRaises(RecordParseError):
            list(adapter.parse(unsafe))

    def test_pcap_metadata_csv_and_json_are_offline(self):
        csv_path = self.write("capture.csv", "frame.time,ip.src,ip.dst,tcp.srcport,tcp.dstport,protocol,packet_count\n2026-10-01T10:00:00Z,192.0.2.50,198.51.100.20,53000,443,tcp,12\n")
        self.assertEqual(self.pipeline.select_adapter(csv_path).name, "pcap_metadata")
        result = self.pipeline.ingest(csv_path)
        event = EventRepository(self.db).list()[0]
        self.assertEqual(result["events_created"], 1)
        self.assertEqual(event["source_type"], "pcap_metadata")
        self.assertEqual(event["destination_port"], 443)
        self.assertEqual(event["packet_count"], 12)
        json_path = self.write("tshark.jsonl", '{"_source":{"layers":{"frame":{"frame.time_epoch":"1790848800","frame.protocols":"eth:ip:tcp"},"ip":{"ip.src":"192.0.2.51","ip.dst":"198.51.100.21"},"tcp":{"tcp.srcport":"50001","tcp.dstport":"443"}}}}\n')
        self.assertEqual(self.pipeline.ingest(json_path)["events_created"], 1)
        self.assertTrue(any(item["source_type"] == "pcap_metadata" for item in EventRepository(self.db).list()))
        self.assertFalse(PcapMetadataAdapter().can_handle(self.write("raw.pcap", b"\xd4\xc3\xb2\xa1")))
        with self.assertRaises(RecordParseError):
            list(PcapMetadataAdapter().parse(self.root / "raw.pcap"))

    def test_occurrence_ids_distinguish_identical_rows_and_repeat_file_skips(self):
        repeated = "Oct 01 10:10:00 host sshd[1]: Failed password for demo from 192.0.2.60 port 22\n"
        first = self.write("auth.log", repeated + repeated)
        imported = self.pipeline.ingest(first)
        self.assertEqual(imported["events_created"], 2)
        events = EventRepository(self.db).list()
        ids = [event["event_id"] for event in events]
        self.assertEqual(len(set(ids)), 2)
        self.assertTrue(all(event_id.startswith("evt_") for event_id in ids))
        self.assertEqual(self.pipeline.ingest(first)["status"], "skipped_duplicate_file")
        self.assertEqual(self.pipeline.ingest(first)["status"], "skipped_duplicate_file")
        copy = self.write("auth-copy.log", repeated + repeated)
        copied = self.pipeline.ingest(copy)
        self.assertEqual(copied["events_duplicate"], 2)
        self.assertEqual(copied["events_created"], 0)
        expected = stable_id("evt", "auth_log", "2026-10-01T10:10:00+00:00", repeated.rstrip("\n"), 0)
        self.assertIn(expected, ids)

    def test_malformed_middle_record_preserves_prior_and_following_valid_records(self):
        path = self.write("mixed.jsonl", '\n'.join([
            '{"timestamp":"2026-10-01T10:00:00Z","event_type":"auth_failure"}',
            '{malformed}',
            '{"timestamp":"2026-10-01T10:00:02Z","event_type":"auth_success"}',
        ]) + '\n')
        result = self.pipeline.ingest(path, chunk_size=1)
        self.assertEqual(result["status"], "completed_with_errors")
        self.assertEqual(result["events_created"], 2)
        self.assertEqual(result["events_invalid"], 1)
        self.assertEqual(len(EventRepository(self.db).list()), 2)

    def test_batch_tracking_counters_and_file_hash(self):
        path = self.write("tracked.jsonl", '{"timestamp":"2026-10-01T00:00:00Z"}\n{bad}\n')
        result = self.pipeline.ingest(path)
        row = IngestBatchRepository(self.db).get(result["batch_id"])
        self.assertEqual(row["status"], "completed_with_errors")
        self.assertEqual(row["events_created"], 1)
        self.assertEqual(row["events_invalid"], 1)
        self.assertEqual(row["parse_error_count"], 1)
        self.assertIn("invalid JSON", row["error_summary"])

    def test_non_utf8_windows_endings_max_line_and_raw_truncation(self):
        auth_line = b"Oct 01 10:00:00 host sshd[1]: Accepted password for al\xffice from 192.0.2.70 port 22\r\n"
        path = self.write("auth.log", auth_line)
        result = self.pipeline.ingest(path)
        self.assertEqual(result["events_created"], 1)
        event = EventRepository(self.db).list()[0]
        self.assertTrue(event["username"].startswith("al"))
        long_line = self.write("too-long.log", "Oct 01 10:00:00 host app: " + "x" * 200 + "\n")
        limited = IngestionPipeline(Database(self.root / "limited.db"), max_line_length=50).ingest(long_line)
        self.assertGreaterEqual(limited["events_invalid"], 1)
        raw_path = self.write("raw.jsonl", json.dumps({"timestamp":"2026-10-01T00:00:00Z", "detail":"x"*300}) + "\n")
        raw_pipeline = IngestionPipeline(Database(self.root / "raw.db"), max_raw_bytes=80)
        self.assertEqual(raw_pipeline.ingest(raw_path)["events_created"], 1)
        raw = EventRepository(raw_pipeline.database).list()[0]
        self.assertTrue(raw["raw_truncated"])

    def test_ip_validation_threshold_no_adapter_and_file_limit(self):
        invalid_ip = self.write("bad-ip.jsonl", '{"timestamp":"2026-10-01T00:00:00Z","source_ip":"999.1.1.1"}\n')
        invalid = self.pipeline.ingest(invalid_ip)
        self.assertEqual(invalid["status"], "failed")
        self.assertEqual(invalid["events_invalid"], 1)
        unsupported = self.write("unknown.bin", b"\x00\x01 random")
        no_adapter = self.pipeline.ingest(unsupported)
        self.assertEqual(no_adapter["status"], "failed")
        too_large = IngestionPipeline(Database(self.root / "large.db"), max_file_bytes=2).ingest(unsupported)
        self.assertEqual(too_large["status"], "failed")


if __name__ == "__main__":
    unittest.main()
