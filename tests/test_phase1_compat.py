"""Phase 1 compatibility and persistence tests (stdlib unittest)."""
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timezone
import sqlite3

from database.database import Database, MIGRATIONS
from database.repositories import (AlertRepository, AnalystRepository, AssetRepository,
    EventRepository, EvidenceLinkRepository, IncidentRepository, IngestBatchRepository, IOCRepository)
from ingestion.adapter import EventAdapter, ParseErrorPolicy
from ingestion.batches import build_batch, finalize_batch
from models import Alert, Analyst, Asset, Incident, IOC, NormalizedEvent, SecurityEvent
from models.ids import make_id
from models.timestamps import to_utc_iso


class PhaseOneCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.db = Database(Path(self.temp_dir.name) / "soc.db")
        self.db.initialize()

    def test_legacy_alert_constructor(self):
        alert = Alert("log_analyzer", "192.0.2.10", "HIGH", "Brute Force", 80,
                      "five failures", "Investigate")
        self.assertEqual(alert.evidence, ["five failures"])
        self.assertTrue(alert.timestamp.endswith("+00:00"))
        self.assertEqual(alert.to_dict()["severity"], "HIGH")

    def test_every_model_round_trips(self):
        alert = Alert("test", "source", "LOW", "test", 10, [], "review")
        incident = Incident("Test incident")
        ioc = IOC("192.0.2.10", "ipv4")
        asset = Asset("host-1")
        analyst = Analyst("analyst1")
        batch = {"id": "batch-models", "source_file": "source", "file_hash": "hash",
                 "started_at": to_utc_iso(0), "status": "COMPLETED"}
        IngestBatchRepository(self.db).save(batch)
        event = SecurityEvent(source="syslog", hostname="host-1", username="alice",
                              source_ip="192.0.2.10", raw_event={"line": 1}, ingest_batch_id=batch["id"])
        repositories = [
            (AlertRepository(self.db), alert.to_dict(), alert.alert_id, "attack_type"),
            (IncidentRepository(self.db), incident.to_dict(), incident.incident_id, "title"),
            (IOCRepository(self.db), ioc.to_dict(), ioc.ioc_id, "value"),
            (AssetRepository(self.db), asset.to_dict(), asset.asset_id, "hostname"),
            (AnalystRepository(self.db), analyst.to_dict(), analyst.user_id, "username"),
        ]
        for repository, payload, identity, key in repositories:
            with self.subTest(repository=type(repository).__name__):
                repository.save(payload)
                self.assertEqual(repository.get(identity)[key], payload[key])
        events = EventRepository(self.db)
        events.save(event)
        self.assertEqual(events.get(event.event_id)["username"], "alice")

    def test_ioc_duplicate_is_one_row(self):
        repository = IOCRepository(self.db)
        first = IOC("example.test", "domain")
        later = IOC("example.test", "domain", last_seen="2026-10-01T00:00:00+00:00")
        repository.save(first.to_dict())
        repository.save(later.to_dict())
        self.assertEqual(repository.count(), 1)

    def test_migrations_are_repeatable_and_connection_pragmas_are_enabled(self):
        self.db.migrate()
        with self.db.session() as connection:
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0], 9)
        self.assertEqual(self.db.current_version(), 9)

    def test_migration_preserves_preexisting_alert_data(self):
        with self.db.session() as connection:
            connection.execute("INSERT INTO alerts(alert_id,timestamp,severity,payload) VALUES(?,?,?,?)",
                               ("legacy-1", "2026-10-01T00:00:00+00:00", "LOW", "{}"))
        self.db.migrate()
        with self.db.session() as connection:
            self.assertEqual(connection.execute("SELECT alert_id FROM alerts WHERE alert_id='legacy-1'").fetchone()[0], "legacy-1")

    def test_phase2_migration_upgrades_legacy_batch_fields(self):
        old_path = Path(self.temp_dir.name) / "pre-v4.db"
        connection = sqlite3.connect(old_path)
        connection.execute("CREATE TABLE schema_version(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        for version in (1, 2, 3):
            connection.executescript("BEGIN;" + MIGRATIONS[version] +
                f"INSERT INTO schema_version(version,applied_at) VALUES({version},'old');COMMIT;")
        connection.execute("INSERT INTO ingest_batches(id,source_file,file_hash,started_at,event_count,status,errors_count,errors_json) VALUES(?,?,?,?,?,?,?,?)",
                           ("old-batch", "old.log", "sha", "2026-01-01T00:00:00+00:00", 5, "COMPLETED", 2, '["bad row"]'))
        connection.commit()
        connection.close()
        upgraded = Database(old_path)
        upgraded.migrate()
        batch = IngestBatchRepository(upgraded).get("old-batch")
        self.assertEqual(batch["status"], "completed")
        self.assertEqual(batch["events_created"], 5)
        self.assertEqual(batch["parse_error_count"], 2)

    def test_event_idempotency_batches_and_evidence_links(self):
        batch = {"id": "batch-events", "source_file": "auth.log", "file_hash": "abc",
                 "started_at": to_utc_iso(0), "status": "COMPLETED"}
        IngestBatchRepository(self.db).save(batch)
        event = SecurityEvent(source_ip="192.0.2.5", ingest_batch_id=batch["id"])
        events = EventRepository(self.db)
        events.save(event)
        events.save(event)
        with self.db.session() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)
        incident = Incident("Correlation")
        IncidentRepository(self.db).save(incident.to_dict())
        links = EvidenceLinkRepository(self.db)
        links.link(incident.incident_id, event.event_id)
        self.assertEqual(links.events_for_incident(incident.incident_id), [event.event_id])
        batch = {"id": make_id("batch", "logs.txt", "hash"), "source_file": "logs.txt",
                 "file_hash": "hash", "started_at": to_utc_iso(0), "status": "COMPLETED",
                 "event_count": 1, "errors_count": 1, "errors": ["line 2 malformed"]}
        batches = IngestBatchRepository(self.db)
        batches.save(batch)
        self.assertTrue(batches.already_ingested("logs.txt", "hash"))

    def test_utc_timestamp_normalization(self):
        self.assertEqual(to_utc_iso(0), "1970-01-01T00:00:00+00:00")
        self.assertEqual(to_utc_iso("2026-10-01T05:30:00+05:30"), "2026-10-01T00:00:00+00:00")
        self.assertEqual(to_utc_iso(datetime(2026, 10, 1, 5, 30, tzinfo=timezone.utc)), "2026-10-01T05:30:00+00:00")
        with self.assertRaises((TypeError, ValueError)):
            to_utc_iso(object())

    def test_same_normalized_event_input_has_same_id(self):
        left = NormalizedEvent(timestamp="2026-10-01T00:00:00Z", source="syslog", raw_event={"b": 2, "a": 1})
        right = NormalizedEvent(timestamp="2026-10-01T00:00:00Z", source="syslog", raw_event={"a": 1, "b": 2})
        self.assertEqual(left.event_id, right.event_id)

    def test_parse_error_policy_and_adapter_contract(self):
        class ExampleAdapter:
            name = "example"
            def can_handle(self, source): return True
            def parse(self, source): return iter(())
        self.assertIsInstance(ExampleAdapter(), EventAdapter)
        errors = ParseErrorPolicy(max_recorded_errors=2)
        for index in range(3): errors.record("bad record", index)
        self.assertEqual(errors.errors_count, 3)
        self.assertEqual(len(errors.errors), 2)
        self.assertEqual(errors.batch_status, "completed_with_errors")
        self.assertEqual(ParseErrorPolicy().max_recorded_errors, 100)

    def test_batch_hash_and_status(self):
        fixture = Path(__file__).parent / "fixtures" / "auth.log"
        first, second = build_batch(fixture), build_batch(fixture)
        self.assertEqual(first["file_hash"], second["file_hash"])
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(finalize_batch(first, 2, 1, ["bad record"])["status"], "completed_with_errors")
        self.assertEqual(finalize_batch(first, 2, 0, [])["status"], "completed")
        self.assertEqual(finalize_batch(first, 0, 0, ["I/O failure"], failed=True)["status"], "failed")

    def test_generic_evidence_refs_and_scanner_scope(self):
        links = EvidenceLinkRepository(self.db)
        links.link_reference("ALERT", "alert-1", "IOC", "ioc-1")
        self.assertEqual(links.references_for("alert", "alert-1"),
                         [{"evidence_type": "IOC", "evidence_id": "ioc-1"}])
        from tools.port_scanner import PortScanner
        with self.assertRaises(PermissionError):
            PortScanner().scan_target("203.0.113.9", ports_to_scan=[])

    def test_deterministic_id(self):
        self.assertEqual(make_id("event", "filehash", 3), make_id("event", "filehash", 3))
        self.assertNotEqual(make_id("event", "filehash", 3), make_id("event", "filehash", 4))


if __name__ == "__main__":
    unittest.main()
