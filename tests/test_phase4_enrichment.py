import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from database.database import Database, MIGRATIONS
from database.repositories import AlertRepository, EventRepository, IngestBatchRepository
from enrichment.extractor import IOCExtractor, normalize_domain, normalize_ip, normalize_url
from enrichment.service import EnrichmentService, MAP_PATH
from models.event import NormalizedEvent


class PhaseFourEnrichmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = Database(self.root / "soc.sqlite")
        self.db.initialize()
        self.batch = "enrichment-test-batch"
        IngestBatchRepository(self.db).save({"id": self.batch, "source_file": "local", "file_hash": "hash",
            "started_at": "2026-01-01T00:00:00+00:00", "status": "completed"})

    def event(self, event_id, timestamp, **kwargs):
        return NormalizedEvent(event_id=event_id, timestamp=timestamp, ingest_batch_id=self.batch, **kwargs)

    def persist(self, *events):
        EventRepository(self.db).save_many(list(events))

    def rows(self, table):
        with self.db.read_session() as c:
            return [dict(r) for r in c.execute(f"SELECT * FROM {table}")]

    def test_dedupe_occurrence_and_reverse_order_event_time(self):
        events = [self.event("a", "2026-01-03T00:00:00Z", source_ip="192.168.1.4"),
                  self.event("b", "2026-01-01T00:00:00Z", source_ip="192.168.1.4"),
                  self.event("c", "2026-01-02T00:00:00Z", source_ip="192.168.1.4")]
        self.persist(*events)
        service = EnrichmentService(self.db)
        one = service.run()
        self.assertEqual(one["iocs_created"], 1)
        self.assertEqual(one["ioc_event_links_created"], 3)
        self.assertEqual(service.run(force=True)["ioc_event_links_created"], 0)
        row = self.rows("iocs")[0]
        self.assertEqual(row["occurrence_count"], 3)
        self.assertEqual(row["first_seen"], "2026-01-01T00:00:00+00:00")
        self.assertEqual(row["last_seen"], "2026-01-03T00:00:00+00:00")
        reverse = self.root / "reverse.sqlite"
        db2 = Database(reverse); db2.initialize()
        IngestBatchRepository(db2).save({"id": self.batch, "source_file": "local", "file_hash": "hash", "started_at": "2026-01-01T00:00:00+00:00", "status": "completed"})
        EventRepository(db2).save_many(list(reversed(events)))
        EnrichmentService(db2).run()
        row2 = db2
        with db2.read_session() as c:
            row2 = dict(c.execute("SELECT * FROM iocs").fetchone())
        self.assertEqual((row["first_seen"], row["last_seen"], row["occurrence_count"]),
                         (row2["first_seen"], row2["last_seen"], row2["occurrence_count"]))

    def test_confidence_structured_wins_and_never_downgrades(self):
        indicator = "203.0.113.18"
        event = self.event("structured", "2026-02-01T00:00:00Z", source_ip=indicator,
                           raw_event={"message": f"connection from {indicator}"})
        result = IOCExtractor().extract(event.to_dict())
        ip = next(i for i in result if i.value == indicator)
        self.assertEqual(ip.confidence, 0.95)
        self.assertEqual(ip.source_field, "source_ip")
        self.persist(event)
        service = EnrichmentService(self.db)
        service.run()
        service.run(force=True)
        row = self.rows("iocs")[0]
        self.assertEqual(row["confidence"], 0.95)

    def test_ip_tags_mapped_ipv6_and_zone_id(self):
        self.assertEqual(normalize_ip("10.2.3.4"), ("ipv4", "10.2.3.4", "private"))
        self.assertEqual(normalize_ip("127.0.0.1")[2], "loopback")
        self.assertEqual(normalize_ip("169.254.1.2")[2], "link_local")
        self.assertEqual(normalize_ip("224.0.0.1")[2], "multicast")
        self.assertEqual(normalize_ip("::ffff:192.0.2.8")[:2], ("ipv4", "192.0.2.8"))
        self.assertEqual(normalize_ip("fe80::1%eth0"), ("ipv6", "fe80::1", "link_local"))

    def test_domain_false_positives_and_real_domains(self):
        for value in ("report.pdf", "config.sys", "evil.exe", "svchost.exe", "10.0.19041", "1.2.3.4.5", "server.local"):
            self.assertIsNone(normalize_domain(value), value)
        extractor = IOCExtractor()
        got = {(i.type, i.value) for i in extractor.extract({"raw_event": "visit example.com and sub.example.org"})}
        self.assertIn(("domain", "example.com"), got)
        self.assertIn(("domain", "sub.example.org"), got)

    def test_url_email_and_defanged_behavior(self):
        self.assertEqual(normalize_url("HTTP://Example.COM:80/CasePath?q=AbC"), "http://example.com/CasePath?q=AbC")
        self.assertEqual(normalize_url("https://EXAMPLE.com:443/a?x=Q"), "https://example.com/a?x=Q")
        extracted = IOCExtractor().extract({"raw_event": "https://Example.com/A?Q=Z contact User.Name@EXAMPLE.COM"})
        pairs = {(i.type, i.value) for i in extracted}
        self.assertIn(("url", "https://example.com/A?Q=Z"), pairs)
        self.assertIn(("email", "User.Name@example.com"), pairs)
        self.assertNotIn(("domain", "example.com"), pairs)
        self.assertNotIn("email", {i.type for i in IOCExtractor().extract({"username": "operator@example.com", "raw_event": {"username": "operator@example.com"}})})
        self.assertNotIn("ipv4", {i.type for i in IOCExtractor().extract({"username": "192.0.2.9", "raw_event": "192.0.2.9"})})
        self.assertFalse(any(i.value == "example.com" for i in IOCExtractor().extract({"raw_event": "example[.]com hxxp://example[.]com"})))

    def test_hash_boundaries_and_structured_field_confidence(self):
        md5, sha1, sha256 = "a" * 32, "b" * 40, "c" * 64
        found = IOCExtractor().extract({"raw_event": f"{md5} {sha1} sha256:{sha256}"})
        types = [i.type for i in found]
        self.assertEqual(types.count("md5"), 1)
        self.assertEqual(types.count("sha1"), 1)
        self.assertEqual(types.count("sha256"), 1)
        self.assertEqual(next(i for i in found if i.type == "sha256").confidence, 0.7)
        structured = IOCExtractor().extract({"file_hash": sha256})
        self.assertEqual(next(i for i in structured if i.type == "sha256").confidence, 0.95)

    def test_path_extraction_is_structured_only_by_default(self):
        raw = IOCExtractor().extract({"raw_event": "noise /var/log/auth.log"})
        self.assertNotIn("file_path", {i.type for i in raw})
        structured = IOCExtractor().extract({"attributes": {"target_filename": "C:\\Temp\\bad.exe"}})
        self.assertIn(("file_path", "C:\\Temp\\bad.exe"), {(i.type, i.value) for i in structured})

    def test_detection_ioc_link_uniqueness_and_phase3_mapping_ownership(self):
        events = [self.event(f"fail{i}", f"2026-03-01T00:00:0{i}Z", event_type="auth_failure", source_ip="198.51.100.2") for i in range(5)]
        self.persist(*events)
        alert = {"alert_id": "det-1", "id": "det-1", "timestamp": events[0].timestamp, "severity": "HIGH",
                 "status": "NEW", "rule_id": "R001", "mitre_techniques": ["T1110"],
                 "evidence_refs": [event.event_id for event in events], "evidence": [event.event_id for event in events]}
        AlertRepository(self.db).save(alert)
        EventRepository(self.db)  # ensure database repositories and target exists
        first = EnrichmentService(self.db).run()
        self.assertEqual(first["detection_links_created"], 1)
        self.assertEqual(EnrichmentService(self.db).run(force=True)["detection_links_created"], 0)
        mappings = self.rows("attack_mappings")
        self.assertEqual(len(mappings), 1)
        self.assertEqual(mappings[0]["baseline_disagreement"], 0)
        self.assertEqual(AlertRepository(self.db).get("det-1"), alert)
        self.assertEqual(len(self.rows("ioc_detection_links")), 1)
        self.assertEqual(EnrichmentService(self.db).run(force=True)["mappings_created"], 0)

    def test_missing_mapping_evidence_warns_and_does_not_crash(self):
        AlertRepository(self.db).save({"alert_id": "missing-det", "timestamp": "2026-01-01T00:00:00Z", "severity": "HIGH",
            "status": "NEW", "rule_id": "R001", "mitre_techniques": ["T1110"], "evidence_refs": ["absent"]})
        result = EnrichmentService(self.db).run()
        self.assertTrue(any("missing evidence" in warning for warning in result["warnings"]))
        self.assertEqual(self.rows("attack_mappings"), [])

    def test_r030_new_mapping_does_not_overwrite_legacy_phase3_mapping(self):
        event = self.event("clear", "2026-03-02T00:00:00Z", event_type="audit_log_cleared", source_type="windows_events", original_event_type="1102")
        self.persist(event)
        phase3 = {"alert_id": "legacy-r030", "timestamp": event.timestamp, "severity": "HIGH", "status": "NEW",
                  "rule_id": "R030", "mitre_techniques": ["T1070.001"], "evidence_refs": [event.event_id]}
        AlertRepository(self.db).save(phase3)
        EnrichmentService(self.db).run()
        self.assertEqual(AlertRepository(self.db).get("legacy-r030"), phase3)
        mapping = self.rows("attack_mappings")[0]
        self.assertEqual(mapping["technique_id"], "T1685.005")
        self.assertEqual(mapping["baseline_disagreement"], 1)
        self.assertEqual(json.loads(mapping["baseline_techniques"]), ["T1070.001"])

    def test_per_event_failure_isolation_long_input_state_force_and_idempotency(self):
        bad = self.event("bad", "2026-04-01T00:00:00Z", source_ip="192.0.2.2")
        good = self.event("good", "2026-04-01T00:00:00Z", raw_event="sha256:" + "a" * 64 + " z" * 1000000)
        self.persist(bad, good)
        with self.db.session() as c:
            c.execute("UPDATE events SET raw='{' WHERE id='bad'")
        start = time.monotonic()
        result = EnrichmentService(self.db).run()
        self.assertLess(time.monotonic() - start, 5)
        self.assertEqual(result["events_processed"], 2)
        self.assertEqual(result["errors"], 1)
        self.assertEqual(self.rows("enrichment_state")[0]["status"], "error")
        count_before = len(self.rows("ioc_events"))
        self.assertEqual(EnrichmentService(self.db).run()["events_processed"], 0)
        forced = EnrichmentService(self.db).run(force=True)
        self.assertEqual(forced["events_processed"], 2)
        self.assertEqual(len(self.rows("ioc_events")), count_before)
        self.assertEqual(self.rows("iocs")[0]["occurrence_count"], 1)

    def test_enrichment_never_mutates_event_or_phase3_detection_rows(self):
        event = self.event("untouched", "2026-04-03T00:00:00Z", source_ip="198.51.100.12")
        self.persist(event)
        alert = {"alert_id": "det-untouched", "timestamp": event.timestamp, "severity": "MEDIUM", "status": "NEW",
                 "rule_id": "R010", "mitre_techniques": [], "evidence_refs": [event.event_id]}
        AlertRepository(self.db).save(alert)
        with self.db.read_session() as c:
            event_before = c.execute("SELECT raw FROM events WHERE id=?", (event.event_id,)).fetchone()[0]
        alert_before = AlertRepository(self.db).get("det-untouched")
        EnrichmentService(self.db).run(force=True)
        with self.db.read_session() as c:
            event_after = c.execute("SELECT raw FROM events WHERE id=?", (event.event_id,)).fetchone()[0]
        self.assertEqual(event_before, event_after)
        self.assertEqual(alert_before, AlertRepository(self.db).get("det-untouched"))

    def test_since_and_dry_run_are_read_only(self):
        self.persist(self.event("old", "2026-04-01T00:00:00Z", source_ip="203.0.113.1"),
                     self.event("new", "2026-04-02T00:00:00Z", source_ip="203.0.113.2"))
        with self.db.read_session() as c:
            before = {t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("iocs", "ioc_events", "enrichment_state", "attack_mappings")}
        preview = EnrichmentService(self.db).run(since="2026-04-01T12:00:00Z", dry_run=True)
        self.assertEqual(preview["events_processed"], 1)
        self.assertEqual(preview["iocs_created"], 1)
        self.assertGreater(preview["ioc_event_links_created"], 0)
        with self.db.read_session() as c:
            after = {t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in before}
        self.assertEqual(before, after)
        applied = EnrichmentService(self.db).run(since="2026-04-01T12:00:00Z")
        self.assertEqual(applied["events_processed"], 1)
        self.assertEqual(EnrichmentService(self.db).run(since="2026-04-02T00:00:00Z")["events_processed"], 0)

    def test_technique_ids_are_from_static_artifact(self):
        mapping = json.loads(MAP_PATH.read_text())
        ids = set(mapping["techniques"])
        for ids_used in ((["T1110"]), (["T1098"]), (["T1136"]), (["T1070.001"]), (["T1543.003"])):
            self.assertTrue(set(ids_used) <= ids)
        self.assertEqual(mapping["attack_version"], "19.2")
        for technique_id, record in mapping["techniques"].items():
            self.assertEqual(record["technique_id"], technique_id)
            self.assertTrue(record["technique_name"])
            self.assertIn("attack_version", record)
            self.assertIn("verification", record)
        from detection.engine import MITRE
        self.assertTrue({tid for rule in MITRE.values() for tid in rule[0]} <= ids)

    def test_migration_six_preserves_ioc_table_and_adds_indexes(self):
        self.assertIn(6, MIGRATIONS)
        with self.db.read_session() as c:
            names = {r["name"] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertTrue({"iocs", "ioc_events", "ioc_detection_links", "attack_mappings", "enrichment_state"} <= names)

    def test_cli_invalid_since_is_nonzero_and_dry_run_does_not_write(self):
        from enrichment.__main__ import main
        event = self.event("cli", "2026-05-01T00:00:00Z", source_ip="203.0.113.90")
        self.persist(event)
        with self.db.read_session() as c:
            before = c.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        preview = main(["--db", str(self.db.path), "--dry-run"])
        self.assertEqual(preview, 0)
        with self.db.read_session() as c:
            after = c.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        self.assertEqual(before, after)
        with self.assertRaises(SystemExit) as error:
            main(["--db", str(self.db.path), "--since", "not-a-timestamp"])
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
