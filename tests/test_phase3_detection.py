import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from database.database import Database
from database.repositories import AlertRepository, EventRepository, IngestBatchRepository, EvidenceLinkRepository
from detection.engine import DetectionEngine, load_config
from models.alert import Alert
from models.event import NormalizedEvent
from models.ids import stable_id


class PhaseThreeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = Database(self.root / "phase3.db")
        self.db.initialize()
        self.batch_id = "phase3-batch"
        IngestBatchRepository(self.db).save({"id": self.batch_id, "source_file": "unit", "file_hash": "h",
            "started_at": "2026-01-01T00:00:00+00:00", "status": "completed"})

    def event(self, n, seconds, *, kind="auth_failure", ip="192.0.2.1", user="alice", host="node"):
        timestamp = (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)).isoformat()
        event = NormalizedEvent(event_id=f"e{n}", timestamp=timestamp, event_type=kind,
            source_ip=ip, username=user, hostname=host, ingest_batch_id=self.batch_id)
        return event

    def persist(self, events):
        EventRepository(self.db).save_many(events)

    def run_engine(self, events=None, config=None):
        if events is not None: self.persist(events)
        return DetectionEngine(self.db, config).run()

    def test_legacy_alert_constructor_and_enrichment(self):
        alert = Alert("module", "source", "LOW", "type", 20, ["x"], "act")
        self.assertEqual(alert.status, "NEW")
        self.assertEqual(alert.id, alert.alert_id)
        self.assertEqual(alert.title, "type")

    def test_eight_failures_one_brute_force_and_extensions_update_same_detection(self):
        events = [self.event(i, i) for i in range(8)]
        result = self.run_engine(events)
        r1 = [d for d in result if d["rule_id"] == "R001"]
        self.assertEqual(len(r1), 1)
        det_id = r1[0]["id"]
        self.assertEqual(len(r1[0]["event_ids"]), 8)
        extended = self.run_engine([self.event(i, i) for i in range(8, 10)])
        r1_again = [d for d in extended if d["rule_id"] == "R001"]
        self.assertEqual(len(r1_again), 1)
        self.assertEqual(r1_again[0]["id"], det_id)
        self.assertEqual(len(AlertRepository(self.db).get(det_id)["evidence_refs"]), 10)
        refs = EvidenceLinkRepository(self.db).references_for("ALERT", det_id)
        self.assertEqual(len(refs), 10)

    def test_r001_supersedes_r002_and_different_ips_not_aggregated(self):
        self.persist([self.event(i, i, ip="192.0.2.10" if i < 4 else "192.0.2.11", user=f"user{i}") for i in range(5)])
        result = DetectionEngine(self.db).run()
        self.assertFalse(any(d["rule_id"] == "R001" for d in result))
        # Four failures from A may trigger its weaker R002 threshold; B's single event is not added.
        ip_a = [d for d in result if d["rule_id"] == "R002" and d["grouping_key"] == "source_ip=192.0.2.10"]
        self.assertEqual(len(ip_a), 1)
        self.assertEqual(len(ip_a[0]["event_ids"]), 4)
        # Same-group stronger rule suppresses the overlapping weak rule.
        fresh = self.root / "supersede.db"
        db = Database(fresh); db.initialize()
        IngestBatchRepository(db).save({"id": self.batch_id, "source_file": "unit", "file_hash": "h", "started_at": "2026-01-01T00:00:00+00:00", "status": "completed"})
        EventRepository(db).save_many([self.event(i, i, user="same") for i in range(8)])
        stronger = DetectionEngine(db).run()
        self.assertTrue(any(d["rule_id"] == "R001" for d in stronger))
        self.assertFalse(any(d["rule_id"] == "R002" for d in stronger))
        with db.session() as c:
            reasons = [r[0] for r in c.execute("SELECT reason FROM suppressed_detections")]
        self.assertIn("superseded_by_R001", reasons)

    def test_r003_correlates_exact_ip_username_and_is_idempotent(self):
        events = [self.event(1, 0), self.event(2, 10), self.event(3, 20, kind="auth_success"),
                  self.event(4, 30, kind="auth_success")]
        result = self.run_engine(events)
        self.assertEqual(len([d for d in result if d["rule_id"] == "R003"]), 1)
        self.assertEqual(len([d for d in DetectionEngine(self.db).run() if d["rule_id"] == "R003"]), 1)
        other = self.root / "other.db"
        db = Database(other); db.initialize()
        IngestBatchRepository(db).save({"id": self.batch_id, "source_file": "unit", "file_hash": "h", "started_at": "2026-01-01T00:00:00+00:00", "status": "completed"})
        EventRepository(db).save(self.event(9, 0, kind="auth_success", ip="198.51.100.8", user="bob"))
        self.assertFalse(any(d["rule_id"] == "R003" for d in DetectionEngine(db).run()))

    def test_failure_window_exact_300_included_301_excluded_and_order_independent(self):
        exactly = [self.event(i, (i - 1) * 75) for i in (1, 2, 3, 4)] + [self.event(5, 300)]
        exact_result = self.run_engine(exactly)
        self.assertTrue(any(d["rule_id"] == "R001" for d in exact_result))
        fresh = self.root / "window.db"
        db = Database(fresh); db.initialize()
        IngestBatchRepository(db).save({"id": self.batch_id, "source_file": "unit", "file_hash": "h", "started_at": "2026-01-01T00:00:00+00:00", "status": "completed"})
        EventRepository(db).save_many([self.event(i, (i - 1) * 75) for i in (1, 2, 3, 4)] + [self.event(5, 301)])
        self.assertFalse(any(d["rule_id"] == "R001" for d in DetectionEngine(db).run()))
        # Identical persisted input order is canonicalized by (timestamp,event_id).
        shuffled = self.root / "shuffle.db"
        db2 = Database(shuffled); db2.initialize()
        IngestBatchRepository(db2).save({"id": self.batch_id, "source_file": "unit", "file_hash": "h", "started_at": "2026-01-01T00:00:00+00:00", "status": "completed"})
        EventRepository(db2).save_many(list(reversed(exactly)))
        left = [(d["id"], sorted(d["event_ids"])) for d in exact_result if d["rule_id"].startswith("R00")]
        right = [(d["id"], sorted(d["event_ids"])) for d in DetectionEngine(db2).run() if d["rule_id"].startswith("R00")]
        self.assertEqual(left, right)

    def test_config_threshold_suppression_cidr_and_audit(self):
        config = json.loads(Path(__file__).parents[1].joinpath("detection/rules.json").read_text())
        config["rules"]["R001"]["threshold"] = 4
        config["suppression"]["trusted_source_ips"] = ["192.0.2.0/24"]
        path = self.root / "rules.json"; path.write_text(json.dumps(config))
        self.persist([self.event(i, i) for i in range(4)])
        self.assertFalse(DetectionEngine(self.db, path).run())
        with self.db.session() as c:
            self.assertGreater(c.execute("SELECT COUNT(*) FROM suppressed_detections WHERE rule_id='R001'").fetchone()[0], 0)
            self.assertEqual(c.execute("SELECT COUNT(*) FROM rule_executions").fetchone()[0], 9)
        config["rules"]["R001"]["threshold"] = 0
        path.write_text(json.dumps(config))
        with self.assertRaises(ValueError): load_config(path)

    def test_trusted_user_suppression_and_rule_event_semantics(self):
        config = json.loads(Path(__file__).parents[1].joinpath("detection/rules.json").read_text())
        config["suppression"]["trusted_users"] = ["alice"]
        path = self.root / "trusted.json"; path.write_text(json.dumps(config))
        self.persist([self.event(i, i) for i in range(5)])
        self.assertFalse(DetectionEngine(self.db, path).run())
        ev = self.event(20, 20, kind="privilege_assigned")
        self.persist([ev])
        # privilege assignment is medium by default, with no speculative technique mapping.
        cfg = json.loads(Path(__file__).parents[1].joinpath("detection/rules.json").read_text())
        cfg["suppression"]["trusted_users"] = []
        path.write_text(json.dumps(cfg))
        found = DetectionEngine(self.db, path).run()
        r010 = next(d for d in found if d["rule_id"] == "R010")
        alert = AlertRepository(self.db).get(r010["id"])
        self.assertEqual(alert["severity"], "MEDIUM")
        self.assertEqual(alert["mitre_techniques"], [])


if __name__ == "__main__":
    unittest.main()
