import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from database.database import Database
from database.repositories import EventRepository, IngestBatchRepository
from models.event import NormalizedEvent
from response.service import ResponseService


class Phase9BPlaybookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = Database(self.root / "soc.db")
        self.db.initialize()
        conf = SimpleNamespace(
            response_approval_ttl_seconds=60,
            response_require_different_approver=True,
            response_protected_ips=(),
            response_protected_hosts=("protected01",),
            response_protected_accounts=("system",),
        )
        self.service = ResponseService(self.db, config=conf)
        IngestBatchRepository(self.db).save({
            "id": "batch",
            "source_file": "fixture",
            "file_hash": "hash",
            "started_at": "2026-04-01T00:00:00Z",
            "status": "completed",
        })
        EventRepository(self.db).save(NormalizedEvent(
            event_id="event-1",
            timestamp="2026-04-01T00:00:00Z",
            hostname="endpoint01",
            username="alice",
            source_ip="8.8.8.8",
            destination_ip="1.1.1.1",
            event_type="auth_failure",
            raw_event={"message": "failed login"},
            ingest_batch_id="batch",
        ))
        with self.db.session() as c:
            c.execute("INSERT INTO incidents(incident_id,created_at,updated_at,status,severity,risk_score,payload) VALUES(?,?,?,?,?,?,?)",
                      ("inc-1", "2026-04-01T00:00:00Z", "2026-04-01T00:00:00Z", "open", "HIGH", 80, "{}"))
            c.execute("INSERT INTO incident_events VALUES(?,?)", ("inc-1", "event-1"))
            c.execute("INSERT INTO alerts(alert_id,timestamp,severity,payload,status) VALUES(?,?,?,?,?)",
                      ("det-1", "2026-04-01T00:00:00Z", "HIGH", json.dumps({"hostname": "endpoint01", "username": "alice", "source_ip": "8.8.8.8"}), "NEW"))
            c.execute("INSERT INTO incident_detections VALUES(?,?)", ("inc-1", "det-1"))

    def test_registry_includes_simulated_playbooks(self):
        playbooks = self.service.list_playbooks()
        self.assertTrue(any(item["id"] == "brute_force_response" for item in playbooks))
        self.assertTrue(any(item["simulation_only"] is True for item in playbooks))

    def test_response_options_build_from_incident_context(self):
        options = self.service.get_response_options("inc-1")
        self.assertTrue(options)
        self.assertIn("brute_force_response", [item["id"] for item in options])
        self.assertTrue(options[0]["availability"] in {"available", "unavailable"})

    def test_start_execution_is_idempotent_and_persists_steps(self):
        first = self.service.start_playbook_execution("inc-1", "brute_force_response", actor="analyst")
        second = self.service.start_playbook_execution("inc-1", "brute_force_response", actor="analyst")
        self.assertEqual(first["execution_id"], second["execution_id"])
        self.assertEqual(first["status"], "awaiting_approval")
        with self.db.read_session() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM response_playbook_executions WHERE incident_id=?", ("inc-1",)).fetchone()[0], 1)
            self.assertGreaterEqual(c.execute("SELECT COUNT(*) FROM response_playbook_steps WHERE execution_id=?", (first["execution_id"],)).fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
