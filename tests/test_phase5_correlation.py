import json
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from correlation.service import CorrelationService
from database.database import Database, MIGRATIONS
from database.repositories import AlertRepository, EventRepository, IngestBatchRepository
from models.event import NormalizedEvent


class PhaseFiveCorrelationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "soc.db"); self.db.initialize()
        self.batch = "batch"
        IngestBatchRepository(self.db).save({"id": self.batch, "source_file": "test", "file_hash": "h",
            "started_at": "2026-01-01T00:00:00Z", "status": "completed"})
        self.base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def add(self, did, seconds, *, ip="192.0.2.1", user="alice", host="host-a", severity="HIGH", kind="auth_failure", rule="R001", evidence=None, extra=None):
        timestamp = (self.base + timedelta(seconds=seconds)).isoformat()
        ev = NormalizedEvent(event_id="event-" + did, timestamp=timestamp, event_type=kind,
            source_ip=ip, username=user, hostname=host, ingest_batch_id=self.batch)
        EventRepository(self.db).save(ev)
        payload = {"alert_id": did, "id": did, "timestamp": timestamp, "severity": severity,
            "status": "NEW", "rule_id": rule, "evidence_refs": evidence or [ev.event_id],
            "mitre_techniques": [], "mitre_tactics": []}
        payload.update(extra or {})
        AlertRepository(self.db).save(payload)
        return payload

    def fetch(self, table):
        with self.db.read_session() as c:
            return [dict(r) for r in c.execute(f"SELECT * FROM {table}")]

    def test_shared_event_correlates_and_no_time_only_match(self):
        shared = NormalizedEvent(event_id="common", timestamp=self.base.isoformat(), event_type="observed",
            source_ip="192.0.2.200", username="neutral", hostname="evidence-host", ingest_batch_id=self.batch)
        EventRepository(self.db).save(shared)
        self.add("det_a", 0, evidence=["common"])
        self.add("det_b", 300, ip="198.51.100.9", user="bob", host="other", evidence=["common"])
        result = CorrelationService(self.db).run()
        self.assertEqual(result["incident_created"], 1)
        self.assertEqual(len(self.fetch("incident_detections")), 2)
        other = Path(self.tmp.name) / "alone.db"; db = Database(other); db.initialize()
        IngestBatchRepository(db).save({"id": self.batch, "source_file": "test", "file_hash": "h", "started_at": "2026-01-01T00:00:00Z", "status": "completed"})
        # Distinct event evidence and distinct keys: timestamps alone do not join.
        self.add("det_c", 0, ip="203.0.113.1", user="c", host="c")
        self.add("det_d", 1, ip="203.0.113.2", user="d", host="d")
        CorrelationService(self.db).run()
        with self.db.read_session() as c:
            assigned = c.execute("SELECT detection_id,incident_id FROM incident_detections WHERE detection_id IN ('det_c','det_d')").fetchall()
        self.assertEqual(len(assigned), 2)  # both HIGH detections get standalone incidents
        self.assertNotEqual(assigned[0]["incident_id"], assigned[1]["incident_id"])

    def test_boundary_and_transitive_chain(self):
        self.add("det_a", 0, ip="198.51.100.1", user="u", host="a")
        self.add("det_b", 300, ip="198.51.100.1", user="v", host="b")
        self.add("det_c", 550, ip="198.51.100.1", user="w", host="c")
        stats = CorrelationService(self.db).run()
        self.assertEqual(stats["incident_created"], 1)
        self.assertEqual(len(self.fetch("incident_detections")), 3)
        # 301 seconds alone is outside the window.
        db2 = Database(Path(self.tmp.name) / "outside.db"); db2.initialize()
        IngestBatchRepository(db2).save({"id": self.batch, "source_file": "test", "file_hash": "h", "started_at": "2026-01-01T00:00:00Z", "status": "completed"})
        for did, sec in (("det_x",0),("det_y",301)):
            ts=(self.base+timedelta(seconds=sec)).isoformat(); ev=NormalizedEvent(event_id="ev"+did,timestamp=ts,event_type="x",source_ip="192.0.2.99",username=did,hostname=did,ingest_batch_id=self.batch)
            EventRepository(db2).save(ev); AlertRepository(db2).save({"alert_id":did,"timestamp":ts,"severity":"LOW","rule_id":"R010","evidence_refs":[ev.event_id]})
        CorrelationService(db2).run()
        with db2.read_session() as c: self.assertEqual(c.execute("SELECT COUNT(*) FROM incident_detections").fetchone()[0],0)

    def test_idempotence_merge_stability_risk_breakdown_and_analyst_status(self):
        self.add("det_a", 0, ip="192.0.2.1", user="alice", host="host-a", severity="HIGH")
        self.add("det_b", 10, ip="192.0.2.2", user="bob", host="host-b", severity="MEDIUM")
        service = CorrelationService(self.db)
        service.run()
        with self.db.session() as c:
            incident_id = c.execute("SELECT incident_id FROM incidents").fetchone()[0]
            c.execute("UPDATE incidents SET status='TRIAGED' WHERE incident_id=?", (incident_id,))
            p = json.loads(c.execute("SELECT payload FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()[0]); p["status"]="TRIAGED"
            c.execute("UPDATE incidents SET payload=? WHERE incident_id=?", (json.dumps(p), incident_id))
        before = (len(self.fetch("incidents")), len(self.fetch("correlation_edges")), len(self.fetch("incident_detections")))
        service.run()
        after = (len(self.fetch("incidents")), len(self.fetch("correlation_edges")), len(self.fetch("incident_detections")))
        self.assertEqual(before, after)
        p = json.loads(self.fetch("incidents")[0]["payload"])
        self.assertEqual(p["status"], "TRIAGED")
        self.assertEqual(sum(x["points"] for x in p["risk_breakdown"]), p["risk_score"])
        self.assertEqual(p["risk_score"], 70)
        self.assertEqual(self.fetch("correlation_executions")[0]["config_hash"],service.config_hash)

    def test_nat_suppression_and_migration_is_repeatable(self):
        for i in range(25):
            self.add(f"det_{i:03}", i, ip="203.0.113.7", user=f"u{i}", host=f"h{i}")
        result=CorrelationService(self.db).run()
        self.assertGreater(result["suppressed_count"],0)
        with self.db.read_session() as c:
            sizes = [r[0] for r in c.execute("SELECT COUNT(*) FROM incident_detections GROUP BY incident_id")]
            self.assertTrue(all(size == 1 for size in sizes))
        self.db.migrate(); self.assertEqual(self.db.current_version(),9)
        self.assertIn(7,MIGRATIONS)

    def test_shared_ioc_and_private_ioc_exclusion(self):
        from database.repositories import IOCRepository
        self.add("det_i1", 0, ip="198.51.100.1", user="a", host="a", severity="LOW")
        self.add("det_i2", 5, ip="198.51.100.2", user="b", host="b", severity="LOW")
        self.add("det_p1", 10, ip="198.51.100.3", user="c", host="c", severity="LOW")
        self.add("det_p2", 15, ip="198.51.100.4", user="d", host="d", severity="LOW")
        repo=IOCRepository(self.db)
        repo.save({"ioc_id":"ioc-public","value":"example.test","type":"domain","classification":None})
        repo.save({"ioc_id":"ioc-private","value":"192.168.1.1","type":"ipv4","classification":"private"})
        with self.db.session() as c:
            for did,ioc in (("det_i1","ioc-public"),("det_i2","ioc-public"),("det_p1","ioc-private"),("det_p2","ioc-private")):
                c.execute("INSERT INTO ioc_detection_links VALUES(?,?,?)",(ioc,did,"observed_in"))
        result=CorrelationService(self.db).run()
        self.assertGreaterEqual(result["suppressed_count"],1)
        with self.db.read_session() as c:
            public=c.execute("SELECT COUNT(DISTINCT incident_id) FROM incident_detections WHERE detection_id IN ('det_i1','det_i2')").fetchone()[0]
            private=c.execute("SELECT COUNT(DISTINCT incident_id) FROM incident_detections WHERE detection_id IN ('det_p1','det_p2')").fetchone()[0]
        self.assertEqual(public,1)
        self.assertEqual(private,0)  # LOW standalone detections are not incidents

    def test_ioc_candidate_edge_cap_is_audited(self):
        from database.repositories import IOCRepository
        for i in range(3): self.add(f"det_cap{i}",i,ip=f"192.0.2.{i+1}",user=f"u{i}",host=f"h{i}",severity="LOW")
        IOCRepository(self.db).save({"ioc_id":"ioc-cap","value":"cap.example","type":"domain"})
        with self.db.session() as c:
            for i in range(3): c.execute("INSERT INTO ioc_detection_links VALUES(?,?,?)",("ioc-cap",f"det_cap{i}","observed_in"))
        result=CorrelationService(self.db,{"max_ioc_candidate_edges":1}).run()
        self.assertGreaterEqual(result["suppressed_count"],1)
        self.assertIn("candidate_edge_cap",{r["reason"] for r in self.fetch("correlation_suppressions")})

    def test_merge_keeps_loser_and_rebuilds_membership(self):
        from database.repositories import IOCRepository
        for shared_id in ("cluster-a-evidence", "cluster-b-evidence"):
            EventRepository(self.db).save(NormalizedEvent(event_id=shared_id, timestamp=self.base.isoformat(),
                event_type="x", source_ip=shared_id, username=shared_id, hostname=shared_id, ingest_batch_id=self.batch))
        self.add("det_a", 0, ip="192.0.2.1", user="a", host="cluster-a", evidence=["cluster-a-evidence"])
        self.add("det_b", 1, ip="192.0.2.2", user="b", host="cluster-a", evidence=["cluster-a-evidence"])
        self.add("det_d", 2, ip="192.0.2.3", user="d", host="cluster-b", evidence=["cluster-b-evidence"])
        self.add("det_e", 3, ip="192.0.2.4", user="e", host="cluster-b", evidence=["cluster-b-evidence"])
        IOCRepository(self.db).save({"ioc_id":"ioc-a","value":"198.51.100.40","type":"ipv4"})
        IOCRepository(self.db).save({"ioc_id":"ioc-b","value":"198.51.100.41","type":"ipv4"})
        with self.db.session() as c:
            c.execute("INSERT INTO ioc_detection_links VALUES('ioc-a','det_a','observed_in')")
            c.execute("INSERT INTO ioc_detection_links VALUES('ioc-b','det_d','observed_in')")
            for mapping_id,did,tech in (("map-a","det_a","T1001"),("map-b","det_d","T1002")):
                c.execute("INSERT INTO attack_mappings(id,detection_id,technique_id,technique_name,tactic_ids,attack_version,mapping_source,confidence,evidence_ids) VALUES(?,?,?,?,?,?,?,?,?)",
                    (mapping_id,did,tech,"test","[]","test","test",0.9,"[]"))
        CorrelationService(self.db).run()
        with self.db.read_session() as c: initial={r["detection_id"]:r["incident_id"] for r in c.execute("SELECT * FROM incident_detections")}
        self.assertNotEqual(initial["det_a"],initial["det_d"])
        bridge=self.add("det_c", 2, ip="192.0.2.5", user="c", host="bridge", evidence=["cluster-a-evidence","cluster-b-evidence"])
        CorrelationService(self.db).run()
        with self.db.read_session() as c:
            rows=[dict(r) for r in c.execute("SELECT incident_id,status,payload FROM incidents")]
            active=c.execute("SELECT COUNT(DISTINCT incident_id) FROM incident_detections").fetchone()[0]
            history=c.execute("SELECT COUNT(*) FROM incident_merge_history").fetchone()[0]
        anchor_id=next(r["incident_id"] for r in rows if "det_a" in json.loads(r["payload"]).get("detection_ids",[]))
        loser=next(r for r in rows if r["incident_id"] != anchor_id)
        self.assertEqual(active,1)
        self.assertEqual(loser["status"],"merged")
        self.assertEqual(json.loads(loser["payload"])["merged_into"],anchor_id)
        self.assertGreaterEqual(history,1)
        with self.db.read_session() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM incident_events WHERE incident_id=?",(anchor_id,)).fetchone()[0],2)
            self.assertEqual(c.execute("SELECT COUNT(*) FROM incident_iocs WHERE incident_id=?",(anchor_id,)).fetchone()[0],2)
            self.assertEqual(c.execute("SELECT COUNT(*) FROM incident_attack_mappings WHERE incident_id=?",(anchor_id,)).fetchone()[0],2)

    def test_since_is_strict_and_1000_detections_bounded(self):
        self.add("det_since",0,ip="192.0.2.1",user="x",host="x",severity="LOW")
        exact=(self.base+timedelta(seconds=1)).isoformat()
        self.add("det_since2",1,ip="192.0.2.1",user="y",host="y",severity="LOW")
        CorrelationService(self.db).run()  # establish the current rule/config snapshot
        first=CorrelationService(self.db).run(since=exact)
        self.assertEqual(first["candidate_count"],0)
        self.add("det_since3",2,ip="192.0.2.1",user="z",host="z",severity="LOW")
        later=CorrelationService(self.db).run(since=self.base.isoformat())
        self.assertGreater(later["candidate_count"],0)
        bulk=Database(Path(self.tmp.name)/"bulk.db"); bulk.initialize()
        IngestBatchRepository(bulk).save({"id":self.batch,"source_file":"test","file_hash":"h","started_at":self.base.isoformat(),"status":"completed"})
        events=[]
        alerts=[]
        for i in range(1000):
            ts=(self.base+timedelta(seconds=i)).isoformat(); did=f"det_bulk_{i:04}"
            ev=NormalizedEvent(event_id=f"bulk_e_{i:04}",timestamp=ts,event_type="event",source_ip=f"198.51.100.{i%250+1}",username=f"user{i}",hostname=f"host{i}",ingest_batch_id=self.batch)
            events.append(ev)
            alerts.append({"alert_id":did,"timestamp":ts,"severity":"LOW","status":"NEW","rule_id":"R010","evidence_refs":[ev.event_id]})
        EventRepository(bulk).save_many(events)
        for alert in alerts: AlertRepository(bulk).save(alert)
        start=time.monotonic(); result=CorrelationService(bulk).run(); elapsed=time.monotonic()-start
        self.assertLess(elapsed,15.0)
        self.assertEqual(result["error_count"],0)

    def test_max_incident_span_limits_transitive_component(self):
        cfg={"window_seconds":300,"max_incident_span_seconds":400}
        for did,sec in (("det_s1",0),("det_s2",250),("det_s3",500)):
            self.add(did,sec,ip="198.51.100.9",user=did,host=did)
        CorrelationService(self.db,cfg).run()
        with self.db.read_session() as c:
            sizes=sorted(r[0] for r in c.execute("SELECT COUNT(*) FROM incident_detections GROUP BY incident_id"))
        self.assertEqual(sizes,[1,2])

    def test_c005_needs_host_and_shared_event(self):
        self.add("det_h1",0,host="same-host",ip="192.0.2.1",user="a")
        self.add("det_h2",1,host="same-host",ip="192.0.2.2",user="b")
        result=CorrelationService(self.db).run()
        self.assertEqual(result["edge_count"],0)
        self.assertEqual(len(self.fetch("correlation_edges")),0)
        self.assertNotEqual(self.fetch("incidents")[0]["incident_id"], self.fetch("incidents")[1]["incident_id"])

    def test_confidence_primary_fields_and_stable_anchor(self):
        EventRepository(self.db).save(NormalizedEvent(event_id="shared-neutral",timestamp=self.base.isoformat(),
            event_type="neutral",ingest_batch_id=self.batch))
        for did,sec,host,user,ip in (("det_p1",0,"host-a","alice","198.51.100.1"),
            ("det_p2",1,"host-a","bob","198.51.100.2"),("det_p3",2,"host-b","bob","198.51.100.2")):
            own="event-"+did
            self.add(did,sec,host=host,user=user,ip=ip,evidence=["shared-neutral",own],severity="MEDIUM")
        CorrelationService(self.db).run()
        payload=json.loads(self.fetch("incidents")[0]["payload"])
        self.assertEqual(payload["primary_host"],"host-a")
        self.assertEqual(payload["primary_user"],"bob")
        self.assertEqual(payload["primary_src_ip"],"198.51.100.2")
        self.assertEqual(payload["confidence"],"HIGH")
        self.assertEqual(payload["incident_id"],"inc_"+__import__("hashlib").sha256(b"det_p1").hexdigest()[:16])
        before_id=payload["incident_id"]
        self.add("det_p4",3,ip="198.51.100.4",user="new-user",host="new-host",severity="MEDIUM",evidence=["shared-neutral","event-det_p4"])
        CorrelationService(self.db).run()
        payload=json.loads(self.fetch("incidents")[0]["payload"])
        self.assertEqual(payload["incident_id"],before_id)

    def test_risk_modifiers_and_resolved_reopen(self):
        EventRepository(self.db).save(NormalizedEvent(event_id="risk-common",timestamp=self.base.isoformat(),
            event_type="context",ingest_batch_id=self.batch))
        self.add("det_fail",0,kind="auth_failure",severity="HIGH",evidence=["risk-common","event-det_fail"],extra={"mitre_techniques":["T1"],"mitre_tactics":["initial"]})
        self.add("det_success",10,kind="auth_success",severity="HIGH",evidence=["risk-common","event-det_success"],extra={"privileged_account":True,"mitre_techniques":["T2","T3","T4","T5"],"mitre_tactics":["initial","exec","persist"]})
        CorrelationService(self.db).run()
        incident=self.fetch("incidents")[0]
        p=json.loads(incident["payload"])
        self.assertEqual(p["risk_score"],100)
        self.assertEqual(p["risk_level"],"CRITICAL")
        self.assertEqual(sum(x["points"] for x in p["risk_breakdown"]),100)
        self.assertIn("successful_login_after_failures",{x["factor"] for x in p["risk_breakdown"]})
        with self.db.session() as c:
            p["status"]="RESOLVED"; p["resolved_at"]="2026-01-01T01:00:00Z"
            c.execute("UPDATE incidents SET status='RESOLVED',payload=? WHERE incident_id=?",(json.dumps(p),incident["incident_id"]))
        self.add("det_followup",20,kind="auth_success",severity="HIGH",evidence=["risk-common","event-det_followup"])
        CorrelationService(self.db).run()
        reopened=json.loads(next(r["payload"] for r in self.fetch("incidents") if r["incident_id"]==incident["incident_id"]))
        self.assertGreaterEqual(reopened["risk_score"],p["risk_score"])
        self.assertEqual(reopened["status"],"open")
        self.assertEqual(reopened["status_history"][-1]["to"],"open")

    def test_late_arrival_and_shuffled_order_converge(self):
        def build(path, order):
            db=Database(path); db.initialize()
            IngestBatchRepository(db).save({"id":self.batch,"source_file":"same","file_hash":"h","started_at":self.base.isoformat(),"status":"completed"})
            EventRepository(db).save(NormalizedEvent(event_id="shared-late",timestamp=self.base.isoformat(),event_type="evidence",ingest_batch_id=self.batch))
            for did,sec in order:
                ts=(self.base+timedelta(seconds=sec)).isoformat(); eid="event-"+did
                ev=NormalizedEvent(event_id=eid,timestamp=ts,event_type="auth_failure",source_ip="192.0.2."+str(sec+1),username=did,hostname=did,ingest_batch_id=self.batch)
                EventRepository(db).save(ev)
                AlertRepository(db).save({"alert_id":did,"timestamp":ts,"severity":"MEDIUM","rule_id":"R001","evidence_refs":["shared-late",eid]})
                CorrelationService(db).run()
            with db.read_session() as c:
                return sorted(tuple(r) for r in c.execute("SELECT incident_id,detection_id FROM incident_detections"))
        in_order=build(Path(self.tmp.name)/"ordered.db",[("det_l1",0),("det_l2",100),("det_l3",200)])
        late=build(Path(self.tmp.name)/"late.db",[("det_l1",0),("det_l3",200),("det_l2",100)])
        self.assertEqual(in_order,late)

    def test_title_sanitization_and_raw_log_exclusion(self):
        raw="\x1b[31mSECRET RAW LOG\x1b[0m"
        self.add("det_safe",0,host="host\x1b[2J\nname",extra={"raw":raw,"title":raw})
        CorrelationService(self.db).run()
        payload=json.loads(self.fetch("incidents")[0]["payload"])
        self.assertNotIn("\x1b",payload["title"])
        self.assertNotIn("SECRET RAW LOG",payload["title"]+payload["description"])
        self.assertLessEqual(len(payload["title"]),180)

    def test_malformed_detection_is_isolated_and_audited(self):
        self.add("det_good",0,severity="HIGH")
        with self.db.session() as c:
            c.execute("INSERT INTO alerts(alert_id,timestamp,severity,payload,status) VALUES(?,?,?,?,?)",
                ("det_bad",self.base.isoformat(),"HIGH","{","NEW"))
        result=CorrelationService(self.db).run()
        self.assertEqual(result["error_count"],1)
        self.assertEqual(len(self.fetch("incident_detections")),1)
        self.assertEqual(self.fetch("correlation_executions")[0]["status"],"completed_with_errors")

    def test_migration_from_version_six_preserves_alert(self):
        from unittest.mock import patch
        legacy=Database(Path(self.tmp.name)/"v6.db")
        with patch("database.database.MIGRATIONS",{v:sql for v,sql in MIGRATIONS.items() if v<=6}):
            legacy.initialize()
        AlertRepository(legacy).save({"alert_id":"det_legacy","timestamp":self.base.isoformat(),"severity":"HIGH","rule_id":"R010"})
        legacy.migrate(); legacy.migrate()
        self.assertEqual(legacy.current_version(),9)
        self.assertEqual(AlertRepository(legacy).get("det_legacy")["severity"],"HIGH")

    def test_cli_empty_and_unknown_are_clean(self):
        from correlation.__main__ import main
        self.assertEqual(main(["--db", str(Path(self.tmp.name)/"empty.db"), "incidents"]),0)
        self.assertEqual(main(["--db", str(self.db.path), "show", "missing"]),0)


if __name__ == "__main__": unittest.main()
