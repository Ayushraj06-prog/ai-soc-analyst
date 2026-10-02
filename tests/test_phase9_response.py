import ast
import hashlib
import importlib.util
import io
import json
import os
import socket
import subprocess
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from contextlib import redirect_stdout

from database.database import Database, MIGRATIONS
from database.repositories import EventRepository, IngestBatchRepository
from models.event import NormalizedEvent
from response.executors import EndpointExecutor, FirewallExecutor, IdentityExecutor, RealExecutionNotImplemented
from response.service import ResponseConflict, ResponseForbidden, ResponseService
from response.targets import canonical_target


class MutableClock:
    def __init__(self): self.value=datetime(2026,4,1,tzinfo=timezone.utc)
    def __call__(self): return self.value
    def advance(self,seconds): self.value+=timedelta(seconds=seconds)


class ResponsePhase9Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.db=Database(self.root/"soc.db");self.db.initialize()
        self.clock=MutableClock()
        self.config=SimpleNamespace(response_approval_ttl_seconds=60,response_require_different_approver=True,
            response_protected_ips=(),response_protected_hosts=("protected01",),response_protected_accounts=("system",))
        self.service=ResponseService(self.db,clock=self.clock,config=self.config)
        IngestBatchRepository(self.db).save({"id":"batch","source_file":"fixture","file_hash":"hash","started_at":"2026-04-01T00:00:00Z","status":"completed"})
        EventRepository(self.db).save(NormalizedEvent(event_id="event-1",timestamp="2026-04-01T00:00:00Z",hostname="endpoint01",username="alice",source_ip="8.8.8.8",destination_ip="1.1.1.1",event_type="auth_failure",raw_event={"message":"untrusted"},ingest_batch_id="batch"))
        with self.db.session() as c:
            c.execute("INSERT INTO incidents(incident_id,created_at,updated_at,status,severity,risk_score,payload) VALUES(?,?,?,?,?,?,?)",("inc-1","2026-04-01T00:00:00Z","2026-04-01T00:00:00Z","open","HIGH",80,"{}"))
            c.execute("INSERT INTO incident_events VALUES(?,?)",("inc-1","event-1"))
            c.execute("INSERT INTO alerts(alert_id,timestamp,severity,payload,status) VALUES(?,?,?,?,?)",("det-1","2026-04-01T00:00:00Z","HIGH",json.dumps({"hostname":"endpoint01","username":"alice","source_ip":"8.8.8.8"}),"NEW"))
            c.execute("INSERT INTO incident_detections VALUES(?,?)",("inc-1","det-1"))
            c.execute("INSERT INTO iocs(ioc_id,value,type,first_seen,last_seen,payload) VALUES(?,?,?,?,?,?)",("ioc-1","example.com","domain","2026-04-01T00:00:00Z","2026-04-01T00:00:00Z","{}"))
            c.execute("INSERT INTO incident_iocs VALUES(?,?)",("inc-1","ioc-1"))

    def proposal(self,action_type="simulate_block_ip",target="8.8.8.8",target_type="ip",**kwargs):
        return self.service.propose("inc-1",action_type,target=target,target_type=target_type,actor="requester",**kwargs)

    def approved(self,action=None):
        action=action or self.proposal()
        return self.service.approve(action["action_id"],expected_status="pending",actor="approver")

    def test_migration_fresh_and_twice_and_constraints(self):
        self.assertEqual(self.db.current_version(),9)
        self.db.migrate();self.db.migrate()
        with self.db.session() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM schema_version WHERE version=9").fetchone()[0],1)
            with self.assertRaises(Exception):
                c.execute("INSERT INTO response_actions(action_id,incident_id,action_type,parameters_json,policy_rule_id,policy_version,approval_state,execution_state,verification_state,execution_mode,approval_binding_hash,requested_by,created_at,updated_at,revision) VALUES('bad','inc-1','simulate_block_ip','{}','RSP001','1','not_required','not_started','not_verified','real','x','t','x','x',1)")
            with self.assertRaises(Exception): c.execute("INSERT INTO response_actions(action_id,incident_id,action_type,parameters_json,policy_rule_id,policy_version,approval_state,execution_state,verification_state,execution_mode,approval_binding_hash,requested_by,created_at,updated_at,revision) VALUES('bad2','inc-1','simulate_block_ip','{}','RSP001','1','bogus','not_started','not_verified','simulation','x','t','x','x',1)")
        action=self.proposal()
        with self.db.session() as c:
            for column in ("approval_state","execution_state","verification_state"):
                with self.subTest(column=column),self.assertRaises(Exception):c.execute(f"UPDATE response_actions SET {column}='invalid' WHERE action_id=?",(action["action_id"],))
            with self.assertRaises(Exception):c.execute("INSERT INTO execution_attempts(attempt_id,action_id,attempt_number,execution_mode,started_at,status) VALUES('bad-attempt',?,1,'real','now','simulated')",(action["action_id"],))

    def test_migration_from_version8_preserves_data(self):
        path=self.root/"version8.db"
        c=__import__("sqlite3").connect(path)
        try:
            c.execute("CREATE TABLE schema_version(version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL)")
            for version in range(1,9):
                c.executescript("BEGIN;"+MIGRATIONS[version]+f"\nINSERT INTO schema_version VALUES({version},'fixture'); COMMIT;")
            c.execute("INSERT INTO incidents VALUES('legacy','now','now','open','HIGH',7,'{}')")
            c.execute("INSERT INTO alerts VALUES('alert-legacy','now','HIGH','{}','NEW')")
            c.execute("INSERT INTO iocs(ioc_id,value,type,first_seen,last_seen,payload) VALUES('ioc-legacy','example.com','domain','now','now','{}')")
            c.execute("INSERT INTO audit_log(timestamp,actor,action,entity_type,entity_id,details) VALUES('now','old','old.action','incident','legacy','{}')")
            c.execute("INSERT INTO ingest_batches(id,source_file,file_hash,started_at,event_count,status) VALUES('batch-legacy','old.log','hash','now',1,'completed')")
            c.execute("INSERT INTO events(id,timestamp,event_type,raw,ingest_batch_id) VALUES('event-legacy','now','auth','{}','batch-legacy')")
            c.commit()
        finally:c.close()
        db=Database(path);db.migrate();db.migrate()
        with db.read_session() as c:
            self.assertEqual(c.execute("SELECT payload FROM incidents WHERE incident_id='legacy'").fetchone()[0],"{}")
            self.assertEqual(c.execute("SELECT MAX(version) FROM schema_version").fetchone()[0],9)
            for table,key,value in (("alerts","alert_id","alert-legacy"),("iocs","ioc_id","ioc-legacy"),("audit_log","entity_id","legacy"),("events","id","event-legacy")):
                self.assertEqual(c.execute(f"SELECT COUNT(*) FROM {table} WHERE {key}=?",(value,)).fetchone()[0],1)

    def test_recommend_is_deterministic_and_idempotent(self):
        first=self.service.recommend("inc-1",actor="requester")
        second=self.service.recommend("inc-1",actor="requester")
        self.assertEqual([x["action_id"] for x in first],[x["action_id"] for x in second])
        self.assertEqual(len(first),2)
        with self.db.read_session() as c:self.assertEqual(c.execute("SELECT COUNT(*) FROM response_actions").fetchone()[0],2)

    def test_approval_execution_idempotency_rollback_attempt_two(self):
        action=self.approved()
        first=self.service.execute(action["action_id"],expected_status="not_started",actor="approver")
        again=self.service.execute(action["action_id"],expected_status="not_started",actor="approver")
        self.assertEqual(first["result"],again["result"])
        self.assertEqual(first["execution_mode"],"simulation")
        self.service.rollback(action["action_id"],expected_status="simulated",actor="approver")
        self.service.rollback(action["action_id"],expected_status="simulated",actor="approver")
        self.service.execute(action["action_id"],expected_status="rolled_back",actor="approver")
        with self.db.read_session() as c:
            self.assertEqual([r[0] for r in c.execute("SELECT attempt_number FROM execution_attempts ORDER BY attempt_number")],[1,2])

    def test_action_identity_uses_canonical_mapped_ip(self):
        a=self.proposal(target="::ffff:8.8.8.8")
        b=self.proposal(target="8.8.8.8")
        self.assertEqual(a["action_id"],b["action_id"])

    def test_environment_cannot_enable_real_mode_and_executor_failure_is_recorded(self):
        action=self.approved()
        with patch.dict(os.environ,{"SOC_RESPONSE_EXECUTION_MODE":"real"}),patch("response.service.SimulationExecutor.execute",side_effect=RuntimeError("simulated failure")):
            with self.assertRaises(RuntimeError):self.service.execute(action["action_id"],expected_status="not_started",actor="approver")
        current=self.service.get(action["action_id"])
        self.assertEqual(current["execution_mode"],"simulation")
        self.assertEqual(current["execution_state"],"failed")
        self.assertEqual(current["verification_state"],"failed")

    def test_all_real_executor_stubs_raise_unconditionally(self):
        for cls in (FirewallExecutor,IdentityExecutor,EndpointExecutor):
            with self.assertRaises(RealExecutionNotImplemented): cls().execute("x")

    def test_target_validation_and_evidence_boundary(self):
        self.assertEqual(canonical_target("::ffff:8.8.8.8","ip"),"8.8.8.8")
        self.assertEqual(canonical_target("EXAMPLE.COM","domain"),"example.com")
        for value in ("127.0.0.1","169.254.1.2","224.0.0.1","0.0.0.0","255.255.255.255","fe80::1%eth0","2001:db8::1","8.8.8.8\u202e"):
            with self.subTest(value=value),self.assertRaises(ValueError): canonical_target(value,"ip")
        for value,kind in (("bad host!","host"),("bad\\","account"),("bad\x00name","account")):
            with self.subTest(value=value),self.assertRaises(ValueError): canonical_target(value,kind)
        with self.assertRaises(ResponseForbidden): self.service.propose("inc-1","simulate_block_ip",target="9.9.9.9",target_type="ip",actor="requester")

    def test_protected_target_blocked_before_execution(self):
        self.config.response_protected_ips=("8.8.8.8/32",)
        action=self.proposal()
        self.assertEqual(action["execution_state"],"blocked_by_policy")
        self.assertIn("protected",action["result"]["blocked_reason"])
        self.assertTrue(self.service.get(action["action_id"]))

    def test_private_ip_needs_justification_and_target_is_canonical(self):
        EventRepository(self.db).save(NormalizedEvent(event_id="event-private",timestamp="2026-04-01T00:00:00Z",source_ip="10.2.3.4",raw_event={},ingest_batch_id="batch"))
        with self.db.session() as c:c.execute("INSERT INTO incident_events VALUES(?,?)",("inc-1","event-private"))
        blocked=self.service.propose("inc-1","simulate_block_ip",target="10.2.3.4",target_type="ip",actor="requester")
        self.assertEqual(blocked["execution_state"],"blocked_by_policy")
        allowed=self.service.propose("inc-1","simulate_block_ip",target="::ffff:10.2.3.4",target_type="ip",parameters={"policy_justification":"approved containment test"},actor="requester")
        self.assertEqual(allowed["target"],"10.2.3.4")
        self.assertEqual(allowed["execution_state"],"not_started")

    def test_approval_binding_mismatch_is_audited_and_refused(self):
        action=self.approved()
        with self.db.session() as c:
            c.execute("DROP TRIGGER trg_response_evidence_update")
            c.execute("UPDATE response_action_evidence SET evidence_id='ioc-1' WHERE action_id=? AND evidence_type='EVENT'",(action["action_id"],))
        with self.assertRaises(ResponseForbidden):self.service.execute(action["action_id"],expected_status="not_started",actor="approver")
        with self.db.read_session() as c:
            self.assertEqual(c.execute("SELECT execution_state FROM response_actions WHERE action_id=?",(action["action_id"],)).fetchone()[0],"not_started")
            self.assertEqual(c.execute("SELECT COUNT(*) FROM audit_log WHERE action='response.binding_mismatch'").fetchone()[0],1)

    def test_target_and_policy_binding_mismatches_are_refused(self):
        for field,value in (("target","1.1.1.1"),("policy_version","tampered")):
            with self.subTest(field=field):
                action=self.approved(self.proposal(parameters={"policy_justification":field}))
                with self.db.session() as c:
                    c.execute("DROP TRIGGER trg_response_action_immutable")
                    c.execute(f"UPDATE response_actions SET {field}=? WHERE action_id=?",(value,action["action_id"]))
                    c.execute("CREATE TRIGGER trg_response_action_immutable BEFORE UPDATE OF incident_id,action_type,target,target_type,parameters_json,policy_rule_id,policy_version,playbook_id,playbook_version,execution_mode,approval_binding_hash,revision,supersedes,requested_by,created_at,metadata_json ON response_actions BEGIN SELECT RAISE(ABORT,'response proposal fields are immutable; create a revision'); END")
                with self.assertRaises(ResponseForbidden):self.service.execute(action["action_id"],expected_status="not_started",actor="approver")

    def test_proposal_fields_and_evidence_are_immutable(self):
        action=self.proposal()
        with self.db.session() as c:
            with self.assertRaises(Exception):c.execute("UPDATE response_actions SET target='9.9.9.9' WHERE action_id=?",(action["action_id"],))
            with self.assertRaises(Exception):c.execute("DELETE FROM response_action_evidence WHERE action_id=?",(action["action_id"],))
            with self.assertRaises(Exception):c.execute("DELETE FROM response_actions WHERE action_id=?",(action["action_id"],))

    def test_approval_expiry_and_requester_separation(self):
        action=self.proposal()
        with self.assertRaises(ResponseForbidden):self.service.approve(action["action_id"],expected_status="pending",actor="requester")
        self.clock.advance(61)
        with self.assertRaises(ResponseForbidden):self.service.execute(action["action_id"],expected_status="not_started",actor="approver")
        self.assertEqual(self.service.get(action["action_id"])["approval_state"],"expired")

    def test_reproposal_supersedes_prior_revision(self):
        old=self.proposal()
        new=self.proposal(parameters={"policy_justification":"changed reason"})
        self.assertNotEqual(old["action_id"],new["action_id"])
        self.assertEqual(new["revision"],2)
        self.assertEqual(new["supersedes"],old["action_id"])
        self.assertEqual(self.service.get(old["action_id"])["execution_state"],"superseded")

    def test_changed_evidence_creates_new_unapproved_revision(self):
        old=self.proposal()
        EventRepository(self.db).save(NormalizedEvent(event_id="event-2",timestamp="2026-04-01T00:00:01Z",source_ip="8.8.4.4",raw_event={},ingest_batch_id="batch"))
        with self.db.session() as c:c.execute("INSERT INTO incident_events VALUES(?,?)",("inc-1","event-2"))
        new=self.service.propose("inc-1","simulate_block_ip",target="8.8.8.8",target_type="ip",actor="requester")
        self.assertNotEqual(old["action_id"],new["action_id"])
        self.assertEqual(new["approval_state"],"pending")
        self.assertEqual(new["revision"],2)

    def test_rejected_proposal_can_be_reproposed_as_new_revision(self):
        old=self.proposal();self.service.reject(old["action_id"],expected_status="pending",actor="approver",reason="review again")
        new=self.proposal()
        self.assertNotEqual(old["action_id"],new["action_id"])
        self.assertEqual(new["revision"],2)
        self.assertEqual(new["approval_state"],"pending")

    def test_wrong_expected_state_conflicts(self):
        action=self.proposal()
        with self.assertRaises(ResponseConflict):self.service.approve(action["action_id"],expected_status="approved",actor="approver")

    def test_nonreversible_action_cannot_rollback(self):
        action=self.service.propose("inc-1","collect_evidence",actor="requester")
        result=self.service.execute(action["action_id"],expected_status="not_started",actor="requester")
        self.assertEqual(result["execution_state"],"simulated")
        with self.assertRaises(ResponseForbidden):self.service.rollback(action["action_id"],expected_status="simulated",actor="requester")

    def test_cli_dry_run_keeps_database_bytes_identical(self):
        from response import cli
        before=self.db.path.read_bytes()
        with patch.object(cli,"settings",SimpleNamespace(database_path=self.db.path)):
            with redirect_stdout(io.StringIO()):self.assertEqual(cli.main(["recommend","--incident","inc-1","--dry-run"]),0)
        self.assertEqual(self.db.path.read_bytes(),before)
        uninitialized=self.root/"never-created"/"soc.db"
        with patch.object(cli,"settings",SimpleNamespace(database_path=uninitialized)):
            with self.assertRaises(SystemExit):cli.main(["recommend","--incident","inc-1","--dry-run"])
        self.assertFalse(uninitialized.exists())

    def test_api_binds_actor_and_rejects_real_mode_and_approved_by_fields(self):
        if importlib.util.find_spec("fastapi") is None:self.skipTest("FastAPI is unavailable")
        from fastapi.testclient import TestClient
        from api.app import create_app
        with patch("api.dependencies.settings",SimpleNamespace(api_auth_enabled=True,api_auth_token="shared-test-token")):
          with TestClient(create_app(self.db)) as client:
            self.assertEqual(client.get("/api/v1/incidents/inc-1/response/actions").status_code,401)
            headers={"Authorization":"Bearer shared-test-token"}
            response=client.post("/api/v1/incidents/inc-1/response/actions",headers=headers,json={"action_type":"simulate_block_ip","target":"8.8.8.8","target_type":"ip"})
            self.assertEqual(response.status_code,200,response.text)
            payload=response.json();self.assertEqual(payload["execution_mode"],"simulation")
            self.assertEqual(payload["requested_by"],"api-user")
            url=f"/api/v1/response/actions/{payload['action_id']}/approve"
            self.assertEqual(client.post(url,headers=headers,json={"expected_status":"pending","approved_by":"root"}).status_code,422)
            execute=f"/api/v1/response/actions/{payload['action_id']}/execute"
            self.assertEqual(client.post(execute,headers=headers,json={"expected_status":"not_started","execution_mode":"real"}).status_code,422)
            self.assertEqual(client.post(url,headers=headers,json={"expected_status":"pending"}).status_code,200)
            self.assertEqual(client.post(execute,headers=headers,json={"expected_status":"not_started"}).json()["execution_state"],"simulated")
            audit=client.get("/api/v1/audit?resource_type=response_action",headers=headers).json()
            self.assertGreaterEqual(audit["total"],3)

    def test_double_approve_and_approve_reject_race(self):
        action=self.proposal();barrier=threading.Barrier(3);results=[]
        def run(method):
            barrier.wait()
            try:method(action["action_id"],expected_status="pending",actor="approver") ;results.append("ok")
            except ResponseConflict:results.append("conflict")
        ts=[threading.Thread(target=run,args=(self.service.approve,)) for _ in range(2)]
        [t.start() for t in ts];barrier.wait();[t.join() for t in ts]
        self.assertCountEqual(results,["ok","conflict"])
        action2=self.proposal(parameters={"policy_justification":"another revision"});barrier=threading.Barrier(3);results=[]
        ts=[threading.Thread(target=run,args=(fn,)) for fn in (self.service.approve,self.service.reject)]
        # Repoint the helper closure to the second action for this race.
        def race(fn):
            barrier.wait()
            try:fn(action2["action_id"],expected_status="pending",actor="approver");results.append("ok")
            except ResponseConflict:results.append("conflict")
        ts=[threading.Thread(target=race,args=(fn,)) for fn in (self.service.approve,self.service.reject)]
        [t.start() for t in ts];barrier.wait();[t.join() for t in ts]
        self.assertCountEqual(results,["ok","conflict"])

    def test_double_execute_race_has_one_attempt(self):
        action=self.approved();barrier=threading.Barrier(3);results=[]
        def run():
            barrier.wait()
            try:results.append(self.service.execute(action["action_id"],expected_status="not_started",actor="approver")["execution_state"])
            except ResponseConflict:results.append("conflict")
        ts=[threading.Thread(target=run) for _ in range(2)];[t.start() for t in ts];barrier.wait();[t.join() for t in ts]
        with self.db.read_session() as c:self.assertEqual(c.execute("SELECT COUNT(*) FROM execution_attempts WHERE action_id=?",(action["action_id"],)).fetchone()[0],1)
        self.assertIn("simulated",results)

    def test_stale_executing_attempt_recovers_to_failed(self):
        action=self.approved()
        old=(self.clock.value-timedelta(seconds=1000)).isoformat().replace("+00:00","Z")
        with self.db.session() as c:
            c.execute("UPDATE response_actions SET execution_state='executing' WHERE action_id=?",(action["action_id"],))
            c.execute("INSERT INTO execution_attempts(attempt_id,action_id,attempt_number,execution_mode,started_at,status) VALUES('stale',?,1,'simulation',?,'executing')",(action["action_id"],old))
        with self.assertRaises(ResponseConflict):self.service.execute(action["action_id"],expected_status="executing",actor="approver")
        self.assertEqual(self.service.get(action["action_id"])["execution_state"],"failed")

    def test_audit_is_immutable_and_audit_failure_rolls_back(self):
        action=self.proposal()
        collect=self.service.propose("inc-1","collect_evidence",actor="requester")
        with self.db.session() as c:
            audit_id=c.execute("SELECT audit_id FROM audit_log WHERE entity_type='response_action' LIMIT 1").fetchone()[0]
            with self.assertRaises(Exception):c.execute("UPDATE audit_log SET action='changed' WHERE audit_id=?",(audit_id,))
            with self.assertRaises(Exception):c.execute("DELETE FROM audit_log WHERE audit_id=?",(audit_id,))
            c.execute("CREATE TRIGGER reject_response_audit BEFORE INSERT ON audit_log WHEN NEW.entity_type='response_action' BEGIN SELECT RAISE(ABORT,'audit failure'); END")
        with self.assertRaises(Exception):self.service.execute(collect["action_id"],expected_status="not_started",actor="requester")
        with self.db.read_session() as c:
            self.assertEqual(c.execute("SELECT execution_state FROM response_actions WHERE action_id=?",(collect["action_id"],)).fetchone()[0],"not_started")
            self.assertEqual(c.execute("SELECT COUNT(*) FROM execution_attempts WHERE action_id=?",(collect["action_id"],)).fetchone()[0],0)
        with self.assertRaises(Exception):self.service.propose("inc-1","create_case_note",parameters={"note":"test"},actor="requester")
        with self.db.read_session() as c:self.assertEqual(c.execute("SELECT COUNT(*) FROM response_actions WHERE action_type='create_case_note'").fetchone()[0],0)

    def test_dry_run_is_read_only_and_creates_no_rows(self):
        before=self.db.path.read_bytes()
        results=self.service.recommend("inc-1",actor="cli:analyst",via="cli",dry_run=True)
        self.assertTrue(results);self.assertEqual(self.db.path.read_bytes(),before)
        with self.db.read_session() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM response_actions").fetchone()[0],0)
            self.assertEqual(c.execute("SELECT COUNT(*) FROM execution_attempts").fetchone()[0],0)
            self.assertEqual(c.execute("SELECT COUNT(*) FROM audit_log WHERE entity_type='response_action'").fetchone()[0],0)

    def test_static_and_runtime_simulation_boundary(self):
        root=Path(__file__).parents[1]/"response"
        dangerous_imports={"subprocess","socket","requests","urllib"}
        for path in root.glob("*.py"):
            tree=ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node,ast.Import):self.assertFalse(dangerous_imports.intersection(alias.name.split('.')[0] for alias in node.names),path.name)
                if isinstance(node,ast.ImportFrom):self.assertNotIn((node.module or "").split('.')[0],dangerous_imports,path.name)
                if isinstance(node,ast.Call):
                    self.assertFalse(isinstance(node.func,ast.Name) and node.func.id in {"eval","exec"},path.name)
                    self.assertFalse(isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name) and node.func.value.id=="os" and node.func.attr=="system",path.name)
        before=set(p.name for p in self.root.iterdir())
        with patch.object(socket,"socket",side_effect=AssertionError("socket called")) as sock,patch.object(subprocess,"Popen",side_effect=AssertionError("subprocess called")) as proc:
            action=self.proposal()
            self.service.approve(action["action_id"],expected_status="pending",actor="approver")
            self.service.execute(action["action_id"],expected_status="not_started",actor="approver")
            self.service.rollback(action["action_id"],expected_status="simulated",actor="approver")
            self.service.recommend("inc-1",actor="requester")
        sock.assert_not_called();proc.assert_not_called()
        self.assertEqual(set(p.name for p in self.root.iterdir()),before)


if __name__=="__main__": unittest.main()
