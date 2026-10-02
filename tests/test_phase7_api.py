import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from api.services.api_service import APIService
from database.database import Database, MIGRATIONS
from database.repositories import IngestBatchRepository, EventRepository
from models.event import NormalizedEvent


class Provider:
    def __init__(self): self.calls=0
    def generate(self,prompt): self.calls+=1; return "{}"


class APIFacadeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.db=Database(Path(self.temp.name)/"api.db"); self.db.initialize()
        self.service=APIService(self.db)
        IngestBatchRepository(self.db).save({"id":"api-batch","source_file":"api-fixture","file_hash":"hash","started_at":"2026-01-01T00:00:00Z","status":"completed"})
        for n,stamp in enumerate(("2026-01-01T00:00:00+00:00","2026-01-02T00:00:00+00:00")):
            alert_id=f"alert-{n}"
            payload={"alert_id":alert_id,"timestamp":stamp,"severity":"HIGH","status":"NEW","rule_id":"R001","title":f"Alert {n}","hostname":"srv","username":"alice","source_ip":"198.51.100.1"}
            with self.db.session() as c:
                c.execute("INSERT INTO alerts(alert_id,timestamp,severity,payload,status) VALUES(?,?,?,?,?)",(alert_id,stamp,"HIGH",json.dumps(payload),"NEW"))
            EventRepository(self.db).save(NormalizedEvent(event_id=f"event-{n}",timestamp=stamp,event_type="auth_failure",hostname="srv",username="alice",source_ip="198.51.100.1",raw_event={"message":"safe","api_key":"should-not-return"},ingest_batch_id="api-batch"))
        with self.db.session() as c:
            for n,stamp in enumerate(("2026-01-01T00:00:00+00:00","2026-01-02T00:00:00+00:00")):
                p={"incident_id":f"inc-{n}","title":f"Incident {n}","status":"open","severity":"HIGH","risk_score":50+n,"risk_level":"MEDIUM","confidence":"low","primary_host":"srv","primary_user":"alice","primary_src_ip":"198.51.100.1","detection_ids":[]}
                c.execute("INSERT INTO incidents(incident_id,created_at,updated_at,status,severity,risk_score,payload) VALUES(?,?,?,?,?,?,?)",(f"inc-{n}",stamp,stamp,"open","HIGH",50+n,json.dumps(p)))
            c.execute("INSERT INTO iocs(ioc_id,value,type,first_seen,last_seen,payload) VALUES(?,?,?,?,?,?)",("ioc-1","198.51.100.1","ip","2026-01-01T00:00:00Z","2026-01-02T00:00:00Z",json.dumps({"classification":"external"})))

    def test_health_and_readiness(self):
        self.assertEqual(self.service.health()["status"],"ok")
        self.assertEqual(self.service.ready()["schema_version"],9)

    def test_alerts_filter_page_and_stable_order(self):
        result=self.service.list_alerts(severity="high",limit=1,offset=0)
        self.assertEqual(result["total"],2); self.assertEqual(result["items"][0]["alert_id"],"alert-1")
        self.assertEqual(self.service.list_alerts(rule_id="' OR 1=1 --")["total"],0)

    def test_events_iocs_and_incidents_query(self):
        self.assertEqual(self.service.list_events(event_type="auth_failure")["total"],2)
        self.assertEqual(self.service.list_iocs(type="ip")["total"],1)
        page=self.service.list_incidents(min_risk_score=51,limit=1)
        self.assertEqual(page["total"],1); self.assertEqual(page["items"][0]["incident_id"],"inc-1")
        self.assertEqual(self.service.list_incidents(limit=1,sort="risk_asc")["items"][0]["incident_id"],"inc-0")
        with self.assertRaises(ValueError):self.service.list_incidents(sort="created_at desc; DROP TABLE incidents")
        detail=self.service.incident_detail("inc-0")
        self.assertEqual(detail["detection_ids"],[]); self.assertEqual(detail["events"],[])

    def test_phase8_dashboard_counts_trends_activity_and_bounded_search(self):
        summary=self.service.dashboard_summary()
        self.assertEqual(summary["active_incidents"],2)
        self.assertEqual(summary["high_severity_alerts"],2)
        self.assertEqual(summary["detection_count"],2)
        trends=self.service.dashboard_trends(days=7)
        self.assertEqual(trends["days"],7)
        self.assertEqual(sum(row["count"] for row in trends["severity_distribution"]),2)
        activity=self.service.dashboard_activity(limit=10)
        self.assertGreaterEqual(activity["total"],4)
        results=self.service.search("Alert 0")
        self.assertTrue(any(row["alert_id"]=="alert-0" for row in results["alerts"]))
        with self.assertRaises(ValueError):self.service.search("x")

    def test_analyst_edit_is_audited_and_cannot_set_derived_values(self):
        updated=self.service.update_incident("inc-0",{"status":"investigating","notes":"Review started"},"analyst")
        self.assertEqual(updated["status"],"investigating"); self.assertEqual(updated["analyst_notes"],"Review started")
        audit=self.service.list_audit(action="incident.updated")
        self.assertEqual(audit["total"],1); self.assertEqual(audit["items"][0]["actor"],"analyst")
        with self.assertRaises(ValueError):self.service.update_incident("inc-0",{"risk_score":99},"analyst")

    def test_audit_logs_and_secret_redaction(self):
        with self.db.session() as c:
            c.execute("INSERT INTO audit_log(timestamp,actor,action,entity_type,entity_id,details) VALUES(?,?,?,?,?,?)",("2026-01-01T00:00:00Z","test","x","x","x",json.dumps({"api_key":"secret","message":"ok\u001b[31m"})))
        entry=self.service.list_audit()["items"][0]
        self.assertNotIn("api_key",entry["details"]); self.assertEqual(entry["details"]["message"],"ok")

    def test_timestamp_limits_and_invalid_ip_helpers(self):
        with self.assertRaises(ValueError):self.service.list_events(since="bad")
        with self.assertRaises(ValueError):self.service.list_alerts(limit=201)
        self.assertEqual(self.service.page_values(1,0),(1,0))

    def test_correlation_get_is_read_only(self):
        before=self.service.correlation_executions()["total"]
        after=self.service.correlation_executions()["total"]
        self.assertEqual(before,after)

    def test_explicit_correlation_uses_phase5_and_records_audit(self):
        result=self.service.run_correlation(actor="api-test")
        self.assertTrue(result["execution_id"])
        self.assertEqual(self.service.correlation_executions()["total"],1)
        self.assertEqual(self.service.list_audit(action="correlation.executed")["total"],1)

    def test_investigation_delegates_to_phase6_empty_evidence_path(self):
        provider=Provider()
        with self.db.session() as c:
            p={"incident_id":"empty-api","title":"No evidence","status":"open","severity":"LOW","risk_score":0,"risk_level":"LOW","confidence":"low","detection_ids":[]}
            c.execute("INSERT INTO incidents(incident_id,created_at,updated_at,status,severity,risk_score,payload) VALUES(?,?,?,?,?,?,?)",("empty-api","2026-01-01T00:00:00Z","2026-01-01T00:00:00Z","open","LOW",0,json.dumps(p)))
        api=APIService(self.db,investigation_provider=provider)
        self.assertEqual(api.investigations("empty-api"),[])
        result=api.investigate("empty-api")
        self.assertEqual(result["status"],"completed");self.assertEqual(provider.calls,0)


HAS_HTTP_STACK=all(importlib.util.find_spec(name) for name in ("fastapi","pydantic","httpx"))


@unittest.skipUnless(HAS_HTTP_STACK,"FastAPI/httpx dependencies are declared but unavailable in this environment")
class APIRouteTests(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        from api.app import create_app
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.db=Database(Path(self.temp.name)/"http.db")
        self.client=TestClient(create_app(self.db))
        self.client.__enter__(); self.addCleanup(self.client.__exit__,None,None,None)

    def seed(self):
        with self.db.session() as c:
            c.execute("INSERT INTO ingest_batches(id,source_file,file_hash,started_at,event_count,status) VALUES(?,?,?,?,?,?)",("route-batch","route-source","route-hash","2026-01-01T00:00:00Z",1,"completed"))
            c.execute("INSERT INTO alerts(alert_id,timestamp,severity,payload,status) VALUES(?,?,?,?,?)",("route-alert","2026-01-01T00:00:00Z","HIGH",json.dumps({"alert_id":"route-alert","rule_id":"R001","hostname":"api-host","username":"analyst","source_ip":"198.51.100.20"}),"NEW"))
            c.execute("INSERT INTO events(id,timestamp,source_type,host,user,src_ip,dst_ip,event_type,raw,raw_ref,ingest_batch_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",("route-event","2026-01-01T00:00:00Z","auth","api-host","analyst","198.51.100.20",None,"auth_failure",json.dumps({"raw_event":{"message":"normal","password":"hidden"},"event":{"event_id":"route-event","raw_ref":"C:\\secret\\event.json","ingest_batch_id":"internal"}}),"C:\\secret\\event.json","route-batch"))
            c.execute("INSERT INTO iocs(ioc_id,value,type,first_seen,last_seen,payload) VALUES(?,?,?,?,?,?)",("route-ioc","198.51.100.20","ip","2026-01-01T00:00:00Z","2026-01-01T00:00:00Z","{}"))
            p={"incident_id":"route-incident","title":"API incident","description":"test","status":"open","severity":"HIGH","risk_score":65,"risk_level":"HIGH","confidence":"low","primary_host":"api-host","primary_user":"analyst","primary_src_ip":"198.51.100.20","detection_ids":[]}
            c.execute("INSERT INTO incidents(incident_id,created_at,updated_at,status,severity,risk_score,payload) VALUES(?,?,?,?,?,?,?)",("route-incident","2026-01-01T00:00:00Z","2026-01-01T00:00:00Z","open","HIGH",65,json.dumps(p)))

    def test_health_ready_api_prefix_and_openapi(self):
        self.assertEqual(self.client.get("/api/v1/health").status_code,200)
        self.assertEqual(self.client.get("/api/v1/ready").json()["schema_version"],9)
        self.assertEqual(self.client.get("/docs").status_code,200)
        self.assertEqual(self.client.get("/health").status_code,200)
        schema=self.client.get("/openapi.json").json()
        self.assertNotEqual(schema["paths"]["/api/v1/alerts"]["get"]["responses"]["200"]["content"]["application/json"]["schema"],{})
        sort=next(p for p in schema["paths"]["/api/v1/incidents"]["get"]["parameters"] if p["name"]=="sort")
        self.assertEqual(sort["schema"]["enum"],["created_desc","created_asc","risk_desc","risk_asc"])

    def test_existing_schema_v7_is_migrated_and_preserved_on_api_startup(self):
        path=Path(self.temp.name)/"legacy-v7.db";legacy=Database(path)
        with patch("database.database.MIGRATIONS",{v:sql for v,sql in MIGRATIONS.items() if v<=7}):
            legacy.initialize()
        with legacy.session() as c:
            c.execute("INSERT INTO incidents(incident_id,created_at,updated_at,status,severity,risk_score,payload) VALUES(?,?,?,?,?,?,?)",("legacy","2026-01-01T00:00:00Z","2026-01-01T00:00:00Z","open","LOW",0,json.dumps({"title":"Preserved"})))
        from api.app import create_app
        from fastapi.testclient import TestClient
        with TestClient(create_app(legacy)) as client:
            self.assertEqual(client.get("/api/v1/ready").json()["schema_version"],9)
            self.assertEqual(client.get("/api/v1/incidents/legacy").json()["title"],"Preserved")
        self.assertEqual(legacy.current_version(),9)

    def test_request_validation_and_error_shape(self):
        invalid=self.client.get("/api/v1/events",params={"src_ip":"not-ip"})
        self.assertEqual(invalid.status_code,400); self.assertIn("error",invalid.json())
        oversized=self.client.get("/api/v1/incidents",params={"limit":201})
        self.assertEqual(oversized.status_code,422)

    def test_invalid_patch_fields_and_missing_incident(self):
        self.assertEqual(self.client.patch("/api/v1/incidents/nope",json={"risk_score":100}).status_code,422)
        missing=self.client.patch("/api/v1/incidents/nope",json={"notes":"x"})
        self.assertEqual(missing.status_code,404); self.assertEqual(missing.json()["error"]["code"],"incident_not_found")

    def test_collections_filter_paginate_and_details(self):
        self.seed()
        for path in ("/api/v1/alerts?severity=HIGH&limit=1","/api/v1/events?src_ip=198.51.100.20",
                     "/api/v1/iocs?type=ip","/api/v1/incidents?min_risk_score=60&limit=1"):
            response=self.client.get(path)
            self.assertEqual(response.status_code,200,path)
            self.assertEqual(response.json()["total"],1,path)
        self.assertEqual(self.client.get("/api/v1/alerts/route-alert").status_code,200)
        event=self.client.get("/api/v1/events/route-event").json()
        self.assertNotIn("password",json.dumps(event).lower())
        self.assertNotIn("raw_ref",event);self.assertNotIn("ingest_batch_id",event)
        self.assertNotIn("C:\\secret",json.dumps(event))
        self.assertEqual(self.client.get("/api/v1/iocs/route-ioc").status_code,200)
        incident=self.client.get("/api/v1/incidents/route-incident").json()
        self.assertEqual(incident["title"],"API incident");self.assertIn("description",incident)

    def test_analyst_update_audits_and_derived_field_is_rejected(self):
        self.seed()
        response=self.client.patch("/api/v1/incidents/route-incident",json={"status":"investigating","notes":"review"})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()["analyst_notes"],"review")
        audit=self.client.get("/api/v1/audit?action=incident.updated").json()
        self.assertEqual(audit["total"],1)
        self.assertEqual(self.client.patch("/api/v1/incidents/route-incident",json={"risk_score":1}).status_code,422)

    def test_investigation_and_explicit_correlation_routes(self):
        self.seed()
        runs=self.client.get("/api/v1/incidents/route-incident/investigations")
        self.assertEqual(runs.status_code,200);self.assertEqual(runs.json()["total"],0)
        investigation=self.client.post("/api/v1/incidents/route-incident/investigate",json={"force":False})
        self.assertEqual(investigation.status_code,200,investigation.text)
        self.assertEqual(investigation.json()["status"],"completed")
        self.assertTrue(self.client.get("/api/v1/investigations/"+investigation.json()["investigation_id"]).json()["summary"])
        self.assertEqual(self.client.post("/api/v1/incidents/missing/investigate",json={}).status_code,404)
        before=self.client.get("/api/v1/correlation/executions").json()["total"]
        self.assertEqual(self.client.get("/api/v1/correlation/executions").json()["total"],before)
        executed=self.client.post("/api/v1/correlation/run")
        self.assertEqual(executed.status_code,200,executed.text)
        self.assertEqual(self.client.get("/api/v1/correlation/executions").json()["total"],before+1)
        self.assertEqual(self.client.get("/api/v1/audit?action=correlation.executed").json()["total"],1)

    def test_phase8_dashboard_search_and_global_workflows(self):
        self.seed()
        summary=self.client.get("/api/v1/dashboard/summary")
        self.assertEqual(summary.status_code,200);self.assertEqual(summary.json()["detection_count"],1)
        self.assertEqual(self.client.get("/api/v1/dashboard/trends?days=7").status_code,200)
        self.assertEqual(self.client.get("/api/v1/dashboard/activity?limit=10").status_code,200)
        search=self.client.get("/api/v1/search?q=route")
        self.assertEqual(search.status_code,200);self.assertEqual(len(search.json()["alerts"]),1)
        self.assertEqual(self.client.get("/api/v1/investigations").status_code,200)
        self.assertEqual(self.client.get("/api/v1/attack/mappings").status_code,200)
        from types import SimpleNamespace
        with patch("api.dependencies.settings",SimpleNamespace(api_auth_enabled=True,api_auth_token="test-secret")):
            self.assertEqual(self.client.get("/api/v1/dashboard/summary").status_code,401)
            self.assertEqual(self.client.get("/api/v1/dashboard/summary",headers={"Authorization":"Bearer test-secret"}).status_code,200)

    def test_phase8_alert_filters_and_ioc_relationship_detail(self):
        self.seed()
        with self.db.session() as c:
            c.execute("INSERT INTO incident_detections(incident_id,detection_id) VALUES(?,?)",("route-incident","route-alert"))
            c.execute("INSERT INTO incident_iocs(incident_id,ioc_id) VALUES(?,?)",("route-incident","route-ioc"))
            c.execute("INSERT INTO ioc_events(ioc_id,event_id,source_field,confidence) VALUES(?,?,?,?)",("route-ioc","route-event","source_ip",1.0))
            c.execute("INSERT INTO ioc_detection_links(ioc_id,detection_id,relationship_type) VALUES(?,?,?)",("route-ioc","route-alert","observed_in"))
        results=self.client.get("/api/v1/alerts?search=route&sort=timestamp_asc")
        self.assertEqual(results.status_code,200);self.assertEqual(results.json()["items"][0]["incident_id"],"route-incident")
        self.assertEqual(self.client.get("/api/v1/incidents?confidence=low").json()["items"][0]["detection_count"],1)
        ioc=self.client.get("/api/v1/iocs/route-ioc").json()
        self.assertEqual(ioc["occurrence_count"],1);self.assertEqual(ioc["incidents"][0]["incident_id"],"route-incident")


if __name__=="__main__":unittest.main()
