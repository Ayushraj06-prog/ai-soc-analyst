"""Thin query/update facade over the existing SQLite and domain services."""
import json
import logging
import re
import sqlite3
from datetime import datetime, timezone

from correlation.service import CorrelationService
from database.database import Database
from investigation.service import InvestigationService
from models.timestamps import to_utc_iso
from app.config import settings
from version import __version__
from ai.assistant import provider_status

log = logging.getLogger("ai_soc.api")
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET = re.compile(r"(?i)([\"']?(?:password|passwd|secret|token|api[_-]?key|authorization)[\"']?\s*[:=]\s*[\"']?)([^\s,;\"']+)")
_MAX_LIMIT = 200


def clean(value, *, limit=4000):
    if value is None:
        return None
    text = _ANSI.sub("", str(value))
    text = _CONTROL.sub("", text)
    text = _SECRET.sub(lambda m: m.group(1) + "[REDACTED]", text)
    return text[:limit]


def clean_json(value, *, limit=4000):
    if isinstance(value, dict):
        result = {}
        for key, item in list(value.items())[:100]:
            key_text=str(key)
            if (re.search(r"(?i)password|passwd|secret|token|api[_-]?key|authorization", key_text)
                    or key_text.lower() in {"raw_ref", "ingest_batch_id", "database_path", "db_path"}
                    or re.search(r"(?i)(?:file|database|db)[_-]?path", key_text)):
                continue
            result[clean(key_text, limit=200)] = clean_json(item, limit=limit)
        return result
    if isinstance(value, list):
        return [clean_json(item, limit=limit) for item in value[:100]]
    if isinstance(value, str):
        return clean(value, limit=limit)
    return value


class APIService:
    def __init__(self, database, *, investigation_provider=None):
        self.db = database if isinstance(database, Database) else Database(database)
        self.investigation_provider = investigation_provider

    @staticmethod
    def page_values(limit, offset):
        if limit < 1 or limit > _MAX_LIMIT:
            raise ValueError(f"limit must be between 1 and {_MAX_LIMIT}")
        if offset < 0 or offset > 1_000_000:
            raise ValueError("offset must be between 0 and 1000000")
        return limit, offset

    @staticmethod
    def timestamp(value):
        if value is None:
            return None
        try:
            return to_utc_iso(value)
        except (TypeError, ValueError, OverflowError, OSError) as exc:
            raise ValueError("timestamp must be a valid ISO-8601 timestamp") from exc

    def health(self):
        return {"status": "ok", "service": "ai-soc-analyst"}

    def system_status(self):
        readiness = self.ready()
        return {
            "status": "ok" if readiness["status"] == "ready" else "degraded",
            "environment": settings.environment,
            "application_version": __version__,
            "schema_version": readiness.get("schema_version"),
            "database": readiness.get("database", "unavailable"),
            "ai_provider": settings.llm_provider,
            "ai_provider_status": provider_status() if settings.llm_provider else "not_configured",
        }

    def ready(self):
        try:
            with self.db.read_session() as c:
                version_table = c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'").fetchone()
                if not version_table:
                    return {"status": "not_ready", "database": "ok", "schema_version": None}
                version = c.execute("SELECT COALESCE(MAX(version),0) FROM schema_version").fetchone()[0]
                required = {"alerts", "events", "iocs", "incidents", "investigations", "audit_log",
                            "response_actions", "response_action_evidence", "execution_attempts"}
                existing = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not required.issubset(existing) or version < 9:
                    return {"status": "not_ready", "database": "ok", "schema_version": version}
                return {"status": "ready", "database": "ok", "schema_version": version}
        except (sqlite3.Error, OSError):
            log.exception("API readiness database check failed")
            return {"status": "not_ready", "database": "unavailable", "schema_version": None}

    def _page(self, table, select, filters, order, limit, offset):
        limit, offset = self.page_values(limit, offset)
        clauses, params = [], []
        for expression, value in filters:
            if value is not None:
                clauses.append(expression + " = ?")
                params.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.db.read_session() as c:
            total = c.execute(f"SELECT COUNT(*) FROM {table}{where}", params).fetchone()[0]
            rows = c.execute(f"SELECT {select} FROM {table}{where} ORDER BY {order} LIMIT ? OFFSET ?",
                             (*params, limit, offset)).fetchall()
        return {"items": rows, "total": total, "limit": limit, "offset": offset}

    def list_alerts(self, *, severity=None, status=None, rule_id=None, mitre_technique=None,
                    host=None, user=None, source_ip=None, since=None, until=None,
                    search=None, sort="timestamp_desc", limit=50, offset=0):
        since, until = self.timestamp(since), self.timestamp(until)
        orders={"timestamp_desc":"timestamp DESC,alert_id DESC","timestamp_asc":"timestamp ASC,alert_id ASC",
                "severity_desc":"CASE severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END DESC,timestamp DESC,alert_id DESC"}
        if sort not in orders: raise ValueError("sort must be timestamp_desc, timestamp_asc, or severity_desc")
        filters = [("severity", severity.upper() if severity else None), ("status", status),
                   ("json_extract(payload,'$.rule_id')", rule_id),
                   ("json_extract(payload,'$.hostname')", host),
                   ("json_extract(payload,'$.username')", user),
                   ("json_extract(payload,'$.source_ip')", source_ip),
        ]
        clauses,params=[],[]
        for exp,val in filters:
            if val is not None: clauses.append(exp+" = ?");params.append(val)
        if since: clauses.append("timestamp >= ?");params.append(since)
        if until: clauses.append("timestamp <= ?");params.append(until)
        if mitre_technique:
            clauses.append("EXISTS (SELECT 1 FROM attack_mappings m WHERE m.detection_id=alerts.alert_id AND m.technique_id=?)");params.append(mitre_technique)
        if search:
            term=self._like(search)
            clauses.append("(alert_id LIKE ? ESCAPE '\\' OR payload LIKE ? ESCAPE '\\')");params.extend((term,term))
        limit,offset=self.page_values(limit,offset);where=" WHERE "+" AND ".join(clauses) if clauses else ""
        with self.db.read_session() as c:
            total=c.execute("SELECT COUNT(*) FROM alerts"+where,params).fetchone()[0]
            rows=c.execute("SELECT alert_id,timestamp,severity,payload,status FROM alerts"+where+" ORDER BY "+orders[sort]+" LIMIT ? OFFSET ?",(*params,limit,offset)).fetchall()
            items=[]
            for row in rows:
                item=dict(row)
                try: payload=json.loads(item.pop("payload") or "{}")
                except ValueError: payload={}
                item.update(clean_json(payload))
                linked=c.execute("SELECT incident_id FROM incident_detections WHERE detection_id=?",(item["alert_id"],)).fetchone()
                item["incident_id"]=linked[0] if linked else None
                items.append(item)
        return {"items":items,"total":total,"limit":limit,"offset":offset}

    @staticmethod
    def _like(value):
        text=str(value)[:120].replace("\\","\\\\").replace("%","\\%").replace("_","\\_")
        return "%"+text+"%"

    def alert_detail(self, alert_id):
        item=self.get_record("alerts","alert_id",alert_id)
        if not item:return None
        with self.db.read_session() as c:
            item["events"]=[]
            evidence_ids=item.get("evidence_refs",[])
            evidence_ids=[str(value) for value in evidence_ids[:100]] if isinstance(evidence_ids,list) else []
            if evidence_ids:
                marks=",".join("?" for _ in evidence_ids)
                rows=c.execute(f"SELECT id,timestamp,source_type,host,user,src_ip,dst_ip,event_type,raw FROM events WHERE id IN ({marks}) ORDER BY timestamp,id LIMIT 100",evidence_ids)
            else: rows=[]
            for row in rows:
                event=dict(row)
                try:raw=json.loads(event.pop("raw") or "{}")
                except ValueError:raw={}
                event["raw"]=clean_json(raw.get("raw_event",raw),limit=2000)
                item["events"].append(event)
            item["iocs"]=[dict(r) for r in c.execute("SELECT i.ioc_id,i.value,i.type,i.first_seen,i.last_seen FROM ioc_detection_links x JOIN iocs i ON i.ioc_id=x.ioc_id WHERE x.detection_id=? ORDER BY i.ioc_id LIMIT 100",(alert_id,))]
            item["attack_mappings"]=[dict(r) for r in c.execute("SELECT technique_id,technique_name,tactic_ids,mapping_source,confidence,evidence_ids,baseline_techniques,baseline_disagreement FROM attack_mappings WHERE detection_id=? ORDER BY technique_id,id",(alert_id,))]
            for mapping in item["attack_mappings"]:
                for field in ("tactic_ids","evidence_ids","baseline_techniques"):
                    try:mapping[field]=json.loads(mapping[field] or "[]")
                    except (ValueError,TypeError):mapping[field]=[]
            incident=c.execute("SELECT incident_id FROM incident_detections WHERE detection_id=?",(alert_id,)).fetchone()
            item["incident_id"]=incident[0] if incident else None
        return clean_json(item)

    def list_events(self, *, event_type=None, source_type=None, host=None, user=None, src_ip=None,
                    dst_ip=None, since=None, until=None, limit=50, offset=0):
        since, until = self.timestamp(since), self.timestamp(until)
        filters = [("event_type", event_type), ("source_type", source_type), ("host", host),
                   ("user", user), ("src_ip", src_ip), ("dst_ip", dst_ip)]
        base = self._page("events", "id,timestamp,source_type,host,user,src_ip,dst_ip,event_type,raw", filters,
                          "timestamp DESC,id DESC", limit, offset)
        if since or until:
            clauses, params = [], []
            for exp, val in filters:
                if val is not None: clauses.append(exp + " = ?"); params.append(val)
            if since: clauses.append("timestamp >= ?"); params.append(since)
            if until: clauses.append("timestamp <= ?"); params.append(until)
            where = " WHERE " + " AND ".join(clauses) if clauses else ""
            with self.db.read_session() as c:
                total = c.execute("SELECT COUNT(*) FROM events" + where, params).fetchone()[0]
                rows = c.execute("SELECT id,timestamp,source_type,host,user,src_ip,dst_ip,event_type,raw FROM events" + where + " ORDER BY timestamp DESC,id DESC LIMIT ? OFFSET ?", (*params, limit, offset)).fetchall()
            base = {"items": rows, "total": total, "limit": limit, "offset": offset}
        items = []
        for row in base["items"]:
            item = dict(row)
            try: raw = json.loads(item.pop("raw"))
            except (ValueError, TypeError): raw = {}
            event = raw.get("event", {}) if isinstance(raw, dict) else {}
            item["raw"] = clean_json(raw.get("raw_event", raw) if isinstance(raw, dict) else raw, limit=2000)
            item.update({k: clean(v, limit=500) for k, v in event.items() if k not in item and k not in {"raw_event", "ingest_batch_id", "raw_ref"}})
            items.append(item)
        return {**base, "items": items}

    def list_iocs(self, *, type=None, value=None, first_seen=None, last_seen=None, limit=50, offset=0):
        fs, ls = self.timestamp(first_seen), self.timestamp(last_seen)
        filters = [("type", type), ("value", value)]
        base = self._page("iocs", "ioc_id,value,type,first_seen,last_seen,payload", filters,
                          "last_seen DESC,ioc_id DESC", limit, offset)
        if fs or ls:
            clauses, params = [], []
            for exp, val in filters:
                if val is not None: clauses.append(exp + " = ?"); params.append(val)
            if fs: clauses.append("first_seen >= ?"); params.append(fs)
            if ls: clauses.append("last_seen <= ?"); params.append(ls)
            where = " WHERE " + " AND ".join(clauses) if clauses else ""
            with self.db.read_session() as c:
                total = c.execute("SELECT COUNT(*) FROM iocs" + where, params).fetchone()[0]
                rows = c.execute("SELECT ioc_id,value,type,first_seen,last_seen,payload FROM iocs" + where + " ORDER BY last_seen DESC,ioc_id DESC LIMIT ? OFFSET ?", (*params,limit,offset)).fetchall()
            base = {"items": rows, "total": total, "limit": limit, "offset": offset}
        return self._present_page(base, "payload")

    @staticmethod
    def _present_page(page, payload_key):
        items=[]
        for row in page["items"]:
            item=dict(row)
            try: payload=json.loads(item.pop(payload_key) or "{}")
            except (ValueError, TypeError): payload={}
            item.update(clean_json(payload))
            items.append(item)
        return {**page,"items":items}

    def list_incidents(self, *, status=None, severity=None, risk_level=None, min_risk_score=None,
                       max_risk_score=None, primary_host=None, primary_user=None, primary_src_ip=None,
                       confidence=None, since=None, until=None, limit=50, offset=0, sort="created_desc"):
        since, until = self.timestamp(since), self.timestamp(until)
        filters=[("status",status), ("severity",severity.upper() if severity else None),
            ("json_extract(payload,'$.risk_level')",risk_level),
            ("json_extract(payload,'$.primary_host')",primary_host),
            ("json_extract(payload,'$.primary_user')",primary_user),
            ("json_extract(payload,'$.primary_src_ip')",primary_src_ip),
            ("json_extract(payload,'$.confidence')",confidence)]
        limit, offset = self.page_values(limit,offset)
        order_by={"created_desc":"created_at DESC,incident_id DESC",
                  "created_asc":"created_at ASC,incident_id ASC",
                  "risk_desc":"risk_score DESC,incident_id DESC",
                  "risk_asc":"risk_score ASC,incident_id ASC"}.get(sort)
        if order_by is None:
            raise ValueError("sort must be created_desc, created_asc, risk_desc, or risk_asc")
        clauses=[]; params=[]
        for exp,val in filters:
            if val is not None: clauses.append(exp+" = ?"); params.append(val)
        if min_risk_score is not None: clauses.append("risk_score >= ?"); params.append(min_risk_score)
        if max_risk_score is not None: clauses.append("risk_score <= ?"); params.append(max_risk_score)
        if since: clauses.append("created_at >= ?"); params.append(since)
        if until: clauses.append("created_at <= ?"); params.append(until)
        where=" WHERE "+" AND ".join(clauses) if clauses else ""
        with self.db.read_session() as c:
            total=c.execute("SELECT COUNT(*) FROM incidents"+where,params).fetchone()[0]
            rows=c.execute("SELECT incidents.incident_id,created_at,updated_at,status,severity,risk_score,payload,(SELECT COUNT(*) FROM incident_detections d WHERE d.incident_id=incidents.incident_id) AS detection_count FROM incidents"+where+" ORDER BY "+order_by+" LIMIT ? OFFSET ?",(*params,limit,offset)).fetchall()
        return self._present_page({"items":rows,"total":total,"limit":limit,"offset":offset},"payload")

    def incident_detail(self, incident_id):
        with self.db.read_session() as c:
            row=c.execute("SELECT incident_id,created_at,updated_at,status,severity,risk_score,payload FROM incidents WHERE incident_id=?",(incident_id,)).fetchone()
            if not row: return None
            item=dict(row)
            try: payload=json.loads(item.pop("payload") or "{}")
            except ValueError: payload={}
            item.update(clean_json(payload))
            for field,default in (("title",""),("description",""),("risk_level","UNKNOWN"),
                                  ("confidence","low"),("primary_host",None),("primary_user",None),
                                  ("primary_src_ip",None),("first_seen",None),("last_seen",None)):
                item.setdefault(field,default)
            item["detection_ids"]=[r[0] for r in c.execute("SELECT detection_id FROM incident_detections WHERE incident_id=? ORDER BY detection_id",(incident_id,))]
            item["events"]=[]
            for ev in c.execute("SELECT e.id,e.timestamp,e.event_type,e.host,e.user,e.src_ip,e.dst_ip,e.raw FROM incident_events x JOIN events e ON e.id=x.event_id WHERE x.incident_id=? ORDER BY e.timestamp,e.id LIMIT 500",(incident_id,)):
                try: raw=json.loads(ev["raw"] or "{}")
                except (ValueError, TypeError): raw={}
                item["events"].append({"event_id":ev["id"],"timestamp":ev["timestamp"],"event_type":ev["event_type"],"host":clean(ev["host"],limit=500),"user":clean(ev["user"],limit=500),"src_ip":ev["src_ip"],"dst_ip":ev["dst_ip"],"raw":clean_json(raw.get("raw_event",raw),limit=2000)})
            item["iocs"]=[dict(r) for r in c.execute("SELECT i.ioc_id,i.value,i.type,i.first_seen,i.last_seen FROM incident_iocs x JOIN iocs i ON i.ioc_id=x.ioc_id WHERE x.incident_id=? ORDER BY i.ioc_id",(incident_id,))]
            item["attack_mappings"]=[dict(r) for r in c.execute("SELECT m.id,m.detection_id,m.technique_id,m.technique_name,m.tactic_ids,m.mapping_source,m.confidence,m.evidence_ids FROM incident_attack_mappings x JOIN attack_mappings m ON m.id=x.mapping_id WHERE x.incident_id=? ORDER BY m.technique_id,m.id",(incident_id,))]
            for mapping in item["attack_mappings"]:
                for field in ("tactic_ids","evidence_ids"):
                    try: mapping[field]=json.loads(mapping[field] or "[]")
                    except (ValueError,TypeError): mapping[field]=[]
            ids=item["detection_ids"]
            item["correlation_edges"]=[]
            if ids:
                marks=",".join("?" for _ in ids)
                item["correlation_edges"]=[dict(r) for r in c.execute(f"SELECT rule_id,source_detection_id,target_detection_id,matched_at,explanation,rule_version FROM correlation_edges WHERE source_detection_id IN ({marks}) AND target_detection_id IN ({marks}) ORDER BY matched_at,rule_id,source_detection_id,target_detection_id",(*ids,*ids))]
            item["merge_history"]=[dict(r) for r in c.execute("SELECT losing_incident_id,surviving_incident_id,merged_at,details FROM incident_merge_history WHERE losing_incident_id=? OR surviving_incident_id=? ORDER BY merged_at,id",(incident_id,incident_id))]
        return clean_json(item)

    def update_incident(self, incident_id, changes, actor):
        if not isinstance(changes, dict) or set(changes) - {"status", "notes"}:
            raise ValueError("Only status and notes may be updated")
        values={k:v for k,v in changes.items() if v is not None}
        if not values: raise ValueError("At least one analyst-owned field is required")
        if "status" in values:
            status=str(values["status"]).strip().lower()
            if status not in {"open","acknowledged","investigating","confirmed","false_positive","resolved","closed"}:
                raise ValueError("status is not an allowed analyst status")
            values["status"]=status
        if "notes" in values: values["notes"]=clean(values["notes"],limit=4000)
        now=datetime.now(timezone.utc).isoformat()
        with self.db.session() as c:
            c.execute("BEGIN IMMEDIATE")
            row=c.execute("SELECT payload,status FROM incidents WHERE incident_id=?",(incident_id,)).fetchone()
            if not row: return None
            payload=json.loads(row["payload"] or "{}")
            if "notes" in values: payload["analyst_notes"]=values["notes"]
            if "status" in values: payload["status"]=values["status"]
            new_status=values.get("status",row["status"])
            c.execute("UPDATE incidents SET status=?,updated_at=?,payload=? WHERE incident_id=?",(new_status,now,json.dumps(payload,separators=(",",":")),incident_id))
            c.execute("INSERT INTO audit_log(timestamp,actor,action,entity_type,entity_id,details) VALUES(?,?,?,?,?,?)",
                (now,clean(actor,limit=100),"incident.updated","incident",incident_id,json.dumps(clean_json(values),separators=(",",":"))))
        log.info("Analyst updated incident id=%s fields=%s",incident_id,sorted(values))
        return self.incident_detail(incident_id)

    def investigations(self, incident_id):
        with self.db.read_session() as c:
            if not c.execute("SELECT 1 FROM incidents WHERE incident_id=?",(incident_id,)).fetchone(): return None
            rows=c.execute("SELECT investigation_id,incident_id,status,provider,model,run_number,deterministic_confidence,ai_confidence,confidence_warning,ai_unavailable,evidence_hash,started_at,completed_at,result_json FROM investigations WHERE incident_id=? ORDER BY run_number DESC,investigation_id DESC",(incident_id,)).fetchall()
        return [self._investigation(dict(r)) for r in rows]

    def investigation(self, investigation_id):
        with self.db.read_session() as c:
            row=c.execute("SELECT investigation_id,incident_id,status,provider,model,run_number,deterministic_confidence,ai_confidence,confidence_warning,ai_unavailable,evidence_hash,started_at,completed_at,result_json FROM investigations WHERE investigation_id=?",(investigation_id,)).fetchone()
        return self._investigation(dict(row)) if row else None

    def _investigation(self, row):
        try: result=json.loads(row.pop("result_json") or "{}")
        except ValueError: result={}
        return {**row,"summary":clean(result.get("summary"),limit=4000),"findings":clean_json(result.get("key_findings",[])),
                "recommendations":clean_json(result.get("recommended_actions",[])),"attack_mappings":clean_json(result.get("mitre_assessment",[])),
                "evidence_ids":self._investigation_evidence(row["investigation_id"])}

    def _investigation_evidence(self, investigation_id):
        with self.db.read_session() as c:
            return [dict(r) for r in c.execute("SELECT evidence_type,evidence_id,finding_category,relationship FROM investigation_evidence WHERE investigation_id=? ORDER BY evidence_type,evidence_id,finding_category",(investigation_id,))]

    def investigate(self, incident_id, *, force=False, actor="api-user"):
        log.info("Investigation requested for incident id=%s force=%s",incident_id,force)
        service=InvestigationService(self.db,provider=self.investigation_provider)
        result=service.investigate(incident_id,force=force,created_by=actor)
        if result.get("status")=="not_found": return None
        if result.get("status") in {"already_running", "retry_limit"}:
            return clean_json(result)
        if result.get("investigation_id"):
            detail=self.investigation(result["investigation_id"])
            if detail: return detail
        return clean_json(result)

    def list_audit(self, *, action=None, actor=None, resource_type=None, resource_id=None,
                   since=None, until=None, limit=50, offset=0):
        since,until=self.timestamp(since),self.timestamp(until)
        filters=[("action",action),("actor",actor),("entity_type",resource_type),("entity_id",resource_id)]
        clauses=[];params=[]
        for exp,val in filters:
            if val is not None: clauses.append(exp+" = ?");params.append(val)
        if since: clauses.append("timestamp >= ?");params.append(since)
        if until: clauses.append("timestamp <= ?");params.append(until)
        limit,offset=self.page_values(limit,offset);where=" WHERE "+" AND ".join(clauses) if clauses else ""
        with self.db.read_session() as c:
            total=c.execute("SELECT COUNT(*) FROM audit_log"+where,params).fetchone()[0]
            rows=c.execute("SELECT audit_id,timestamp,actor,action,entity_type AS resource_type,entity_id AS resource_id,details FROM audit_log"+where+" ORDER BY timestamp DESC,audit_id DESC LIMIT ? OFFSET ?",(*params,limit,offset)).fetchall()
        items=[]
        for row in rows:
            item=dict(row)
            try:item["details"]=clean_json(json.loads(item["details"]))
            except ValueError:item["details"]={}
            items.append(item)
        return {"items":items,"total":total,"limit":limit,"offset":offset}

    def correlation_executions(self, *, limit=50, offset=0):
        page=self._page("correlation_executions","execution_id,started_at,completed_at,status,candidate_count,edge_count,incident_created,incident_updated,incident_merged,suppressed_count,error_count,config_hash,rule_version,errors",[],"started_at DESC,execution_id DESC",limit,offset)
        return {**page,"items":[dict(row) for row in page["items"]]}

    def run_correlation(self, *, since=None, actor="api-user"):
        since=self.timestamp(since)
        result=CorrelationService(self.db).run(since=since)
        execution_id=result.get("execution_id")
        with self.db.session() as c:
            c.execute("INSERT INTO audit_log(timestamp,actor,action,entity_type,entity_id,details) VALUES(?,?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(),clean(actor,limit=100),"correlation.executed","correlation_execution",execution_id,json.dumps(clean_json(result),separators=(",",":"))))
        log.info("Correlation execution requested execution_id=%s",execution_id)
        return clean_json(result)

    def get_record(self, table, key, value):
        if (table,key) not in {("alerts","alert_id"),("events","id"),("iocs","ioc_id")}:
            raise ValueError("unsupported record type")
        with self.db.read_session() as c:
            row=c.execute(f"SELECT * FROM {table} WHERE {key}=?",(value,)).fetchone()
        if not row:return None
        result=dict(row)
        if table=="events":
            result.pop("raw_ref",None);result.pop("ingest_batch_id",None)
            try: raw=json.loads(result.pop("raw") or "{}")
            except (ValueError,TypeError): raw={}
            event=raw.get("event",{}) if isinstance(raw,dict) else {}
            result.update(clean_json({k:v for k,v in event.items() if k not in {"raw_ref","ingest_batch_id"}}))
            result["raw"]=clean_json(raw.get("raw_event",raw),limit=2000)
        else:
            try: payload=json.loads(result.pop("payload") or "{}")
            except ValueError:payload={}
            result.update(clean_json(payload))
        return result

    def ioc_detail(self, ioc_id):
        item=self.get_record("iocs","ioc_id",ioc_id)
        if not item:return None
        with self.db.read_session() as c:
            item["events"]=[dict(r) for r in c.execute("SELECT e.id AS event_id,e.timestamp,e.source_type,e.host,e.user,e.src_ip,e.dst_ip,e.event_type FROM ioc_events x JOIN events e ON e.id=x.event_id WHERE x.ioc_id=? ORDER BY e.timestamp DESC,e.id LIMIT 100",(ioc_id,))]
            item["detections"]=[dict(r) for r in c.execute("SELECT a.alert_id,a.timestamp,a.severity,a.status,json_extract(a.payload,'$.rule_id') AS rule_id FROM ioc_detection_links x JOIN alerts a ON a.alert_id=x.detection_id WHERE x.ioc_id=? ORDER BY a.timestamp DESC,a.alert_id LIMIT 100",(ioc_id,))]
            item["incidents"]=[dict(r) for r in c.execute("SELECT i.incident_id,json_extract(i.payload,'$.title') AS title,i.status,i.severity,i.risk_score FROM incident_iocs x JOIN incidents i ON i.incident_id=x.incident_id WHERE x.ioc_id=? ORDER BY i.updated_at DESC,i.incident_id LIMIT 100",(ioc_id,))]
            item["occurrence_count"]=c.execute("SELECT COUNT(*) FROM ioc_events WHERE ioc_id=?",(ioc_id,)).fetchone()[0]
        return clean_json(item)

    def list_investigations(self, *, limit=50, offset=0):
        limit,offset=self.page_values(limit,offset)
        with self.db.read_session() as c:
            total=c.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
            rows=c.execute("SELECT investigation_id,incident_id,status,provider,model,run_number,deterministic_confidence,ai_confidence,confidence_warning,ai_unavailable,evidence_hash,started_at,completed_at,result_json FROM investigations ORDER BY started_at DESC,run_number DESC,investigation_id DESC LIMIT ? OFFSET ?",(limit,offset)).fetchall()
        return {"items":[self._investigation(dict(r)) for r in rows],"total":total,"limit":limit,"offset":offset}

    def list_attack_mappings(self, *, technique_id=None, tactic=None, limit=50, offset=0):
        limit,offset=self.page_values(limit,offset);clauses=[];params=[]
        if technique_id:clauses.append("m.technique_id=?");params.append(technique_id)
        where=" WHERE "+" AND ".join(clauses) if clauses else ""
        with self.db.read_session() as c:
            base=" FROM attack_mappings m JOIN alerts a ON a.alert_id=m.detection_id"
            rows=c.execute("SELECT m.id,m.detection_id,m.technique_id,m.technique_name,m.tactic_ids,m.mapping_source,m.confidence,m.evidence_ids,m.baseline_techniques,m.baseline_disagreement,a.timestamp,a.severity"+base+where+" ORDER BY m.technique_id,m.detection_id LIMIT ? OFFSET ?",(*params,limit,offset)).fetchall()
            if tactic:
                rows=[r for r in rows if tactic in (json.loads(r["tactic_ids"] or "[]") if isinstance(r["tactic_ids"],str) else r["tactic_ids"])]
                total=len(rows)
            else:total=c.execute("SELECT COUNT(*)"+base+where,params).fetchone()[0]
        items=[]
        for row in rows:
            item=dict(row)
            for field in ("tactic_ids","evidence_ids","baseline_techniques"):
                try:item[field]=json.loads(item[field] or "[]")
                except (ValueError,TypeError):item[field]=[]
            items.append(item)
        return {"items":clean_json(items),"total":total,"limit":limit,"offset":offset}

    def dashboard_summary(self):
        with self.db.read_session() as c:
            active=c.execute("SELECT COUNT(*) FROM incidents WHERE lower(status) NOT IN ('resolved','closed','false_positive')").fetchone()[0]
            critical=c.execute("SELECT COUNT(*) FROM incidents WHERE upper(severity)='CRITICAL' AND lower(status) NOT IN ('resolved','closed','false_positive')").fetchone()[0]
            high_alerts=c.execute("SELECT COUNT(*) FROM alerts WHERE upper(severity)='HIGH'").fetchone()[0]
            unresolved=c.execute("SELECT COUNT(*) FROM alerts WHERE upper(status) NOT IN ('RESOLVED','SUPPRESSED','CLOSED')").fetchone()[0]
            since=(datetime.now(timezone.utc)-__import__('datetime').timedelta(days=7)).isoformat()
            recent_investigations=c.execute("SELECT COUNT(*) FROM investigations WHERE started_at>=?",(since,)).fetchone()[0]
            iocs=c.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
            detections=c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        return {"active_incidents":active,"critical_incidents":critical,"high_severity_alerts":high_alerts,
                "unresolved_alerts":unresolved,"recent_investigations":recent_investigations,"ioc_count":iocs,"detection_count":detections}

    def dashboard_trends(self, *, days=14):
        days=max(1,min(int(days),90));cutoff=(datetime.now(timezone.utc)-__import__('datetime').timedelta(days=days-1)).date().isoformat()
        with self.db.read_session() as c:
            severity=[dict(r) for r in c.execute("SELECT upper(severity) AS severity,COUNT(*) AS count FROM alerts GROUP BY upper(severity) ORDER BY severity")]
            alert_activity=[dict(r) for r in c.execute("SELECT substr(timestamp,1,10) AS date,COUNT(*) AS count FROM alerts WHERE timestamp>=? GROUP BY substr(timestamp,1,10) ORDER BY date",(cutoff,))]
            incident_activity=[dict(r) for r in c.execute("SELECT substr(created_at,1,10) AS date,COUNT(*) AS count FROM incidents WHERE created_at>=? GROUP BY substr(created_at,1,10) ORDER BY date",(cutoff,))]
            top_sources={"source_ip":[dict(r) for r in c.execute("SELECT json_extract(payload,'$.source_ip') AS value,COUNT(*) AS count FROM alerts WHERE json_extract(payload,'$.source_ip') IS NOT NULL GROUP BY value ORDER BY count DESC,value LIMIT 5")],
                "user":[dict(r) for r in c.execute("SELECT json_extract(payload,'$.username') AS value,COUNT(*) AS count FROM alerts WHERE json_extract(payload,'$.username') IS NOT NULL GROUP BY value ORDER BY count DESC,value LIMIT 5")],
                "host":[dict(r) for r in c.execute("SELECT json_extract(payload,'$.hostname') AS value,COUNT(*) AS count FROM alerts WHERE json_extract(payload,'$.hostname') IS NOT NULL GROUP BY value ORDER BY count DESC,value LIMIT 5")],
                "rule":[dict(r) for r in c.execute("SELECT json_extract(payload,'$.rule_id') AS value,COUNT(*) AS count FROM alerts WHERE json_extract(payload,'$.rule_id') IS NOT NULL GROUP BY value ORDER BY count DESC,value LIMIT 5")]}
        return {"days":days,"severity_distribution":severity,"alert_activity":alert_activity,"incident_activity":incident_activity,"top_sources":clean_json(top_sources)}

    def dashboard_activity(self, *, kind=None, severity=None, since=None, limit=50, offset=0):
        since=self.timestamp(since);limit,offset=self.page_values(limit,offset)
        sources=[]
        if kind in (None,"detection"):
            sources.append(("SELECT alert_id AS id,timestamp,'detection' AS kind,severity,json_extract(payload,'$.title') AS title FROM alerts",[]))
        if kind in (None,"incident"):
            sources.append(("SELECT incident_id AS id,created_at AS timestamp,'incident' AS kind,severity,json_extract(payload,'$.title') AS title FROM incidents",[]))
        if kind in (None,"investigation"):
            sources.append(("SELECT investigation_id AS id,started_at AS timestamp,'investigation' AS kind,NULL AS severity,'Investigation run '||run_number AS title FROM investigations",[]))
        if not sources: raise ValueError("kind must be detection, incident, or investigation")
        union=" UNION ALL ".join(sql for sql,_ in sources);clauses=[];params=[]
        if since:clauses.append("timestamp>=?");params.append(since)
        if severity:clauses.append("upper(severity)=?");params.append(severity.upper())
        where=" WHERE "+" AND ".join(clauses) if clauses else ""
        with self.db.read_session() as c:
            total=c.execute("SELECT COUNT(*) FROM ("+union+")"+where,params).fetchone()[0]
            rows=c.execute("SELECT * FROM ("+union+")"+where+" ORDER BY timestamp DESC,id DESC LIMIT ? OFFSET ?",(*params,limit,offset)).fetchall()
            items=[{**dict(r),"title":clean(r["title"] or r["id"],limit=500)} for r in rows]
        return {"items":items,"total":total,"limit":limit,"offset":offset}

    def search(self, query, *, limit=10):
        query=str(query or "").strip()
        if len(query)<2:raise ValueError("query must contain at least 2 characters")
        if len(query)>120:raise ValueError("query must be at most 120 characters")
        limit=max(1,min(int(limit),20));term=self._like(query)
        with self.db.read_session() as c:
            incidents=[dict(r) for r in c.execute("SELECT incident_id,title,status,severity,risk_score FROM (SELECT incident_id,json_extract(payload,'$.title') AS title,status,severity,risk_score FROM incidents) WHERE incident_id LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\' ORDER BY incident_id DESC LIMIT ?",(term,term,limit))]
            alerts=[dict(r) for r in c.execute("SELECT alert_id,timestamp,severity,status,json_extract(payload,'$.rule_id') AS rule_id,json_extract(payload,'$.hostname') AS host,json_extract(payload,'$.username') AS user FROM alerts WHERE alert_id LIKE ? ESCAPE '\\' OR payload LIKE ? ESCAPE '\\' ORDER BY timestamp DESC,alert_id LIMIT ?",(term,term,limit))]
            iocs=[dict(r) for r in c.execute("SELECT ioc_id,value,type,first_seen,last_seen FROM iocs WHERE ioc_id LIKE ? ESCAPE '\\' OR value LIKE ? ESCAPE '\\' ORDER BY last_seen DESC,ioc_id LIMIT ?",(term,term,limit))]
        return {"query":clean(query,limit=120),"incidents":clean_json(incidents),"alerts":clean_json(alerts),"iocs":clean_json(iocs)}
