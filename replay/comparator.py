"""Normalize and compare deterministic SOC entity tables."""
import hashlib
import json
import sqlite3
from contextlib import closing

ENTITY_TABLES = {
    "events": "SELECT id,timestamp,source_type,host,user,src_ip,dst_ip,event_type,raw,raw_ref,ingest_batch_id FROM events ORDER BY id",
    "alerts": "SELECT alert_id,timestamp,severity,payload,status FROM alerts ORDER BY alert_id",
    "iocs": "SELECT ioc_id,value,type,normalized_value,classification,confidence,occurrence_count,payload FROM iocs ORDER BY ioc_id",
    "ioc_events": "SELECT ioc_id,event_id,source_field,confidence FROM ioc_events ORDER BY ioc_id,event_id",
    "attack_mappings": "SELECT id,detection_id,technique_id,technique_name,tactic_ids,attack_version,mapping_source,confidence,evidence_ids,baseline_techniques,baseline_disagreement FROM attack_mappings ORDER BY id",
    "incidents": "SELECT incident_id,status,severity,risk_score,payload FROM incidents ORDER BY incident_id",
    "incident_events": "SELECT incident_id,event_id FROM incident_events ORDER BY incident_id,event_id",
    "incident_detections": "SELECT incident_id,detection_id FROM incident_detections ORDER BY incident_id,detection_id",
    "incident_iocs": "SELECT incident_id,ioc_id FROM incident_iocs ORDER BY incident_id,ioc_id",
}


def _canonical(value):
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return json.dumps(parsed, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            return value
    return value


def _canonical_incident(value):
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return value
    if isinstance(parsed, dict):
        for key in ("correlation_execution_id", "last_correlated_at", "updated_at", "created_at"):
            parsed.pop(key, None)
    return json.dumps(parsed, sort_keys=True, separators=(",", ":"))


def table_hashes(path):
    result = {}
    with closing(sqlite3.connect(path)) as connection:
        for table, query in ENTITY_TABLES.items():
            rows = []
            for row in connection.execute(query):
                normalized = [_canonical(value) for value in row]
                if table == "incidents" and normalized:
                    normalized[-1] = _canonical_incident(row[-1])
                rows.append(normalized)
            result[table] = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return result


def compare(left, right):
    left_hashes = table_hashes(left)
    right_hashes = table_hashes(right)
    return {table: left_hashes[table] == right_hashes[table] for table in ENTITY_TABLES}
