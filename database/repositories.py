"""JSON-payload repositories with parameterized SQLite statements."""
from __future__ import annotations
import json
import hashlib
from typing import Any
from pathlib import Path

from database.database import Database
from models.event import SecurityEvent
from app.config import settings


class Repository:
    def __init__(self, database: Database, table: str, key: str):
        self.database, self.table, self.key = database, table, key

    def get(self, entity_id: str) -> dict[str, Any] | None:
        with self.database.session() as connection:
            row = connection.execute(f"SELECT payload FROM {self.table} WHERE {self.key} = ?", (entity_id,)).fetchone()
        return json.loads(row["payload"]) if row else None

    def list(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        with self.database.session() as connection:
            rows = connection.execute(f"SELECT payload FROM {self.table} ORDER BY rowid DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(row["payload"]) for row in rows]


class AlertRepository(Repository):
    def __init__(self, database: Database): super().__init__(database, "alerts", "alert_id")

    def save(self, payload: dict[str, Any]) -> bool:
        with self.database.session() as connection:
            created = connection.execute("SELECT 1 FROM alerts WHERE alert_id=?", (payload["alert_id"],)).fetchone() is None
            connection.execute("INSERT OR REPLACE INTO alerts(alert_id,timestamp,severity,payload,status) VALUES(?,?,?,?,?)",
                (payload["alert_id"], payload["timestamp"], payload["severity"], self.database.encode(payload), payload.get("status", "NEW")))
        return created


class IncidentRepository(Repository):
    def __init__(self, database: Database): super().__init__(database, "incidents", "incident_id")

    def save(self, payload: dict[str, Any]) -> None:
        with self.database.session() as connection:
            connection.execute("INSERT OR REPLACE INTO incidents(incident_id,created_at,updated_at,status,severity,risk_score,payload) VALUES(?,?,?,?,?,?,?)",
                (payload["incident_id"], payload["created_at"], payload["updated_at"], payload["status"], payload["severity"], payload["risk_score"], self.database.encode(payload)))


class IOCRepository(Repository):
    def __init__(self, database: Database): super().__init__(database, "iocs", "ioc_id")

    def save(self, payload: dict[str, Any]) -> None:
        with self.database.session() as connection:
            connection.execute("INSERT INTO iocs(ioc_id,value,type,first_seen,last_seen,payload) VALUES(?,?,?,?,?,?) ON CONFLICT(value,type) DO UPDATE SET last_seen=excluded.last_seen,payload=excluded.payload",
                (payload["ioc_id"], payload["value"], payload["type"], payload.get("first_seen"), payload.get("last_seen"), self.database.encode(payload)))

    def count(self) -> int:
        with self.database.session() as connection:
            return connection.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]


class EventRepository:
    def __init__(self, database: Database): self.database = database

    def save(self, event: SecurityEvent | dict[str, Any]) -> None:
        payload = event.to_dict() if isinstance(event, SecurityEvent) else event
        self.save_many([payload])

    def save_many(self, events: list[SecurityEvent | dict[str, Any]]) -> tuple[int, int]:
        """Insert a chunk in one transaction; return created and duplicate counts."""
        created = 0
        duplicates = 0
        rows = []
        for event in events:
            payload = event.to_dict() if isinstance(event, SecurityEvent) else event
            if not payload.get("ingest_batch_id"):
                raise ValueError("Persisted events must reference an ingestion batch")
            rows.append((payload["event_id"], payload["timestamp"], payload.get("source_type") or payload.get("source"),
                payload.get("hostname"), payload.get("username"), payload.get("source_ip"),
                payload.get("destination_ip"), payload.get("event_type"),
                self.database.encode({"raw_event": payload.get("raw_event"), "event": payload}),
                payload.get("raw_ref"), payload.get("ingest_batch_id")))
        with self.database.session() as connection:
            for row in rows:
                cursor = connection.execute("""INSERT OR IGNORE INTO events
                    (id,timestamp,source_type,host,user,src_ip,dst_ip,event_type,raw,raw_ref,ingest_batch_id)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?)""", row)
                if cursor.rowcount:
                    created += 1
                else:
                    duplicates += 1
        return created, duplicates

    def get(self, event_id: str) -> dict[str, Any] | None:
        with self.database.session() as connection:
            row = connection.execute("SELECT raw FROM events WHERE id=?", (event_id,)).fetchone()
        return json.loads(row["raw"])["event"] if row else None

    def list(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        with self.database.session() as connection:
            rows = connection.execute("SELECT raw FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(row["raw"])["event"] for row in rows]

    def query(self, since: str | None = None, batch_id: str | None = None) -> list[dict[str, Any]]:
        clauses, params = [], []
        if since is not None:
            clauses.append("timestamp >= ?"); params.append(since)
        if batch_id is not None:
            clauses.append("ingest_batch_id = ?"); params.append(batch_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.database.session() as connection:
            rows = connection.execute("SELECT raw FROM events" + where + " ORDER BY timestamp,id", params).fetchall()
        return [json.loads(row["raw"])["event"] for row in rows]


class AssetRepository(Repository):
    def __init__(self, database: Database): super().__init__(database, "assets", "asset_id")

    def save(self, payload: dict[str, Any]) -> None:
        with self.database.session() as connection:
            connection.execute("INSERT OR REPLACE INTO assets(asset_id,hostname,criticality,payload) VALUES(?,?,?,?)",
                (payload["asset_id"], payload["hostname"], payload["criticality"], self.database.encode(payload)))


class AnalystRepository(Repository):
    def __init__(self, database: Database): super().__init__(database, "analysts", "user_id")

    def save(self, payload: dict[str, Any]) -> None:
        with self.database.session() as connection:
            connection.execute("INSERT OR REPLACE INTO analysts(user_id,username,payload) VALUES(?,?,?)",
                (payload["user_id"], payload["username"], self.database.encode(payload)))


class IngestBatchRepository:
    def __init__(self, database: Database): self.database = database

    def save(self, batch: dict[str, Any]) -> None:
        status = str(batch.get("status", "running")).lower()
        legacy_status = {"partial": "completed_with_errors"}
        status = legacy_status.get(status, status)
        if status not in {"running", "completed", "completed_with_errors", "failed", "skipped_duplicate_file"}:
            raise ValueError("Invalid ingestion batch status")
        errors = batch.get("errors", [])[:max(0, settings.ingest_error_limit)]
        errors_json = self.database.encode(errors)
        error_summary = " | ".join(str(error)[:500] for error in errors)
        with self.database.session() as connection:
            connection.execute("""INSERT INTO ingest_batches
                (id,source_file,file_hash,started_at,event_count,status,errors_count,errors_json,
                 events_created,events_duplicate,events_invalid,parse_error_count,error_summary)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(source_file,file_hash) DO UPDATE SET
                status=excluded.status,
                event_count=CASE WHEN excluded.status='skipped_duplicate_file' THEN ingest_batches.event_count ELSE excluded.event_count END,
                errors_count=CASE WHEN excluded.status='skipped_duplicate_file' THEN ingest_batches.errors_count ELSE excluded.errors_count END,
                errors_json=CASE WHEN excluded.status='skipped_duplicate_file' THEN ingest_batches.errors_json ELSE excluded.errors_json END,
                events_created=CASE WHEN excluded.status='skipped_duplicate_file' THEN ingest_batches.events_created ELSE excluded.events_created END,
                events_duplicate=CASE WHEN excluded.status='skipped_duplicate_file' THEN ingest_batches.events_duplicate ELSE excluded.events_duplicate END,
                events_invalid=CASE WHEN excluded.status='skipped_duplicate_file' THEN ingest_batches.events_invalid ELSE excluded.events_invalid END,
                parse_error_count=CASE WHEN excluded.status='skipped_duplicate_file' THEN ingest_batches.parse_error_count ELSE excluded.parse_error_count END,
                error_summary=CASE WHEN excluded.status='skipped_duplicate_file' THEN ingest_batches.error_summary ELSE excluded.error_summary END""", (
                batch["id"], batch["source_file"], batch["file_hash"], batch["started_at"],
                batch.get("event_count", 0), status,
                batch.get("errors_count", len(batch.get("errors", []))), errors_json,
                batch.get("events_created", 0), batch.get("events_duplicate", 0),
                batch.get("events_invalid", 0), batch.get("parse_error_count", batch.get("errors_count", 0)), error_summary))

    def already_ingested(self, source_file: str, file_hash: str) -> bool:
        with self.database.session() as connection:
            return connection.execute("SELECT 1 FROM ingest_batches WHERE source_file=? AND file_hash=? AND status IN ('completed','skipped_duplicate_file')",
                                     (source_file, file_hash)).fetchone() is not None

    def get(self, batch_id: str) -> dict[str, Any] | None:
        with self.database.session() as connection:
            row = connection.execute("SELECT * FROM ingest_batches WHERE id=?", (batch_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["errors"] = json.loads(result.pop("errors_json"))
        return result

    @staticmethod
    def hash_file(path: str | Path) -> str:
        digest = hashlib.sha256()
        with Path(path).open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()


class EvidenceLinkRepository:
    def __init__(self, database: Database): self.database = database

    def link(self, incident_id: str, event_id: str) -> None:
        with self.database.session() as connection:
            connection.execute("INSERT OR IGNORE INTO evidence_links(incident_id,event_id) VALUES(?,?)", (incident_id, event_id))
            connection.execute("INSERT OR IGNORE INTO evidence_refs(owner_type,owner_id,evidence_type,evidence_id) VALUES('INCIDENT',?,'EVENT',?)", (incident_id, event_id))

    def link_reference(self, owner_type: str, owner_id: str, evidence_type: str, evidence_id: str) -> None:
        """Link any future owner/evidence entity pair through the extensible registry."""
        with self.database.session() as connection:
            connection.execute("INSERT OR IGNORE INTO evidence_refs(owner_type,owner_id,evidence_type,evidence_id) VALUES(?,?,?,?)",
                               (owner_type.upper(), owner_id, evidence_type.upper(), evidence_id))

    def references_for(self, owner_type: str, owner_id: str) -> list[dict[str, str]]:
        with self.database.session() as connection:
            rows = connection.execute("SELECT evidence_type,evidence_id FROM evidence_refs WHERE owner_type=? AND owner_id=? ORDER BY evidence_type,evidence_id", (owner_type.upper(), owner_id)).fetchall()
        return [{"evidence_type": row["evidence_type"], "evidence_id": row["evidence_id"]} for row in rows]

    def events_for_incident(self, incident_id: str) -> list[str]:
        with self.database.session() as connection:
            rows = connection.execute("SELECT event_id FROM evidence_links WHERE incident_id=? ORDER BY event_id", (incident_id,)).fetchall()
        return [row["event_id"] for row in rows]


class RuleExecutionRepository:
    def __init__(self, database: Database): self.database = database

    def record(self, rule_id, executed_at, batch_id, since, evaluated, created, suppressed, status, errors):
        run_id = __import__("models.ids", fromlist=["stable_id"]).stable_id(
            "run", rule_id, executed_at, batch_id, since)
        with self.database.session() as connection:
            connection.execute("""INSERT OR REPLACE INTO rule_executions
                (id,rule_id,executed_at,batch_id,since_timestamp,events_evaluated,detections_created,
                 detections_suppressed,status,errors) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (run_id, rule_id, executed_at, batch_id, since, evaluated, created, suppressed,
                 status, self.database.encode(errors)))

    def save_suppressed(self, row_id, rule_id, grouping_key, reason, timestamp, evidence):
        with self.database.session() as connection:
            connection.execute("""INSERT OR REPLACE INTO suppressed_detections
                (id,rule_id,grouping_key,reason,timestamp,evidence_json) VALUES(?,?,?,?,?,?)""",
                (row_id, rule_id, grouping_key, reason, timestamp, self.database.encode(evidence)))
