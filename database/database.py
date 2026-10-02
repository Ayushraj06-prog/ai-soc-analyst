"""Small SQLite connection and schema manager using only the standard library."""
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

MIGRATIONS = {
    1: """
CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, severity TEXT NOT NULL,
  payload TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'NEW'
);
CREATE TABLE IF NOT EXISTS incidents (
  incident_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  status TEXT NOT NULL, severity TEXT NOT NULL, risk_score INTEGER NOT NULL,
  payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS iocs (
  ioc_id TEXT PRIMARY KEY, value TEXT NOT NULL, type TEXT NOT NULL,
  first_seen TEXT, last_seen TEXT, payload TEXT NOT NULL, UNIQUE(value, type)
);
CREATE TABLE IF NOT EXISTS assets (
  asset_id TEXT PRIMARY KEY, hostname TEXT NOT NULL UNIQUE, criticality TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS analysts (
  user_id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  audit_id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
  actor TEXT, action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT, details TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id);
""",
    2: """
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source_type TEXT, host TEXT, user TEXT,
  src_ip TEXT, dst_ip TEXT, event_type TEXT, raw TEXT NOT NULL,
  raw_ref TEXT, ingest_batch_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
CREATE TABLE IF NOT EXISTS evidence_links (
  incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
  event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  PRIMARY KEY(incident_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_evidence_event ON evidence_links(event_id);
CREATE TABLE IF NOT EXISTS ingest_batches (
  id TEXT PRIMARY KEY, source_file TEXT NOT NULL, file_hash TEXT NOT NULL,
  started_at TEXT NOT NULL, event_count INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL, errors_count INTEGER NOT NULL DEFAULT 0,
  errors_json TEXT NOT NULL DEFAULT '[]', UNIQUE(source_file, file_hash)
);
""",
    3: """
CREATE TRIGGER IF NOT EXISTS trg_events_ingest_batch_insert
BEFORE INSERT ON events
WHEN NEW.ingest_batch_id IS NULL OR NOT EXISTS (
  SELECT 1 FROM ingest_batches WHERE id = NEW.ingest_batch_id
)
BEGIN SELECT RAISE(ABORT, 'unknown ingest_batch_id'); END;
CREATE TRIGGER IF NOT EXISTS trg_events_ingest_batch_update
BEFORE UPDATE OF ingest_batch_id ON events
WHEN NEW.ingest_batch_id IS NULL OR NOT EXISTS (
  SELECT 1 FROM ingest_batches WHERE id = NEW.ingest_batch_id
)
BEGIN SELECT RAISE(ABORT, 'unknown ingest_batch_id'); END;
CREATE TABLE IF NOT EXISTS evidence_refs (
  owner_type TEXT NOT NULL, owner_id TEXT NOT NULL,
  evidence_type TEXT NOT NULL, evidence_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY(owner_type, owner_id, evidence_type, evidence_id)
);
INSERT OR IGNORE INTO evidence_refs(owner_type,owner_id,evidence_type,evidence_id)
SELECT 'INCIDENT', incident_id, 'EVENT', event_id FROM evidence_links;
CREATE INDEX IF NOT EXISTS idx_evidence_refs_target ON evidence_refs(evidence_type, evidence_id);
""",
    4: """
ALTER TABLE ingest_batches ADD COLUMN events_created INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ingest_batches ADD COLUMN events_duplicate INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ingest_batches ADD COLUMN events_invalid INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ingest_batches ADD COLUMN parse_error_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ingest_batches ADD COLUMN error_summary TEXT NOT NULL DEFAULT '';
UPDATE ingest_batches SET status = CASE UPPER(status)
  WHEN 'COMPLETED' THEN 'completed'
  WHEN 'PARTIAL' THEN 'completed_with_errors'
  WHEN 'FAILED' THEN 'failed'
  WHEN 'RUNNING' THEN 'running'
  ELSE LOWER(status)
END;
UPDATE ingest_batches SET parse_error_count=errors_count,
  events_created=event_count,
  error_summary=CASE WHEN errors_json='[]' THEN '' ELSE substr(errors_json, 1, 1000) END;
""",
    5: """
CREATE INDEX IF NOT EXISTS idx_events_type_timestamp ON events(event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src_timestamp ON events(src_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_user_timestamp ON events(user, timestamp);
CREATE TABLE IF NOT EXISTS rule_executions (
  id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, executed_at TEXT NOT NULL,
  batch_id TEXT, since_timestamp TEXT, events_evaluated INTEGER NOT NULL DEFAULT 0,
  detections_created INTEGER NOT NULL DEFAULT 0, detections_suppressed INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL, errors TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_rule_executions_rule_time ON rule_executions(rule_id, executed_at);
CREATE TABLE IF NOT EXISTS suppressed_detections (
  id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, grouping_key TEXT NOT NULL,
  reason TEXT NOT NULL, timestamp TEXT NOT NULL, evidence_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_suppressed_rule_time ON suppressed_detections(rule_id, timestamp);
""",
    6: """
ALTER TABLE iocs ADD COLUMN normalized_value TEXT;
ALTER TABLE iocs ADD COLUMN classification TEXT;
ALTER TABLE iocs ADD COLUMN confidence REAL NOT NULL DEFAULT 0;
ALTER TABLE iocs ADD COLUMN occurrence_count INTEGER NOT NULL DEFAULT 0;
UPDATE iocs SET normalized_value=lower(trim(value)) WHERE normalized_value IS NULL;
CREATE INDEX IF NOT EXISTS idx_iocs_type_normalized ON iocs(type, normalized_value);
CREATE TABLE IF NOT EXISTS ioc_events (
  ioc_id TEXT NOT NULL REFERENCES iocs(ioc_id) ON DELETE CASCADE,
  event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  source_field TEXT NOT NULL, confidence REAL NOT NULL CHECK(confidence >= 0 AND confidence <= 1),
  PRIMARY KEY(ioc_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_ioc_events_event ON ioc_events(event_id);
CREATE INDEX IF NOT EXISTS idx_ioc_events_ioc ON ioc_events(ioc_id);
CREATE TABLE IF NOT EXISTS ioc_detection_links (
  ioc_id TEXT NOT NULL REFERENCES iocs(ioc_id) ON DELETE CASCADE,
  detection_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
  relationship_type TEXT NOT NULL CHECK(relationship_type IN ('source_of','destination_of','observed_in')),
  PRIMARY KEY(ioc_id, detection_id, relationship_type)
);
CREATE INDEX IF NOT EXISTS idx_ioc_detection_detection ON ioc_detection_links(detection_id);
CREATE INDEX IF NOT EXISTS idx_ioc_detection_ioc ON ioc_detection_links(ioc_id);
CREATE TABLE IF NOT EXISTS attack_mappings (
  id TEXT PRIMARY KEY, detection_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
  technique_id TEXT NOT NULL, technique_name TEXT NOT NULL, tactic_ids TEXT NOT NULL,
  attack_version TEXT NOT NULL, mapping_source TEXT NOT NULL, confidence REAL NOT NULL,
  evidence_ids TEXT NOT NULL, baseline_techniques TEXT NOT NULL DEFAULT '[]',
  baseline_disagreement INTEGER NOT NULL DEFAULT 0,
  UNIQUE(detection_id, technique_id, mapping_source)
);
CREATE INDEX IF NOT EXISTS idx_attack_mappings_detection ON attack_mappings(detection_id);
CREATE INDEX IF NOT EXISTS idx_attack_mappings_technique ON attack_mappings(technique_id);
CREATE TABLE IF NOT EXISTS enrichment_state (
  event_id TEXT PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
  enriched_at TEXT NOT NULL, status TEXT NOT NULL,
  ioc_count INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_enrichment_state_status ON enrichment_state(status);
""",
    7: """
CREATE TABLE IF NOT EXISTS incident_detections (
  incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
  detection_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
  PRIMARY KEY(incident_id, detection_id), UNIQUE(detection_id)
);
CREATE INDEX IF NOT EXISTS idx_incident_detections_detection ON incident_detections(detection_id);
CREATE TABLE IF NOT EXISTS incident_events (
  incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
  event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  PRIMARY KEY(incident_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_incident_events_event ON incident_events(event_id);
CREATE TABLE IF NOT EXISTS incident_iocs (
  incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
  ioc_id TEXT NOT NULL REFERENCES iocs(ioc_id) ON DELETE CASCADE,
  PRIMARY KEY(incident_id, ioc_id)
);
CREATE TABLE IF NOT EXISTS incident_attack_mappings (
  incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
  mapping_id TEXT NOT NULL REFERENCES attack_mappings(id) ON DELETE CASCADE,
  PRIMARY KEY(incident_id, mapping_id)
);
CREATE TABLE IF NOT EXISTS correlation_edges (
  rule_id TEXT NOT NULL, source_detection_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
  target_detection_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
  matched_at TEXT NOT NULL, explanation TEXT NOT NULL, rule_version TEXT NOT NULL,
  config_hash TEXT NOT NULL, execution_id TEXT NOT NULL,
  PRIMARY KEY(rule_id, source_detection_id, target_detection_id, rule_version, config_hash)
);
CREATE INDEX IF NOT EXISTS idx_correlation_edges_source ON correlation_edges(source_detection_id);
CREATE INDEX IF NOT EXISTS idx_correlation_edges_target ON correlation_edges(target_detection_id);
CREATE TABLE IF NOT EXISTS correlation_executions (
  execution_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, completed_at TEXT NOT NULL,
  status TEXT NOT NULL, candidate_count INTEGER NOT NULL, edge_count INTEGER NOT NULL,
  incident_created INTEGER NOT NULL, incident_updated INTEGER NOT NULL,
  incident_merged INTEGER NOT NULL, suppressed_count INTEGER NOT NULL, error_count INTEGER NOT NULL,
  config_hash TEXT NOT NULL, rule_version TEXT NOT NULL, errors TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS incident_merge_history (
  id TEXT PRIMARY KEY, losing_incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
  surviving_incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
  execution_id TEXT NOT NULL REFERENCES correlation_executions(execution_id),
  merged_at TEXT NOT NULL, details TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS correlation_suppressions (
  id TEXT PRIMARY KEY, execution_id TEXT NOT NULL, key_type TEXT NOT NULL,
  key_value TEXT NOT NULL, reason TEXT NOT NULL, detection_count INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS correlation_state (
  key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS detection_keys (
  detection_id TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
  key_type TEXT NOT NULL, key_value TEXT NOT NULL, timestamp TEXT NOT NULL,
  PRIMARY KEY(detection_id, key_type, key_value)
);
CREATE INDEX IF NOT EXISTS idx_detection_keys_lookup ON detection_keys(key_type,key_value,timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity_timestamp ON alerts(severity,timestamp);
""",
    8: """
CREATE TABLE IF NOT EXISTS investigations (
  investigation_id TEXT PRIMARY KEY,
  investigation_key TEXT NOT NULL,
  run_number INTEGER NOT NULL CHECK(run_number > 0),
  incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
  status TEXT NOT NULL CHECK(status IN ('running','completed','failed','invalid','stale')),
  provider TEXT NOT NULL, model TEXT NOT NULL,
  prompt_version TEXT NOT NULL, prompt_template_hash TEXT NOT NULL,
  generation_config_hash TEXT NOT NULL, generation_config_json TEXT NOT NULL,
  prompt_schema_version TEXT NOT NULL, evidence_hash TEXT NOT NULL,
  packet_json TEXT NOT NULL, alias_map_json TEXT NOT NULL,
  result_json TEXT NOT NULL DEFAULT '{}',
  deterministic_confidence TEXT NOT NULL DEFAULT 'low', ai_confidence TEXT NOT NULL DEFAULT 'low',
  confidence_warning INTEGER NOT NULL DEFAULT 0,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  validation_errors TEXT NOT NULL DEFAULT '[]', last_error TEXT NOT NULL DEFAULT '',
  raw_output_hash TEXT, raw_output_excerpt TEXT,
  ai_unavailable INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL DEFAULT 'system',
  started_at TEXT NOT NULL, completed_at TEXT,
  UNIQUE(investigation_key,run_number)
);
CREATE INDEX IF NOT EXISTS idx_investigations_incident ON investigations(incident_id,started_at);
CREATE INDEX IF NOT EXISTS idx_investigations_key_status ON investigations(investigation_key,status,run_number);
CREATE TABLE IF NOT EXISTS investigation_attempts (
  attempt_id TEXT PRIMARY KEY,
  investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
  attempt_number INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('running','completed','failed','invalid')),
  started_at TEXT NOT NULL, completed_at TEXT,
  validation_errors TEXT NOT NULL DEFAULT '[]', error TEXT NOT NULL DEFAULT '',
  raw_output_hash TEXT, raw_output_excerpt TEXT,
  UNIQUE(investigation_id,attempt_number)
);
CREATE INDEX IF NOT EXISTS idx_investigation_attempts_run ON investigation_attempts(investigation_id,attempt_number);
CREATE TABLE IF NOT EXISTS investigation_evidence (
  id TEXT PRIMARY KEY,
  investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
  finding_id TEXT,
  finding_category TEXT NOT NULL,
  evidence_type TEXT NOT NULL,
  evidence_id TEXT NOT NULL,
  relationship TEXT NOT NULL,
  basis TEXT NOT NULL DEFAULT '', confidence TEXT NOT NULL DEFAULT '',
  priority TEXT NOT NULL DEFAULT '', action_type TEXT NOT NULL DEFAULT '',
  UNIQUE(investigation_id,finding_id,finding_category,evidence_type,evidence_id,relationship)
);
CREATE INDEX IF NOT EXISTS idx_investigation_evidence_run ON investigation_evidence(investigation_id);
CREATE INDEX IF NOT EXISTS idx_investigation_evidence_target ON investigation_evidence(evidence_type,evidence_id);
""",
    9: """
CREATE TABLE IF NOT EXISTS response_actions (
  action_id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE RESTRICT,
  action_type TEXT NOT NULL CHECK(action_type IN ('simulate_block_ip','simulate_disable_account','collect_evidence','increase_monitoring','create_case_note','mark_incident_reviewed')),
  target TEXT, target_type TEXT,
  parameters_json TEXT NOT NULL DEFAULT '{}' CHECK(length(parameters_json)<=16384 AND json_valid(parameters_json)),
  policy_rule_id TEXT NOT NULL, policy_version TEXT NOT NULL,
  playbook_id TEXT, playbook_version TEXT,
  approval_state TEXT NOT NULL CHECK(approval_state IN ('not_required','pending','approved','rejected','expired')),
  execution_state TEXT NOT NULL CHECK(execution_state IN ('not_started','executing','simulated','failed','rolled_back','cancelled','blocked_by_policy','superseded')),
  verification_state TEXT NOT NULL CHECK(verification_state IN ('not_verified','simulated','failed','unknown')),
  execution_mode TEXT NOT NULL CHECK(execution_mode='simulation'),
  approval_binding_hash TEXT NOT NULL,
  approval_required INTEGER NOT NULL CHECK(approval_required IN (0,1)),
  requested_by TEXT NOT NULL, approved_by TEXT, approved_at TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, expires_at TEXT,
  revision INTEGER NOT NULL CHECK(revision>0), supersedes TEXT REFERENCES response_actions(action_id) ON DELETE RESTRICT,
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK(length(metadata_json)<=16384 AND json_valid(metadata_json)),
  result_json TEXT NOT NULL DEFAULT '{}' CHECK(length(result_json)<=32768 AND json_valid(result_json)),
  UNIQUE(incident_id,action_type,action_id),
  CHECK((approval_state='approved' AND approved_by IS NOT NULL AND approved_at IS NOT NULL) OR approval_state!='approved')
);
CREATE INDEX IF NOT EXISTS idx_response_incident ON response_actions(incident_id,created_at);
CREATE INDEX IF NOT EXISTS idx_response_state ON response_actions(approval_state,execution_state,updated_at);
CREATE INDEX IF NOT EXISTS idx_response_supersedes ON response_actions(supersedes);
CREATE TABLE IF NOT EXISTS response_action_evidence (
  action_id TEXT NOT NULL REFERENCES response_actions(action_id) ON DELETE RESTRICT,
  evidence_type TEXT NOT NULL CHECK(evidence_type IN ('EVENT','DETECTION','IOC')),
  evidence_id TEXT NOT NULL,
  PRIMARY KEY(action_id,evidence_type,evidence_id)
);
CREATE INDEX IF NOT EXISTS idx_response_evidence_identity ON response_action_evidence(evidence_type,evidence_id);
CREATE TRIGGER IF NOT EXISTS trg_response_evidence_validate
BEFORE INSERT ON response_action_evidence
WHEN (NEW.evidence_type='EVENT' AND NOT EXISTS(SELECT 1 FROM events WHERE id=NEW.evidence_id))
  OR (NEW.evidence_type='DETECTION' AND NOT EXISTS(SELECT 1 FROM alerts WHERE alert_id=NEW.evidence_id))
  OR (NEW.evidence_type='IOC' AND NOT EXISTS(SELECT 1 FROM iocs WHERE ioc_id=NEW.evidence_id))
BEGIN SELECT RAISE(ABORT,'response evidence does not exist'); END;
CREATE TRIGGER IF NOT EXISTS trg_response_event_restrict
BEFORE DELETE ON events WHEN EXISTS(SELECT 1 FROM response_action_evidence WHERE evidence_type='EVENT' AND evidence_id=OLD.id)
BEGIN SELECT RAISE(ABORT,'response evidence is restricted'); END;
CREATE TRIGGER IF NOT EXISTS trg_response_detection_restrict
BEFORE DELETE ON alerts WHEN EXISTS(SELECT 1 FROM response_action_evidence WHERE evidence_type='DETECTION' AND evidence_id=OLD.alert_id)
BEGIN SELECT RAISE(ABORT,'response evidence is restricted'); END;
CREATE TRIGGER IF NOT EXISTS trg_response_ioc_restrict
BEFORE DELETE ON iocs WHEN EXISTS(SELECT 1 FROM response_action_evidence WHERE evidence_type='IOC' AND evidence_id=OLD.ioc_id)
BEGIN SELECT RAISE(ABORT,'response evidence is restricted'); END;
CREATE TABLE IF NOT EXISTS execution_attempts (
  attempt_id TEXT PRIMARY KEY,
  action_id TEXT NOT NULL REFERENCES response_actions(action_id) ON DELETE RESTRICT,
  attempt_number INTEGER NOT NULL CHECK(attempt_number>0),
  execution_mode TEXT NOT NULL CHECK(execution_mode='simulation'),
  started_at TEXT NOT NULL, completed_at TEXT,
  result TEXT NOT NULL DEFAULT '{}' CHECK(length(result)<=32768 AND json_valid(result)), error TEXT NOT NULL DEFAULT '' CHECK(length(error)<=1000),
  status TEXT NOT NULL CHECK(status IN ('executing','simulated','failed','rolled_back')),
  UNIQUE(action_id,attempt_number)
);
CREATE INDEX IF NOT EXISTS idx_response_attempts_action ON execution_attempts(action_id,attempt_number);
CREATE TRIGGER IF NOT EXISTS trg_response_action_immutable
BEFORE UPDATE OF incident_id,action_type,target,target_type,parameters_json,policy_rule_id,policy_version,playbook_id,playbook_version,execution_mode,approval_binding_hash,revision,supersedes,requested_by,created_at,metadata_json ON response_actions
BEGIN SELECT RAISE(ABORT,'response proposal fields are immutable; create a revision'); END;
CREATE TRIGGER IF NOT EXISTS trg_response_action_delete
BEFORE DELETE ON response_actions
BEGIN SELECT RAISE(ABORT,'response actions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_response_evidence_update
BEFORE UPDATE ON response_action_evidence
BEGIN SELECT RAISE(ABORT,'response action evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_response_evidence_delete
BEFORE DELETE ON response_action_evidence
BEGIN SELECT RAISE(ABORT,'response action evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_response_audit_update
BEFORE UPDATE ON audit_log WHEN OLD.entity_type='response_action'
BEGIN SELECT RAISE(ABORT,'response audit records are immutable'); END;
CREATE TRIGGER IF NOT EXISTS trg_response_audit_delete
BEFORE DELETE ON audit_log WHEN OLD.entity_type='response_action'
BEGIN SELECT RAISE(ABORT,'response audit records are immutable'); END;
""",
}


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def read_connect(self) -> sqlite3.Connection:
        """Open an existing database read-only without initializing or changing PRAGMAs."""
        uri = self.path.resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def read_session(self):
        connection = self.read_connect()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def session(self):
        """Commit successful operations and always close the connection."""
        connection = self.connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        self.migrate()

    def migrate(self) -> None:
        """Apply each unapplied numbered migration atomically and record its version."""
        with self.session() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
            applied = {row[0] for row in connection.execute("SELECT version FROM schema_version")}
            for version, sql in sorted(MIGRATIONS.items()):
                if version in applied:
                    continue
                connection.executescript(
                    "BEGIN IMMEDIATE;\n" + sql +
                    f"\nINSERT INTO schema_version(version, applied_at) VALUES({version}, datetime('now'));\nCOMMIT;"
                )

    def current_version(self) -> int:
        if not self.path.exists():
            return 0
        with self.read_session() as connection:
            exists = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'").fetchone()
            if not exists:
                return 0
            return connection.execute("SELECT COALESCE(MAX(version), 0) FROM schema_version").fetchone()[0]

    @staticmethod
    def encode(payload: dict[str, Any]) -> str:
        return json.dumps(payload, default=str, separators=(",", ":"))
