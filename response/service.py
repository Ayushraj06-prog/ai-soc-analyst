"""Transactional Phase 9A response orchestration. All execution is simulation-only."""
import hashlib
import ipaddress
import json
import re
import sqlite3
import unicodedata
from datetime import datetime, timedelta, timezone

from app.config import settings
from database.database import Database
from models.ids import stable_id
from response.catalog import CATALOG, get_action
from response.executors import SimulationExecutor
from response.targets import canonical_target

_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BIDI = {"RLO", "LRO", "RLE", "LRE", "PDF", "RLI", "LRI", "FSI", "PDI"}
_POLICY = {"approval_state": {"pending": {"approved", "rejected", "expired"}},
           "execution_state": {"not_started": {"executing", "blocked_by_policy", "cancelled", "superseded"},
                               "executing": {"simulated", "failed", "blocked_by_policy"},
                               "simulated": {"rolled_back"}, "rolled_back": {"executing"}}}
_POLICY["verification_state"] = {"not_verified": {"simulated", "failed", "unknown"},
                                  "simulated": {"unknown","failed"}, "failed": {"unknown"}, "unknown": {"simulated","failed"}}


def sanitize(value, limit=1000):
    text = _ANSI.sub("", str(value or ""))
    text = "".join(ch for ch in text if _CONTROL.fullmatch(ch) is None and unicodedata.category(ch)!="Cc" and unicodedata.bidirectional(ch) not in _BIDI)
    return text[:limit]


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _digest(value):
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _bounded_json(value, depth=0):
    if depth>5: return "[TRUNCATED]"
    if value is None or isinstance(value,(bool,int,float)): return value
    if isinstance(value,str): return sanitize(value,1000)
    if isinstance(value,list): return [_bounded_json(item,depth+1) for item in value[:100]]
    if isinstance(value,dict):
        result={}
        for key,item in list(value.items())[:100]:
            safe_key=sanitize(key,80)
            if not safe_key or re.search(r"(?i)password|passwd|secret|token|api[_-]?key|authorization",safe_key): continue
            result[safe_key]=_bounded_json(item,depth+1)
        return result
    raise ValueError("parameters must contain JSON-compatible values")


PLAYBOOK_REGISTRY = [
    {
        "id": "brute_force_response",
        "version": "1",
        "name": "Brute-force containment",
        "description": "Simulated containment for repeated authentication failure sequences.",
        "simulation_only": True,
        "supported_actions": ["create_case_note", "simulate_block_ip", "collect_evidence"],
        "required_evidence": ["source_ip", "detection"],
        "steps": [
            {"id": "case_note", "action_type": "create_case_note", "requires_approval": False, "summary": "Create an internal SOC note."},
            {"id": "block_ip", "action_type": "simulate_block_ip", "requires_approval": True, "summary": "Simulate blocking the source IP."},
            {"id": "artifact", "action_type": "collect_evidence", "requires_approval": False, "summary": "Collect evidence summary artifact."},
        ],
    },
    {
        "id": "account_compromise_response",
        "version": "1",
        "name": "Account compromise response",
        "description": "Simulated account containment planning for suspicious account activity.",
        "simulation_only": True,
        "supported_actions": ["create_case_note", "simulate_disable_account", "collect_evidence"],
        "required_evidence": ["user", "detection"],
        "steps": [
            {"id": "case_note", "action_type": "create_case_note", "requires_approval": False, "summary": "Document the likely account risk."},
            {"id": "disable_account", "action_type": "simulate_disable_account", "requires_approval": True, "summary": "Simulate account containment."},
            {"id": "artifact", "action_type": "collect_evidence", "requires_approval": False, "summary": "Persist a bounded evidence snapshot."},
        ],
    },
    {
        "id": "suspicious_service_response",
        "version": "1",
        "name": "Suspicious service response",
        "description": "Simulated response for risky or suspicious service exposure.",
        "simulation_only": True,
        "supported_actions": ["create_case_note", "increase_monitoring", "collect_evidence"],
        "required_evidence": ["host", "detection"],
        "steps": [
            {"id": "case_note", "action_type": "create_case_note", "requires_approval": False, "summary": "Record the suspicious service signal."},
            {"id": "monitoring", "action_type": "increase_monitoring", "requires_approval": False, "summary": "Increase monitoring for the host."},
            {"id": "artifact", "action_type": "collect_evidence", "requires_approval": False, "summary": "Capture the service evidence summary."},
        ],
    },
    {
        "id": "log_tampering_response",
        "version": "1",
        "name": "Log tampering response",
        "description": "Simulated evidence preservation and audit review for suspicious log handling.",
        "simulation_only": True,
        "supported_actions": ["create_case_note", "collect_evidence", "mark_incident_reviewed"],
        "required_evidence": ["detection"],
        "steps": [
            {"id": "case_note", "action_type": "create_case_note", "requires_approval": False, "summary": "Document suspicious log activity."},
            {"id": "evidence", "action_type": "collect_evidence", "requires_approval": False, "summary": "Capture and preserve forensic evidence."},
            {"id": "review", "action_type": "mark_incident_reviewed", "requires_approval": False, "summary": "Mark the incident as reviewed in simulation."},
        ],
    },
    {
        "id": "generic_incident_response",
        "version": "1",
        "name": "Generic incident response",
        "description": "Fallback simulated response for incidents lacking a specialized playbook.",
        "simulation_only": True,
        "supported_actions": ["create_case_note", "collect_evidence"],
        "required_evidence": ["detection"],
        "steps": [
            {"id": "case_note", "action_type": "create_case_note", "requires_approval": False, "summary": "Create a generic incident note."},
            {"id": "evidence", "action_type": "collect_evidence", "requires_approval": False, "summary": "Summarize the evidence bundle."},
        ],
    },
]


class ResponseConflict(RuntimeError):
    """A stale state or concurrent update conflicts with the requested mutation."""


class ResponseForbidden(RuntimeError):
    """The response operation violates an approval or target policy."""


class ResponseNotFound(LookupError):
    pass


class ResponseService:
    def __init__(self, database, *, clock=None, config=None):
        self.db = database if isinstance(database, Database) else Database(database)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.config = config or settings
        self.executor = SimulationExecutor()

    @staticmethod
    def _ensure_playbook_tables(connection):
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS response_playbook_executions (
              execution_id TEXT PRIMARY KEY,
              incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE RESTRICT,
              playbook_id TEXT NOT NULL,
              playbook_version TEXT NOT NULL,
              playbook_hash TEXT NOT NULL,
              run_number INTEGER NOT NULL CHECK(run_number > 0),
              starter TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('awaiting_approval','executing','completed','completed_with_failures','failed','cancelled')),
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              started_at TEXT NOT NULL,
              completed_at TEXT,
              failure_details TEXT NOT NULL DEFAULT '{}',
              config_json TEXT NOT NULL DEFAULT '{}',
              context_json TEXT NOT NULL DEFAULT '{}',
              UNIQUE(incident_id,playbook_id,playbook_version,run_number)
            );
            CREATE INDEX IF NOT EXISTS idx_response_playbook_execution_incident ON response_playbook_executions(incident_id,created_at);
            CREATE INDEX IF NOT EXISTS idx_response_playbook_execution_status ON response_playbook_executions(status,created_at);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_response_playbook_active ON response_playbook_executions(incident_id,playbook_id)
            WHERE status IN ('awaiting_approval','executing');
            CREATE TABLE IF NOT EXISTS response_playbook_steps (
              step_id TEXT PRIMARY KEY,
              execution_id TEXT NOT NULL REFERENCES response_playbook_executions(execution_id) ON DELETE RESTRICT,
              step_index INTEGER NOT NULL CHECK(step_index >= 0),
              step_ref TEXT NOT NULL,
              action_type TEXT NOT NULL,
              target TEXT,
              target_type TEXT,
              status TEXT NOT NULL CHECK(status IN ('pending','awaiting_approval','simulated','failed','skipped','cancelled')),
              attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
              approval_state TEXT NOT NULL DEFAULT 'pending',
              action_id TEXT REFERENCES response_actions(action_id) ON DELETE RESTRICT,
              requested_by TEXT NOT NULL,
              approved_by TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              result_json TEXT NOT NULL DEFAULT '{}',
              UNIQUE(execution_id,step_ref)
            );
            CREATE INDEX IF NOT EXISTS idx_response_playbook_steps_execution ON response_playbook_steps(execution_id,step_index);
            CREATE TABLE IF NOT EXISTS response_playbook_artifacts (
              artifact_id TEXT PRIMARY KEY,
              execution_id TEXT NOT NULL REFERENCES response_playbook_executions(execution_id) ON DELETE RESTRICT,
              artifact_name TEXT NOT NULL,
              content_type TEXT NOT NULL CHECK(content_type IN ('application/json','text/markdown')),
              content_sha256 TEXT NOT NULL,
              generated_at TEXT NOT NULL,
              filename TEXT NOT NULL,
              payload TEXT NOT NULL,
              UNIQUE(execution_id,artifact_name)
            );
            CREATE INDEX IF NOT EXISTS idx_response_playbook_artifacts_exec ON response_playbook_artifacts(execution_id,generated_at);
        """)

    def _now(self):
        value = self.clock()
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _audit(c, *, actor, action, action_id, details, timestamp):
        # Stored in the Phase 7 audit_log table and therefore visible from /api/v1/audit.
        c.execute("INSERT INTO audit_log(timestamp,actor,action,entity_type,entity_id,details) VALUES(?,?,?,?,?,?)",
                  (timestamp, sanitize(actor, 100), action, "response_action", action_id, _json(details)))

    def _evidence(self, c, incident_id):
        refs = {(r[0].upper(), r[1]) for r in c.execute(
            "SELECT evidence_type,evidence_id FROM evidence_refs WHERE owner_type='INCIDENT' AND owner_id=?",
            (incident_id,)) if r[0].upper() in {"EVENT", "DETECTION", "IOC"}}
        refs.update(("EVENT", r[0]) for r in c.execute("SELECT event_id FROM incident_events WHERE incident_id=?", (incident_id,)))
        refs.update(("DETECTION", r[0]) for r in c.execute("SELECT detection_id FROM incident_detections WHERE incident_id=?", (incident_id,)))
        refs.update(("IOC", r[0]) for r in c.execute("SELECT ioc_id FROM incident_iocs WHERE incident_id=?", (incident_id,)))
        return tuple(sorted(refs)[:1000])

    def _targets_from_evidence(self, c, incident_id):
        candidates = {kind: set() for kind in ("ip", "host", "account", "domain")}
        for row in c.execute("SELECT e.host,e.user,e.src_ip,e.dst_ip,e.raw FROM incident_events x JOIN events e ON e.id=x.event_id WHERE x.incident_id=?", (incident_id,)):
            raw = {}
            try:
                raw = json.loads(row[4] or "{}") if isinstance(row[4], str) else (row[4] or {})
            except (TypeError, ValueError):
                raw = {}
            event_payload = raw.get("event", raw) if isinstance(raw, dict) else {}
            domain_value = None
            if isinstance(event_payload, dict):
                domain_value = event_payload.get("domain") or event_payload.get("url")
            for kind, value in (("host", row[0]), ("account", row[1]), ("ip", row[2]), ("ip", row[3]), ("domain", domain_value)):
                if value: candidates[kind].add(str(value))
        for row in c.execute("SELECT a.payload FROM incident_detections x JOIN alerts a ON a.alert_id=x.detection_id WHERE x.incident_id=?", (incident_id,)):
            try: payload = json.loads(row[0] or "{}")
            except (ValueError, TypeError): payload = {}
            for kind, key in (("ip", "source_ip"), ("ip", "destination_ip"), ("host", "hostname"), ("account", "username")):
                if payload.get(key): candidates[kind].add(str(payload[key]))
        for row in c.execute("SELECT i.value,i.type FROM incident_iocs x JOIN iocs i ON i.ioc_id=x.ioc_id WHERE x.incident_id=?", (incident_id,)):
            kind = {"ip": "ip", "domain": "domain", "hostname": "host", "host": "host", "account": "account"}.get(str(row[1]).lower())
            if kind: candidates[kind].add(str(row[0]))
        for evidence_type,evidence_id in self._evidence(c,incident_id):
            if evidence_type=="EVENT":
                row=c.execute("SELECT host,user,src_ip,dst_ip,raw FROM events WHERE id=?",(evidence_id,)).fetchone()
                if row:
                    raw = {}
                    try:
                        raw = json.loads(row[4] or "{}") if isinstance(row[4], str) else (row[4] or {})
                    except (TypeError, ValueError):
                        raw = {}
                    event_payload = raw.get("event", raw) if isinstance(raw, dict) else {}
                    domain_value = event_payload.get("domain") if isinstance(event_payload, dict) else None
                    for kind,value in (("host",row[0]),("account",row[1]),("ip",row[2]),("ip",row[3]),("domain",domain_value)):
                        if value:candidates[kind].add(str(value))
            elif evidence_type=="DETECTION":
                row=c.execute("SELECT payload FROM alerts WHERE alert_id=?",(evidence_id,)).fetchone()
                if row:
                    try:payload=json.loads(row[0] or "{}")
                    except (ValueError,TypeError):payload={}
                    for kind,key in (("ip","source_ip"),("ip","destination_ip"),("host","hostname"),("account","username")):
                        if payload.get(key):candidates[kind].add(str(payload[key]))
            elif evidence_type=="IOC":
                row=c.execute("SELECT value,type FROM iocs WHERE ioc_id=?",(evidence_id,)).fetchone()
                if row:
                    kind={"ip":"ip","domain":"domain","hostname":"host","host":"host","account":"account"}.get(str(row[1]).lower())
                    if kind:candidates[kind].add(str(row[0]))
        return candidates

    def _canonical_observed_target(self, c, incident_id, target, target_type):
        try:
            canonical = canonical_target(target, target_type)
        except ValueError:
            raise
        candidates = self._targets_from_evidence(c, incident_id).get(target_type, set())
        observed = set()
        for candidate in candidates:
            try: observed.add(canonical_target(candidate, target_type))
            except ValueError: continue
        if canonical not in observed:
            raise ResponseForbidden("target is not present in the incident's linked evidence")
        return canonical

    def _protected(self, target, target_type):
        if target_type == "ip":
            for item in self.config.response_protected_ips:
                try:
                    address=ipaddress.ip_address(target);network=ipaddress.ip_network(item,strict=False)
                    if address.version==network.version and address in network:return "target matches a protected IP or CIDR"
                except ValueError:
                    continue
            address = ipaddress.ip_address(target)
            if address.is_private:
                return "private IP requires an explicit policy_justification"
        if target_type == "host" and target.lower() in self.config.response_protected_hosts:
            return "target is a protected host"
        if target_type == "account" and target.lower() in self.config.response_protected_accounts:
            return "target is a protected account"
        if target_type == "account":
            account=target.lower().split("\\")[-1].split("@",1)[0].rstrip("$")
            if account in self.config.response_protected_accounts:return "target is a protected account"
        return None

    def _binding(self, action, evidence):
        return _digest({"action_type": action["action_type"], "target": action["target"],
                        "target_type": action["target_type"], "parameters": json.loads(action["parameters_json"]),
                        "evidence": sorted(evidence), "policy_version": action["policy_version"]})

    def _get_evidence_rows(self, c, action_id):
        return tuple((r[0], r[1]) for r in c.execute(
            "SELECT evidence_type,evidence_id FROM response_action_evidence WHERE action_id=? ORDER BY evidence_type,evidence_id", (action_id,)))

    def _action_row(self, c, action_id):
        row = c.execute("SELECT * FROM response_actions WHERE action_id=?", (action_id,)).fetchone()
        if row is None: raise ResponseNotFound("response action was not found")
        result = dict(row)
        result["parameters"] = json.loads(result.pop("parameters_json"))
        result["metadata"] = json.loads(result.pop("metadata_json"))
        result["result"] = json.loads(result.pop("result_json"))
        result["evidence"] = [{"evidence_type": k, "evidence_id": v} for k, v in self._get_evidence_rows(c, action_id)]
        return result

    def _insert_proposal(self, c, incident_id, action_type, *, target=None, target_type=None, parameters=None,
                         actor="api-user", via="api", evidence=None, supersedes=None):
        definition = get_action(action_type)
        parameters = dict(parameters or {})
        if target_type != definition.target_type and definition.target_type is not None:
            raise ValueError("target_type does not match the action catalog")
        if definition.target_type:
            target = self._canonical_observed_target(c, incident_id, target, target_type)
        else:
            target, target_type = None, None
        evidence = tuple(evidence if evidence is not None else self._evidence(c, incident_id))
        if not evidence:
            raise ResponseForbidden("an action requires evidence linked to the incident")
        allowed = set(self._evidence(c, incident_id))
        if any(item not in allowed for item in evidence):
            raise ResponseForbidden("action evidence is not linked to the incident")
        block_reason = self._protected(target, target_type) if target is not None else None
        justification = sanitize(parameters.get("policy_justification", ""), 500).strip()
        if block_reason and "private IP requires" in block_reason and len(justification) >= 12:
            block_reason = None
        clean_parameters = _bounded_json(parameters)
        if not isinstance(clean_parameters,dict): raise ValueError("parameters must be a JSON object")
        if len(_json(clean_parameters).encode("utf-8"))>16384: raise ValueError("parameters exceed the size limit")
        if justification: clean_parameters["policy_justification"] = justification
        approval_required = definition.required_approval
        approval_state = "pending" if approval_required else "not_required"
        revision = 1
        previous = supersedes
        exact_previous=None
        if previous is None:
            for row in c.execute("SELECT action_id,revision,parameters_json,policy_version,approval_state,execution_state FROM response_actions WHERE incident_id=? AND action_type=? AND COALESCE(target,'')=COALESCE(?, '') ORDER BY revision DESC",
                                 (incident_id, action_type, target)):
                row_evidence=self._get_evidence_rows(c,row[0])
                if row[2]==_json(clean_parameters) and row[3]==definition.policy_version and row_evidence==tuple(sorted(evidence)):
                    exact_previous=row
                    if row[4] not in {"rejected","expired"} and row[5]!="superseded":
                        return self._action_row(c,row[0]),False
                    break
            previous_row = c.execute("SELECT action_id,revision FROM response_actions WHERE incident_id=? AND action_type=? AND COALESCE(target,'')=COALESCE(?, '') ORDER BY revision DESC LIMIT 1",
                                     (incident_id, action_type, target)).fetchone()
            if exact_previous:
                previous,revision=exact_previous[0],int(exact_previous[1])+1
            elif previous_row:
                previous, revision = previous_row[0], int(previous_row[1]) + 1
        else:
            row = c.execute("SELECT revision FROM response_actions WHERE action_id=? AND incident_id=?", (previous, incident_id)).fetchone()
            if row is None: raise ResponseNotFound("superseded action was not found for this incident")
            revision = int(row[0]) + 1
        identity = {"incident": incident_id, "action_type": action_type, "target": target,
                    "target_type": target_type, "parameters": clean_parameters,
                    "policy_version": definition.policy_version, "evidence": sorted(evidence)}
        if revision>1:
            identity["revision"]=revision
        action_id = "rsp_" + _digest(identity)[:24]
        # Identical proposal requests are idempotent.
        existing = c.execute("SELECT action_id FROM response_actions WHERE action_id=?", (action_id,)).fetchone()
        if existing:
            return self._action_row(c, action_id), False
        now = self._now()
        action = {"action_type": action_type, "target": target, "target_type": target_type,
                  "parameters_json": _json(clean_parameters), "policy_version": definition.policy_version}
        binding = self._binding(action, evidence)
        execution_state = "blocked_by_policy" if block_reason else "not_started"
        verification_state = "unknown" if block_reason else "not_verified"
        result_json = _json({"blocked_reason": block_reason} if block_reason else {})
        c.execute("""INSERT INTO response_actions(action_id,incident_id,action_type,target,target_type,parameters_json,
            policy_rule_id,policy_version,playbook_id,playbook_version,approval_state,execution_state,verification_state,
            execution_mode,approval_binding_hash,approval_required,requested_by,created_at,updated_at,expires_at,revision,
            supersedes,metadata_json,result_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'simulation',?,?,?,?,?,?,?,?,?,?)""",
            (action_id,incident_id,action_type,target,target_type,_json(clean_parameters),definition.policy_rule_id,
             definition.policy_version,None,None,approval_state,execution_state,verification_state,binding,int(approval_required),
             sanitize(actor,100),now,now,(datetime.fromisoformat(now.replace("Z","+00:00"))+timedelta(seconds=self.config.response_approval_ttl_seconds)).isoformat().replace("+00:00","Z") if approval_required else None,
             revision,previous,_json({"via":via,"risk":definition.minimum_risk,"reversible":definition.reversible,
             "rollback_action":definition.rollback_action,"allowed_roles":definition.allowed_roles}),result_json))
        for kind, evidence_id in evidence:
            c.execute("INSERT INTO response_action_evidence(action_id,evidence_type,evidence_id) VALUES(?,?,?)", (action_id,kind,evidence_id))
        if previous:
            previous_state=c.execute("SELECT execution_state FROM response_actions WHERE action_id=?",(previous,)).fetchone()
            if previous_state and previous_state[0]=="not_started":
                self._transition(c,previous,dimension="execution_state",expected="not_started",target="superseded",
                    actor=actor,event="response.superseded",details={"superseded_by":action_id,"via":via})
        self._audit(c,actor=actor,action="response.proposed",action_id=action_id,
                    details={"action_type":action_type,"target":target,"target_type":target_type,"revision":revision,"via":via,"blocked_reason":block_reason},timestamp=now)
        return self._action_row(c, action_id), True

    def recommend(self, incident_id, *, actor="api-user", via="api", dry_run=False):
        context = self.db.read_session() if dry_run else self.db.session()
        with context as c:
            if c.execute("SELECT 1 FROM incidents WHERE incident_id=?", (incident_id,)).fetchone() is None:
                raise ResponseNotFound("incident was not found")
            evidence = self._evidence(c, incident_id)
            if not evidence: return []
            candidates = self._targets_from_evidence(c, incident_id)
            # Phase 9A intentionally has no playbook/risk-ranking recommendation engine.
            # The CLI/API recommend command only offers non-targeted catalog foundations.
            specs = [("collect_evidence",None,None,{}), ("increase_monitoring",None,None,{})]
            actions=[]
            for action_type,target,target_type,params in specs:
                if dry_run:
                    definition=get_action(action_type)
                    block_reason=self._protected(target,target_type) if target is not None else None
                    evidence_identity=sorted(evidence)
                    clean_parameters={sanitize(k,80):sanitize(v,1000) if isinstance(v,str) else v for k,v in params.items()}
                    identity={"incident":incident_id,"action_type":action_type,"target":target,"target_type":target_type,
                              "parameters":clean_parameters,"policy_version":definition.policy_version,"evidence":evidence_identity}
                    action_id="rsp_"+_digest(identity)[:24]
                    binding=self._binding({"action_type":action_type,"target":target,"target_type":target_type,
                        "parameters_json":_json(clean_parameters),"policy_version":definition.policy_version},evidence)
                    actions.append({"action_id":action_id,"incident_id":incident_id,"action_type":action_type,
                        "target":target,"target_type":target_type,"parameters":clean_parameters,
                        "policy_rule_id":definition.policy_rule_id,"policy_version":definition.policy_version,
                        "playbook_id":None,"playbook_version":None,
                        "approval_state":"pending" if definition.required_approval else "not_required",
                        "execution_state":"blocked_by_policy" if block_reason else "not_started",
                        "verification_state":"unknown" if block_reason else "not_verified","execution_mode":"simulation",
                        "approval_binding_hash":binding,"approval_required":definition.required_approval,
                        "requested_by":sanitize(actor,100),"approved_by":None,"approved_at":None,
                        "created_at":self._now(),"updated_at":self._now(),"expires_at":None,
                        "revision":1,"supersedes":None,"metadata":{"via":via,"risk":definition.minimum_risk,
                        "reversible":definition.reversible,"rollback_action":definition.rollback_action,"allowed_roles":list(definition.allowed_roles)},
                        "result":{"blocked_reason":block_reason} if block_reason else {},
                        "evidence":[{"evidence_type":k,"evidence_id":v} for k,v in evidence]})
                    continue
                action, _ = self._insert_proposal(c,incident_id,action_type,target=target,target_type=target_type,
                    parameters=params,actor=actor,via=via,evidence=evidence)
                actions.append(action)
            return actions

    def propose(self, incident_id, action_type, *, target=None, target_type=None, parameters=None, actor="api-user", via="api", evidence=None, supersedes=None):
        with self.db.session() as c:
            if c.execute("SELECT 1 FROM incidents WHERE incident_id=?",(incident_id,)).fetchone() is None:
                raise ResponseNotFound("incident was not found")
            action, _ = self._insert_proposal(c,incident_id,action_type,target=target,target_type=target_type,
                parameters=parameters,actor=actor,via=via,evidence=evidence,supersedes=supersedes)
            return action

    def get(self, action_id):
        with self.db.read_session() as c:
            return self._action_row(c,action_id)

    def list_for_incident(self, incident_id):
        with self.db.read_session() as c:
            ids=[r[0] for r in c.execute("SELECT action_id FROM response_actions WHERE incident_id=? ORDER BY created_at,action_id",(incident_id,))]
            return [self._action_row(c,action_id) for action_id in ids]

    def _transition(self,c,action_id,*,dimension,expected,target,actor,event,details=None):
        if target not in _POLICY.get(dimension,{}).get(expected,set()):
            raise ResponseConflict(f"invalid {dimension} transition {expected} -> {target}")
        now=self._now()
        cursor=c.execute(f"UPDATE response_actions SET {dimension}=?,updated_at=? WHERE action_id=? AND {dimension}=?",
                         (target,now,action_id,expected))
        if cursor.rowcount!=1: raise ResponseConflict("response action changed; refresh and retry")
        self._audit(c,actor=actor,action=event,action_id=action_id,details={"dimension":dimension,"from":expected,"to":target,**(details or {})},timestamp=now)
        return self._action_row(c,action_id)

    def approve(self, action_id, *, expected_status, actor, via="api"):
        actor=sanitize(actor,100)
        with self.db.session() as c:
            c.execute("BEGIN IMMEDIATE")
            action=self._action_row(c,action_id)
            if action["approval_state"]!="pending": raise ResponseConflict("approval is no longer pending")
            if action["approval_state"]!=expected_status: raise ResponseConflict("approval state changed; refresh and retry")
            if action["expires_at"] and self._now()>=action["expires_at"]:
                return self._transition(c,action_id,dimension="approval_state",expected=expected_status,target="expired",actor="system:policy:RSP001",event="response.approval_expired",details={"via":via})
            if self.config.response_require_different_approver and actor==action["requested_by"]:
                raise ResponseForbidden("requester and approver must be different")
            c.execute("UPDATE response_actions SET approved_by=?,approved_at=? WHERE action_id=? AND approval_state=?",
                      (actor,self._now(),action_id,expected_status))
            return self._transition(c,action_id,dimension="approval_state",expected=expected_status,target="approved",actor=actor,event="response.approved",details={"via":via,"binding":action["approval_binding_hash"]})

    def reject(self, action_id, *, expected_status, actor, reason="", via="api"):
        reason=sanitize(reason,1000)
        actor=sanitize(actor,100)
        with self.db.session() as c:
            c.execute("BEGIN IMMEDIATE")
            action=self._action_row(c,action_id)
            if action["approval_state"]!=expected_status:raise ResponseConflict("approval state changed; refresh and retry")
            if action["expires_at"] and self._now()>=action["expires_at"]:
                return self._transition(c,action_id,dimension="approval_state",expected=expected_status,target="expired",actor="system:policy:RSP001",event="response.approval_expired",details={"via":via})
            if self.config.response_require_different_approver and actor==action["requested_by"]:
                raise ResponseForbidden("requester and approver must be different")
            return self._transition(c,action_id,dimension="approval_state",expected=expected_status,target="rejected",actor=actor,event="response.rejected",details={"reason":reason,"via":via})

    def _expire_if_needed(self,c,action,actor,via):
        if action["approval_state"]=="pending" and action["expires_at"] and self._now()>=action["expires_at"]:
            self._transition(c,action["action_id"],dimension="approval_state",expected="pending",target="expired",actor="system:policy:RSP001",event="response.approval_expired",details={"via":via})
            return True
        return False

    def execute(self, action_id, *, expected_status, actor, via="api"):
        actor=sanitize(actor,100)
        # The first transaction reserves an attempt via CAS. A stale reservation can be recovered safely.
        with self.db.session() as c:
            c.execute("BEGIN IMMEDIATE")
            action=self._action_row(c,action_id)
            expired=self._expire_if_needed(c,action,actor,via)
            if expired:
                refused="approval expired; re-approval is required"
                recovered=False
            else:
                refused=None
            if action["execution_state"]=="simulated": return action
            if action["execution_state"]=="blocked_by_policy":
                raise ResponseForbidden(action["result"].get("blocked_reason","action is blocked by policy"))
            if refused is None and action["execution_state"]!=expected_status: raise ResponseConflict("execution state changed; refresh and retry")
            if refused is None and action["execution_state"]=="executing":
                attempt=c.execute("SELECT started_at FROM execution_attempts WHERE action_id=? AND status='executing' ORDER BY attempt_number DESC LIMIT 1",(action_id,)).fetchone()
                if attempt and self._now() <= (datetime.fromisoformat(attempt[0].replace("Z","+00:00"))+timedelta(seconds=900)).isoformat().replace("+00:00","Z"):
                    raise ResponseConflict("execution is already running")
                self._transition(c,action_id,dimension="execution_state",expected="executing",target="failed",actor="system:response:stale-recovery",event="response.stale_recovered",details={"via":via})
                c.execute("UPDATE execution_attempts SET status='failed',completed_at=?,error='stale simulated reservation' WHERE action_id=? AND status='executing'",(self._now(),action_id))
                recovered=True
            elif refused is None:
                recovered=False
            if recovered or expired:
                # Commit the recovery and its audit before returning a conflict to the caller.
                pass
            else:
                if action["approval_state"] not in {"not_required","approved"}: raise ResponseForbidden("action requires a current approval")
                if action["execution_state"]=="blocked_by_policy": raise ResponseForbidden(action["result"].get("blocked_reason","action is blocked by policy"))
                evidence=self._get_evidence_rows(c,action_id)
                stored=dict(c.execute("SELECT * FROM response_actions WHERE action_id=?",(action_id,)).fetchone())
                if self._binding(stored,evidence)!=action["approval_binding_hash"]:
                    self._audit(c,actor=actor,action="response.binding_mismatch",action_id=action_id,details={"via":via},timestamp=self._now())
                    refused="approval binding no longer matches the proposal"
                else: refused=None
                if refused is None and not set(evidence).issubset(set(self._evidence(c,action["incident_id"]))):
                    self._audit(c,actor=actor,action="response.evidence_stale",action_id=action_id,details={"via":via},timestamp=self._now())
                    refused="proposal evidence is no longer linked to the incident; create a new revision"
                if refused is None and action["target_type"]:
                    canonical=self._canonical_observed_target(c,action["incident_id"],action["target"],action["target_type"])
                    if canonical!=action["target"]: refused="target canonicalization mismatch"
                    else:
                        reason=self._protected(canonical,action["target_type"])
                        if reason and not ("private IP requires" in reason and len(action["parameters"].get("policy_justification", ""))>=12):
                            self._transition(c,action_id,dimension="execution_state",expected=expected_status,target="blocked_by_policy",actor="system:policy:RSP001",event="response.blocked_by_policy",details={"reason":reason,"via":via})
                            refused=reason
                if refused is not None:
                    # Raise only after transaction exit so the refusal audit is durable.
                    pass
                else:
                    if expected_status not in {"not_started","rolled_back"}: raise ResponseConflict("only new or rolled-back actions can execute")
                    attempt_number=c.execute("SELECT COALESCE(MAX(attempt_number),0)+1 FROM execution_attempts WHERE action_id=?",(action_id,)).fetchone()[0]
                    started=self._now(); attempt_id="attempt_"+_digest([action_id,attempt_number])[:24]
                    c.execute("INSERT INTO execution_attempts(attempt_id,action_id,attempt_number,execution_mode,started_at,status) VALUES(?,?,?,'simulation',?,'executing')",(attempt_id,action_id,attempt_number,started))
                    self._transition(c,action_id,dimension="execution_state",expected=expected_status,target="executing",actor=actor,event="response.execution_started",details={"attempt_number":attempt_number,"via":via})
        if expired: raise ResponseForbidden(refused)
        if recovered: raise ResponseConflict("stale execution was recovered; refresh and retry")
        if refused is not None: raise ResponseForbidden(refused)
        try:
            result=self.executor.execute(action["action_type"],action["target"],action["parameters"],evidence)
            serialized=_json(result)
            with self.db.session() as c:
                c.execute("BEGIN IMMEDIATE")
                fresh=self._action_row(c,action_id)
                self._transition(c,action_id,dimension="execution_state",expected="executing",target="simulated",actor=actor,event="response.simulated",details={"attempt_number":attempt_number,"via":via})
                if fresh["verification_state"]!="simulated":
                    self._transition(c,action_id,dimension="verification_state",expected=fresh["verification_state"],target="simulated",actor=actor,event="response.verification_simulated",details={"attempt_number":attempt_number,"via":via})
                c.execute("UPDATE response_actions SET result_json=? WHERE action_id=? AND execution_state='simulated'",(serialized,action_id))
                c.execute("UPDATE execution_attempts SET status='simulated',completed_at=?,result=? WHERE attempt_id=? AND status='executing'",(self._now(),serialized,attempt_id))
                return self._action_row(c,action_id)
        except Exception as exc:
            with self.db.session() as c:
                c.execute("BEGIN IMMEDIATE")
                fresh=self._action_row(c,action_id)
                if fresh["execution_state"]=="executing":
                    self._transition(c,action_id,dimension="execution_state",expected="executing",target="failed",actor=actor,event="response.execution_failed",details={"attempt_number":attempt_number,"error":sanitize(exc,500),"via":via})
                    if fresh["verification_state"]!="failed":
                        self._transition(c,action_id,dimension="verification_state",expected=fresh["verification_state"],target="failed",actor=actor,event="response.verification_failed",details={"attempt_number":attempt_number,"via":via})
                    c.execute("UPDATE execution_attempts SET status='failed',completed_at=?,error=? WHERE attempt_id=? AND status='executing'",(self._now(),sanitize(exc,500),attempt_id))
            raise

    def rollback(self, action_id, *, expected_status, actor, via="api"):
        definition=None
        with self.db.session() as c:
            c.execute("BEGIN IMMEDIATE")
            action=self._action_row(c,action_id)
            if action["execution_state"]=="rolled_back": return action
            definition=get_action(action["action_type"])
            if not definition.reversible or definition.rollback_action is None:
                raise ResponseForbidden("action is non-reversible")
            if action["execution_state"]!="simulated": raise ResponseConflict("only simulated actions can be rolled back")
            result={**action["result"],"rollback":{"mode":"simulation","rollback_action":definition.rollback_action,"external_effect":False}}
            updated=self._transition(c,action_id,dimension="execution_state",expected=expected_status,target="rolled_back",actor=actor,event="response.rolled_back",details={"via":via})
            c.execute("UPDATE response_actions SET verification_state='simulated',result_json=? WHERE action_id=?",(_json(result),action_id))
            c.execute("UPDATE execution_attempts SET status='rolled_back',completed_at=? WHERE attempt_id=(SELECT attempt_id FROM execution_attempts WHERE action_id=? AND status='simulated' ORDER BY attempt_number DESC LIMIT 1)",(self._now(),action_id))
            return self._action_row(c,action_id)

    @staticmethod
    def _playbook_registry():
        return [dict(playbook) for playbook in PLAYBOOK_REGISTRY]

    def list_playbooks(self):
        playbooks = []
        for playbook in self._playbook_registry():
            playbooks.append({
                "id": playbook["id"],
                "version": playbook["version"],
                "name": playbook["name"],
                "description": playbook["description"],
                "simulation_only": bool(playbook.get("simulation_only", True)),
                "supported_actions": list(playbook.get("supported_actions", [])),
                "required_evidence": list(playbook.get("required_evidence", [])),
                "steps": list(playbook.get("steps", [])),
                "playbook_hash": _digest(playbook),
            })
        return playbooks

    def get_playbook(self, playbook_id):
        for playbook in self._playbook_registry():
            if playbook["id"] == playbook_id:
                item = dict(playbook)
                item["playbook_hash"] = _digest(playbook)
                return item
        raise ResponseNotFound(f"playbook {playbook_id} was not found")

    def get_response_options(self, incident_id):
        with self.db.read_session() as c:
            if c.execute("SELECT 1 FROM incidents WHERE incident_id=?", (incident_id,)).fetchone() is None:
                raise ResponseNotFound("incident was not found")
            evidence = set(self._evidence(c, incident_id))
            options = []
            for playbook in self._playbook_registry():
                reason_codes = []
                if not evidence:
                    reason_codes.append("NO_REQUIRED_EVIDENCE")
                if "source_ip" in playbook["required_evidence"] and not any(kind == "EVENT" or kind == "IOC" for kind, _ in evidence):
                    reason_codes.append("NO_SOURCE_IP")
                if "user" in playbook["required_evidence"] and not any(kind == "DETECTION" for kind, _ in evidence):
                    reason_codes.append("NO_USER_IDENTIFIED")
                availability = "available" if not reason_codes else "unavailable"
                options.append({
                    "id": playbook["id"],
                    "version": playbook["version"],
                    "name": playbook["name"],
                    "description": playbook["description"],
                    "applicability": playbook["required_evidence"],
                    "steps": playbook["steps"],
                    "required_evidence": playbook["required_evidence"],
                    "availability": availability,
                    "reason_codes": reason_codes,
                    "supported_actions": playbook["supported_actions"],
                })
            return options

    def start_playbook_execution(self, incident_id, playbook_id, *, actor="api-user", force=False, via="api", mode="simulate"):
        if mode != "simulate":
            raise ValueError("playbook execution mode must be 'simulate'")
        with self.db.session() as c:
            self._ensure_playbook_tables(c)
            if c.execute("SELECT 1 FROM incidents WHERE incident_id=?", (incident_id,)).fetchone() is None:
                raise ResponseNotFound("incident was not found")
            playbook = None
            for item in self._playbook_registry():
                if item["id"] == playbook_id:
                    playbook = item
                    break
            if playbook is None:
                raise ResponseNotFound("playbook was not found")
            active = c.execute(
                "SELECT execution_id, status FROM response_playbook_executions WHERE incident_id=? AND playbook_id=? AND status IN ('awaiting_approval','executing') ORDER BY created_at DESC LIMIT 1",
                (incident_id, playbook_id),
            ).fetchone()
            if active and not force:
                return self._playbook_execution_row(c, active[0])
            run_number = 1
            if force:
                run_number = (c.execute("SELECT COALESCE(MAX(run_number),0) FROM response_playbook_executions WHERE incident_id=? AND playbook_id=?", (incident_id, playbook_id)).fetchone()[0] or 0) + 1
            else:
                run_number = (c.execute("SELECT COALESCE(MAX(run_number),0) FROM response_playbook_executions WHERE incident_id=? AND playbook_id=?", (incident_id, playbook_id)).fetchone()[0] or 0) + 1
            execution_id = stable_id("resp", incident_id, playbook_id, playbook["version"], run_number)
            now = self._now()
            c.execute(
                "INSERT INTO response_playbook_executions(execution_id,incident_id,playbook_id,playbook_version,playbook_hash,run_number,starter,status,created_at,updated_at,started_at,completed_at,failure_details,config_json,context_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    execution_id,
                    incident_id,
                    playbook_id,
                    playbook["version"],
                    _digest(playbook),
                    run_number,
                    sanitize(actor, 100),
                    "awaiting_approval",
                    now,
                    now,
                    now,
                    None,
                    _json({}),
                    _json({"via": via, "mode": mode}),
                    _json({"incident_id": incident_id, "playbook_id": playbook_id}),
                ),
            )
            for index, step in enumerate(playbook["steps"]):
                step_id = stable_id("respstep", execution_id, step["id"], index)
                status = "awaiting_approval" if step.get("requires_approval") else "pending"
                target = None
                target_type = None
                if step["action_type"] == "simulate_block_ip":
                    for candidate in self._targets_from_evidence(c, incident_id).get("ip", set()):
                        target = candidate
                        break
                    target_type = "ip"
                elif step["action_type"] == "simulate_disable_account":
                    for candidate in self._targets_from_evidence(c, incident_id).get("account", set()):
                        target = candidate
                        break
                    target_type = "account"
                elif step["action_type"] == "create_case_note":
                    target = None
                    target_type = None
                result = {"status": status}
                if not target and step["action_type"] in {"simulate_block_ip", "simulate_disable_account"}:
                    status = "failed"
                    result = {"status": "failed", "reason_code": "NO_SOURCE_IP" if step["action_type"] == "simulate_block_ip" else "NO_USER_IDENTIFIED"}
                c.execute(
                    "INSERT INTO response_playbook_steps(step_id,execution_id,step_index,step_ref,action_type,target,target_type,status,attempt_count,approval_state,requested_by,created_at,updated_at,result_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (step_id, execution_id, index, step["id"], step["action_type"], target, target_type, status, 0, "pending" if status == "pending" else "pending", sanitize(actor, 100), now, now, _json(result)),
                )
            return self._playbook_execution_row(c, execution_id)

    def _playbook_execution_row(self, c, execution_id):
        row = c.execute("SELECT * FROM response_playbook_executions WHERE execution_id=?", (execution_id,)).fetchone()
        if row is None:
            raise ResponseNotFound("playbook execution was not found")
        item = dict(row)
        item["failure_details"] = json.loads(item["failure_details"] or "{}")
        item["config"] = json.loads(item["config_json"] or "{}")
        item["context"] = json.loads(item["context_json"] or "{}")
        item["steps"] = [
            dict(step) for step in c.execute(
                "SELECT step_id,execution_id,step_index,step_ref,action_type,target,target_type,status,attempt_count,approval_state,action_id,requested_by,approved_by,created_at,updated_at,result_json FROM response_playbook_steps WHERE execution_id=? ORDER BY step_index",
                (execution_id,),
            ).fetchall()
        ]
        for step in item["steps"]:
            step["result"] = json.loads(step.pop("result_json") or "{}")
        return item

    def get_playbook_execution(self, execution_id):
        with self.db.read_session() as c:
            self._ensure_playbook_tables(c)
            return self._playbook_execution_row(c, execution_id)

