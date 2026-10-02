"""Explainable, bounded correlation over Phase 3 alerts and Phase 2 events."""
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from models.ids import stable_id
from models.timestamps import to_utc_iso

RULE_VERSION = "1.0"
DEFAULTS = {
    "window_seconds": 300, "max_incident_span_seconds": 86400,
    "max_candidates_per_key": 100, "max_ioc_detections": 100,
    "max_ioc_candidate_edges": 500, "high_frequency_ioc_threshold": 100,
    "excluded_ioc_tags": ["private", "loopback", "link_local", "multicast", "system", "high_frequency"],
    "high_frequency_source_ip_threshold": 20, "standalone_severities": ["HIGH", "CRITICAL"],
    "informational_base": 5,
}
_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


def _clean(value, limit=300):
    text = _ANSI.sub("", str(value or ""))
    text = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _dt(value):
    return datetime.fromisoformat(to_utc_iso(value))


class CorrelationService:
    """Build deterministic incidents from persisted detection alerts."""

    def __init__(self, database, config=None):
        self.db = database
        self.config = dict(DEFAULTS)
        if config:
            self.config.update(config)
        for key in ("window_seconds", "max_incident_span_seconds", "max_candidates_per_key",
                    "max_ioc_detections", "max_ioc_candidate_edges", "high_frequency_ioc_threshold",
                    "high_frequency_source_ip_threshold", "informational_base"):
            if type(self.config[key]) is not int or self.config[key] < 0:
                raise ValueError(f"{key} must be a non-negative integer")
        self.config_hash = hashlib.sha256(json.dumps(self.config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def run(self, since=None):
        since_iso = to_utc_iso(since) if since is not None else None
        started = datetime.now(timezone.utc).isoformat()
        execution_id = stable_id("corr", self.config_hash, RULE_VERSION, started)
        stats = {"candidate_count": 0, "edge_count": 0, "incident_created": 0,
                 "incident_updated": 0, "incident_merged": 0, "suppressed_count": 0,
                 "error_count": 0, "errors": [], "execution_id": execution_id}
        with self.db.session() as c:
            c.execute("INSERT INTO correlation_executions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (execution_id, started, started, "running", 0, 0, 0, 0, 0, 0, 0,
                 self.config_hash, RULE_VERSION, "[]"))
            alerts = [dict(r) for r in c.execute("SELECT alert_id,timestamp,severity,payload,status FROM alerts ORDER BY timestamp,alert_id")]
            detections = {}
            for row in alerts:
                try:
                    payload = json.loads(row["payload"])
                    stamp = to_utc_iso(row["timestamp"])
                    if not payload.get("rule_id") and not str(row["alert_id"]).startswith("det_"):
                        continue
                    detections[row["alert_id"]] = {"id": row["alert_id"], "timestamp": stamp,
                        "severity": str(row["severity"]).upper(), "status": row["status"], "payload": payload,
                        "events": set(), "iocs": set(), "keys": defaultdict(set)}
                except Exception as exc:
                    stats["error_count"] += 1
                    stats["errors"].append(f"{_clean(row['alert_id'],100)}: {_clean(exc,300)}")
            snapshot = {"alerts": [(row["alert_id"], row["timestamp"], row["severity"], row["payload"], row["status"]) for row in alerts]}
            for name, sql in (
                ("events", "SELECT id,timestamp,host,user,src_ip,event_type,raw_ref FROM events ORDER BY id"),
                ("evidence", "SELECT owner_type,owner_id,evidence_type,evidence_id FROM evidence_refs ORDER BY owner_type,owner_id,evidence_type,evidence_id"),
                ("ioc_links", "SELECT ioc_id,detection_id,relationship_type FROM ioc_detection_links ORDER BY ioc_id,detection_id,relationship_type"),
                ("iocs", "SELECT ioc_id,classification,payload FROM iocs ORDER BY ioc_id"),
                ("attack", "SELECT id,detection_id,technique_id,tactic_ids,evidence_ids FROM attack_mappings ORDER BY id"),
            ):
                snapshot[name] = [tuple(r) for r in c.execute(sql)]
            fingerprint = hashlib.sha256(json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            previous = {r["key"]: r["value"] for r in c.execute("SELECT key,value FROM correlation_state")}
            if previous.get("processed_fingerprint") == fingerprint and previous.get("config_hash") == self.config_hash + ":" + RULE_VERSION:
                # Nothing new, late, or changed since the last successful snapshot.
                self._finish(c, execution_id, started, stats, self.config_hash)
                return stats
            candidate_ids = {did for did, d in detections.items()
                if since_iso is None or d["timestamp"] > since_iso or previous.get("config_hash") != self.config_hash + ":" + RULE_VERSION}
            if not detections:
                self._finish(c, execution_id, started, stats, self.config_hash)
                return stats
            # Evidence is read from the generalized Phase 3 registry and alert payload refs.
            for did, d in detections.items():
                refs = d["payload"].get("evidence_refs") or d["payload"].get("evidence") or []
                if isinstance(refs, str): refs = [refs]
                for ref in refs:
                    if isinstance(ref, str) and c.execute("SELECT 1 FROM events WHERE id=?", (ref,)).fetchone(): d["events"].add(ref)
                for ref in c.execute("SELECT evidence_id FROM evidence_refs WHERE owner_type='ALERT' AND owner_id=? AND evidence_type='EVENT'", (did,)):
                    if c.execute("SELECT 1 FROM events WHERE id=?", (ref[0],)).fetchone(): d["events"].add(ref[0])
                d["iocs"].update(r[0] for r in c.execute("SELECT DISTINCT ioc_id FROM ioc_detection_links WHERE detection_id=?", (did,)))
            self._load_evidence_keys(c, detections)
            c.execute("DELETE FROM detection_keys")
            for d in detections.values():
                for typ, values in d["keys"].items():
                    for value in values:
                        c.execute("INSERT OR IGNORE INTO detection_keys VALUES(?,?,?,?)", (d["id"], typ, value, d["timestamp"]))

            # Candidate generation is by indexed structured key. C001-C005 are documented.
            buckets = defaultdict(list)
            for d in detections.values():
                for typ, values in d["keys"].items():
                    for value in values: buckets[(typ, value)].append(d["id"])
            pairs = defaultdict(set)
            suppressed = []
            for (typ, value), ids in sorted(buckets.items()):
                ids = sorted(set(ids), key=lambda i: (detections[i]["timestamp"], i))
                if typ == "ioc":
                    tags = self._ioc_tags(c, value)
                    if tags.intersection(self.config["excluded_ioc_tags"]):
                        suppressed.append((typ, value, "excluded_ioc_tag", len(ids))); continue
                    if len(ids) > min(self.config["max_ioc_detections"], self.config["high_frequency_ioc_threshold"]):
                        suppressed.append((typ, value, "high_frequency_ioc", len(ids))); continue
                    edge_cap = self.config["max_ioc_candidate_edges"]
                elif typ == "source_ip" and len(ids) > self.config["high_frequency_source_ip_threshold"]:
                    suppressed.append((typ, value, "high_frequency_source_ip", len(ids)))
                    # NAT source IP edges require additional matching context.
                    ids = [i for i in ids if any(detections[i]["keys"].get(k) for k in ("user", "host", "event", "ioc"))]
                    edge_cap = self.config["max_candidates_per_key"]
                else:
                    edge_cap = self.config["max_candidates_per_key"]
                generated = 0
                for pos, left in enumerate(ids):
                    for right in ids[pos + 1:]:
                        delta = (_dt(detections[right]["timestamp"]) - _dt(detections[left]["timestamp"])).total_seconds()
                        if delta > self.config["window_seconds"]: break
                        if typ == "source_ip" and len(buckets[(typ, value)]) > self.config["high_frequency_source_ip_threshold"]:
                            if not self._additional_context(detections[left], detections[right]): continue
                        pairs[(left, right)].add(typ)
                        generated += 1
                        if generated >= edge_cap: break
                    if generated >= edge_cap: break
                if generated >= edge_cap and len(ids) > 1:
                    suppressed.append((typ, value, "candidate_edge_cap", len(ids)))

            stats["candidate_count"] = len(candidate_ids)
            edge_rows = []
            # One key relationship may map to multiple defined rules; persist each match.
            mapping = {"source_ip": "C001", "user": "C002", "event": "C003", "ioc": "C004", "host_event": "C005"}
            for (left, right), types in sorted(pairs.items()):
                l, r = detections[left], detections[right]
                if (_dt(r["timestamp"]) - _dt(l["timestamp"])).total_seconds() > self.config["window_seconds"]: continue
                if "host" in types and "event" in types: types.add("host_event")
                for typ in sorted(types):
                    rule = mapping.get(typ)
                    if rule:
                        edge_rows.append((rule, left, right, r["timestamp"],
                            f"Shared {typ.replace('_',' ')} within {self.config['window_seconds']}s", execution_id))
            stats["edge_count"] = len(edge_rows)
            stats["suppressed_count"] = len(suppressed)
            for typ, value, reason, count in suppressed:
                c.execute("INSERT OR IGNORE INTO correlation_suppressions VALUES(?,?,?,?,?,?,?)",
                    (stable_id("csup", execution_id, typ, value, reason), execution_id, typ, value, reason, count, started))

            # Connected components with a maximum total incident span.
            components = {d: {d} for d in detections}
            owner = {d: d for d in detections}
            for rule, left, right, matched, explanation, _ in edge_rows:
                a, b = owner[left], owner[right]
                if a != b:
                    combined = components[a] | components[b]
                    times = [_dt(detections[x]["timestamp"]) for x in combined]
                    if (max(times) - min(times)).total_seconds() <= self.config["max_incident_span_seconds"]:
                        root = min((a, b), key=lambda x: self._anchor_key(components[x], detections))
                        loser = b if root == a else a
                        components[root] = combined; del components[loser]
                        for item in combined: owner[item] = root
            groups = [sorted(members, key=lambda x: self._anchor_key({x}, detections)) for members in components.values() if len(members) > 1 or detections[next(iter(members))]["severity"] in self.config["standalone_severities"]]
            # Save all edges with pair relationships; the primary key preserves rule history per pair.
            for row in edge_rows:
                c.execute("INSERT OR IGNORE INTO correlation_edges(rule_id,source_detection_id,target_detection_id,matched_at,explanation,rule_version,config_hash,execution_id) VALUES(?,?,?,?,?,?,?,?)", (*row[:5], RULE_VERSION, self.config_hash, execution_id))
            for members in sorted(groups, key=lambda m: self._anchor_key(set(m), detections)):
                c.execute("SAVEPOINT incident_component")
                try:
                    result = self._save_component(c, members, detections, execution_id, edge_rows, started)
                    c.execute("RELEASE SAVEPOINT incident_component")
                    stats["incident_created"] += result["created"]
                    stats["incident_updated"] += result["updated"]
                    stats["incident_merged"] += result["merged"]
                except Exception as exc:
                    c.execute("ROLLBACK TO SAVEPOINT incident_component")
                    c.execute("RELEASE SAVEPOINT incident_component")
                    stats["error_count"] += 1
                    stats["errors"].append(f"component {_clean(members[0],100)}: {_clean(exc,300)}")
            c.execute("INSERT INTO correlation_state(key,value,updated_at) VALUES('watermark',?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
                      (max((d["timestamp"] for d in detections.values()), default=""), started))
            c.execute("INSERT INTO correlation_state(key,value,updated_at) VALUES('processed_fingerprint',?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at", (fingerprint, started))
            c.execute("INSERT INTO correlation_state(key,value,updated_at) VALUES('config_hash',?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at", (self.config_hash + ":" + RULE_VERSION, started))
            self._finish(c, execution_id, started, stats, self.config_hash)
        return stats

    def _load_evidence_keys(self, c, detections):
        for d in detections.values():
            # Structured alert-level values, if present.
            for field, typ in (("source_ip", "source_ip"), ("src_ip", "source_ip"),
                               ("username", "user"), ("user", "user"),
                               ("hostname", "host"), ("host", "host")):
                value = d["payload"].get(field)
                if value: d["keys"][typ].add(_clean(value, 255))
            for event_id in d["events"]:
                row = c.execute("SELECT timestamp,host,user,src_ip,event_type FROM events WHERE id=?", (event_id,)).fetchone()
                if not row: continue
                for col, typ in (("host", "host"), ("user", "user"), ("src_ip", "source_ip")):
                    if row[col]: d["keys"][typ].add(_clean(row[col], 255))
                d["keys"]["event"].add(event_id)
            for ioc in d["iocs"]: d["keys"]["ioc"].add(ioc)

    def _ioc_tags(self, c, ioc_id):
        row = c.execute("SELECT payload,classification FROM iocs WHERE ioc_id=?", (ioc_id,)).fetchone()
        if not row: return set()
        try: payload = json.loads(row["payload"])
        except Exception: payload = {}
        tags = payload.get("tags", [])
        classification = row["classification"] or payload.get("classification")
        if classification: tags = list(tags) + [classification]
        return {str(t).lower() for t in tags}

    @staticmethod
    def _additional_context(left, right):
        for typ in ("user", "host", "event", "ioc"):
            if left["keys"].get(typ) and left["keys"].get(typ).intersection(right["keys"].get(typ, set())):
                return True
        return False

    @staticmethod
    def _anchor_key(members, detections):
        d = min((detections[x] for x in members), key=lambda x: (x["timestamp"], x["id"]))
        return d["timestamp"], d["id"]

    def _save_component(self, c, members, detections, execution_id, edges, now):
        anchor = min(members, key=lambda x: self._anchor_key({x}, detections))
        incident_id = stable_id("inc", anchor)
        member_set = set(members)
        related = [e for e in edges if e[1] in member_set and e[2] in member_set]
        old_ids = {r[0] for d in members for r in c.execute("SELECT incident_id FROM incident_detections WHERE detection_id=?", (d,))}
        old_ids.update(r[0] for r in c.execute("SELECT incident_id FROM incidents WHERE incident_id=?", (incident_id,)))
        losing = sorted(old_ids - {incident_id})
        created = c.execute("SELECT 1 FROM incidents WHERE incident_id=?", (incident_id,)).fetchone() is None
        # Keep user-owned fields from the surviving row. Derived values live in the JSON payload.
        old = c.execute("SELECT status,payload,created_at FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        payload = json.loads(old["payload"]) if old else {}
        status = old["status"] if old else "open"
        if old and str(status).lower() == "resolved":
            status = "open"
            history = payload.setdefault("status_history", [])
            history.append({"from": old["status"], "to": "open", "reason": "related detection observed", "execution_id": execution_id, "at": now})
        incident_dets = [detections[x] for x in members]
        primary = {key: self._primary(incident_dets, key) for key in ("host", "user", "source_ip")}
        sev_order = {"INFO": 0, "INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        severity = max((d["severity"] for d in incident_dets), key=lambda x: sev_order.get(x, 0))
        score, breakdown = self._risk(incident_dets, c)
        risk_level = "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"
        confidence = self._confidence(related)
        rules = sorted({e[0] for e in related})
        all_events = set().union(*(d["events"] for d in incident_dets))
        iocs = set().union(*(d["iocs"] for d in incident_dets))
        title = _clean(f"{severity.title()} security incident — {len(members)} detection(s)" + (f" on {primary['host']}" if primary['host'] else ""), 180)
        title = title.replace("—", "-")
        techniques, tactics = set(), set()
        for d in incident_dets:
            techniques.update(map(str, d["payload"].get("mitre_techniques", [])))
            tactics.update(map(str, d["payload"].get("mitre_tactics", [])))
            for mapping in c.execute("SELECT technique_id,tactic_ids FROM attack_mappings WHERE detection_id=?", (d["id"],)):
                techniques.add(str(mapping["technique_id"]))
                try: tactics.update(map(str, json.loads(mapping["tactic_ids"])))
                except (TypeError, ValueError): pass
        desc = _clean(f"Incident summary. Detection count: {len(members)}. Primary host: {primary['host'] or 'unknown'}. Primary user: {primary['user'] or 'unknown'}. Primary source IP: {primary['source_ip'] or 'unknown'}. Matched rules: {', '.join(rules) or 'standalone'}. Severity: {severity}. Risk score: {score}. Confidence: {confidence}. MITRE techniques: {', '.join(sorted(techniques)) or 'none'}. MITRE tactics: {', '.join(sorted(tactics)) or 'none'}.", 2000)
        payload.update({"incident_id": incident_id, "title": title, "description": desc, "status": status,
            "severity": severity, "risk_score": score, "risk_level": risk_level,
            "risk_breakdown": breakdown, "confidence": confidence, "primary_host": primary["host"],
            "primary_user": primary["user"], "primary_src_ip": primary["source_ip"],
            "detection_count": len(members), "first_seen": min(d["timestamp"] for d in incident_dets),
            "last_seen": max(d["timestamp"] for d in incident_dets), "detection_ids": sorted(members),
            "correlation_rules": rules, "mitre_techniques": sorted(techniques), "mitre_tactics": sorted(tactics),
            "analyst_notes": payload.get("analyst_notes", ""), "assigned_to": payload.get("assigned_to"),
            "resolved_at": payload.get("resolved_at"), "merged_into": None,
            "correlation_execution_id": execution_id, "rule_version": RULE_VERSION, "config_hash": self.config_hash})
        c.execute("INSERT INTO incidents(incident_id,created_at,updated_at,status,severity,risk_score,payload) VALUES(?,?,?,?,?,?,?) ON CONFLICT(incident_id) DO UPDATE SET updated_at=excluded.updated_at,status=excluded.status,severity=excluded.severity,risk_score=excluded.risk_score,payload=excluded.payload",
            (incident_id, old["created_at"] if old else now, now, status, severity, score, json.dumps(payload, sort_keys=True, separators=(",", ":"))))
        # Reconcile membership and materialized relationship tables for the current component.
        c.execute("DELETE FROM incident_detections WHERE incident_id=?", (incident_id,))
        c.execute("DELETE FROM incident_events WHERE incident_id=?", (incident_id,))
        c.execute("DELETE FROM incident_iocs WHERE incident_id=?", (incident_id,))
        c.execute("DELETE FROM incident_attack_mappings WHERE incident_id=?", (incident_id,))
        for did in members:
            c.execute("DELETE FROM incident_detections WHERE detection_id=?", (did,))
            c.execute("INSERT INTO incident_detections VALUES(?,?)", (incident_id, did))
        for eid in sorted(all_events): c.execute("INSERT OR IGNORE INTO incident_events VALUES(?,?)", (incident_id, eid))
        for ioc in sorted(iocs): c.execute("INSERT OR IGNORE INTO incident_iocs VALUES(?,?)", (incident_id, ioc))
        for did in members:
            for row in c.execute("SELECT id FROM attack_mappings WHERE detection_id=?", (did,)).fetchall():
                c.execute("INSERT OR IGNORE INTO incident_attack_mappings VALUES(?,?)", (incident_id, row[0]))
        merged = 0
        for loser in losing:
            row = c.execute("SELECT payload,status FROM incidents WHERE incident_id=?", (loser,)).fetchone()
            if not row: continue
            lp = json.loads(row["payload"]); lp.update({"status": "merged", "merged_into": incident_id})
            c.execute("UPDATE incidents SET status='merged',updated_at=?,payload=? WHERE incident_id=?", (now, json.dumps(lp, sort_keys=True), loser))
            c.execute("DELETE FROM incident_detections WHERE incident_id=?", (loser,))
            c.execute("DELETE FROM incident_events WHERE incident_id=?", (loser,))
            c.execute("DELETE FROM incident_iocs WHERE incident_id=?", (loser,))
            c.execute("DELETE FROM incident_attack_mappings WHERE incident_id=?", (loser,))
            c.execute("INSERT OR IGNORE INTO incident_merge_history VALUES(?,?,?,?,?,?)", (stable_id("merge", execution_id, loser, incident_id), loser, incident_id, execution_id, now, json.dumps({"from_status": row["status"]}, sort_keys=True)))
            merged += 1
        return {"created": int(created), "updated": int(not created), "merged": merged}

    @staticmethod
    def _primary(detections, key):
        counts = Counter(); first = {}
        for d in detections:
            for val in d["keys"].get(key, set()):
                counts[val] += 1
                first[val] = min(first.get(val, d["timestamp"]), d["timestamp"])
        return min(counts, key=lambda v: (-counts[v], first[v], v)) if counts else None

    def _risk(self, detections, c):
        rank = {"INFO": 0, "INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        highest = max((d["severity"] for d in detections), key=lambda s: rank.get(s, 0))
        base = {"INFO": self.config["informational_base"], "INFORMATIONAL": self.config["informational_base"], "LOW": 25, "MEDIUM": 50, "HIGH": 70, "CRITICAL": 90}.get(highest, 0)
        points = {"base_severity": base}
        all_events = set().union(*(d["events"] for d in detections))
        kinds = {r[0] for e in all_events if (r := c.execute("SELECT event_type FROM events WHERE id=?", (e,)).fetchone())}
        if "auth_failure" in kinds and "auth_success" in kinds: points["successful_login_after_failures"] = 10
        privileged = any(d["payload"].get("privileged_account") or d["payload"].get("privileged_group") for d in detections)
        privileged = privileged or bool(kinds.intersection({"privilege_assigned", "group_membership_change", "account_created"}))
        if privileged: points["privileged_account"] = 10
        techniques = set().union(*(set(d["payload"].get("mitre_techniques", [])) for d in detections))
        tactics = set().union(*(set(d["payload"].get("mitre_tactics", [])) for d in detections))
        for d in detections:
            for mapping in c.execute("SELECT technique_id,tactic_ids FROM attack_mappings WHERE detection_id=?", (d["id"],)):
                techniques.add(str(mapping["technique_id"]))
                try: tactics.update(map(str, json.loads(mapping["tactic_ids"])))
                except (TypeError, ValueError): pass
        if len(techniques) > 1: points["additional_mitre_techniques"] = min(15, 5 * (len(techniques) - 1))
        if len(tactics) > 1: points["additional_mitre_tactics"] = 5 * (len(tactics) - 1)
        if len(detections) > 3: points["more_than_three_detections"] = 5
        raw = sum(points.values()); score = min(100, max(0, raw))
        # Preserve exact arithmetic explanation under clamping.
        if score != raw: points["score_clamp"] = score - raw
        return score, [{"factor": k, "points": v} for k, v in points.items()]

    @staticmethod
    def _confidence(edges):
        if not edges: return "LOW"
        pair_rules = defaultdict(set)
        for e in edges: pair_rules[(e[1], e[2])].add(e[0])
        if len({d for pair in pair_rules for d in pair}) >= 2 and any(rules.intersection({"C003", "C004"}) for rules in pair_rules.values()):
            return "HIGH"
        if any("C003" in rules or {"C001", "C002"}.issubset(rules) for rules in pair_rules.values()):
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _finish(c, execution_id, started, stats, config_hash):
        completed = datetime.now(timezone.utc).isoformat()
        status = "completed_with_errors" if stats["error_count"] else "completed"
        c.execute("UPDATE correlation_executions SET completed_at=?,status=?,candidate_count=?,edge_count=?,incident_created=?,incident_updated=?,incident_merged=?,suppressed_count=?,error_count=?,config_hash=?,rule_version=?,errors=? WHERE execution_id=?",
            (completed, status, stats["candidate_count"], stats["edge_count"],
             stats["incident_created"], stats["incident_updated"], stats["incident_merged"],
             stats["suppressed_count"], stats["error_count"], config_hash, RULE_VERSION,
             json.dumps(stats["errors"], separators=(",", ":")), execution_id))

