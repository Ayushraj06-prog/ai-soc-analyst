"""Idempotent local-only IOC enrichment and evidence-based ATT&CK mapping."""
import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from database.repositories import EventRepository
from enrichment.extractor import IOCExtractor, sanitize
from models.ids import stable_id
from models.timestamps import to_utc_iso

logger = logging.getLogger(__name__)
MAP_PATH = Path(__file__).with_name("attack_mappings.json")


def _map_data(path=MAP_PATH):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not data.get("attack_version") or not isinstance(data.get("techniques"), dict):
        raise ValueError("Invalid static ATT&CK mapping file")
    for technique_id, entry in data["techniques"].items():
        if technique_id != entry.get("technique_id", technique_id) or not entry.get("name") or not isinstance(entry.get("tactic_ids"), list):
            raise ValueError(f"Invalid ATT&CK record: {technique_id}")
    return data


class EnrichmentService:
    def __init__(self, database, *, extract_raw_paths=False, include_non_global_ips=True, mapping_path=MAP_PATH):
        self.db = database
        self.extractor = IOCExtractor(extract_raw_paths=extract_raw_paths, include_non_global_ips=include_non_global_ips)
        self.mapping_data = _map_data(mapping_path)

    def run(self, *, since=None, force=False, dry_run=False):
        since = to_utc_iso(since) if since is not None else None
        connection_factory = self.db.read_session if dry_run else self.db.session
        with connection_factory() as connection:
            clauses, params = [], []
            if since is not None:
                clauses.append("timestamp > ?"); params.append(since)
            if not force:
                clauses.append("id NOT IN (SELECT event_id FROM enrichment_state)")
            where = " WHERE " + " AND ".join(clauses) if clauses else ""
            rows = connection.execute("SELECT id,raw FROM events" + where + " ORDER BY timestamp,id", params).fetchall()
            events = []
            for row in rows:
                try:
                    events.append(json.loads(row["raw"])["event"])
                except Exception as exc:
                    events.append({"event_id": row["id"], "_load_error": sanitize(exc, 500)})
            existing = {(row["type"], row["normalized_value"]): row["ioc_id"] for row in
                        connection.execute("SELECT ioc_id,type,normalized_value FROM iocs WHERE normalized_value IS NOT NULL")}
        summary = {"events_processed": 0, "iocs_created": 0, "iocs_existing": 0,
                   "ioc_event_links_created": 0, "detection_links_created": 0,
                   "mappings_created": 0, "errors": 0, "warnings": [], "dry_run": dry_run}
        seen_iocs = set()
        preexisting = set(existing)
        preview_links = {}
        for event in events:
            summary["events_processed"] += 1
            event_id = event.get("event_id", "")
            try:
                if event.get("_load_error"):
                    raise ValueError("event payload could not be decoded: " + event["_load_error"])
                event_time = to_utc_iso(event["timestamp"])
                indicators = self.extractor.extract(event)
                for indicator in indicators:
                    preview_links[(event_id, existing.get((indicator.type, indicator.value)) or stable_id("ioc", indicator.type, indicator.value))] = indicator.source_field
                if not dry_run:
                    with self.db.session() as connection:
                        for indicator in indicators:
                            ioc_id = self._upsert_ioc(connection, indicator, event_time)
                            cursor = connection.execute("""INSERT OR IGNORE INTO ioc_events
                                (ioc_id,event_id,source_field,confidence) VALUES(?,?,?,?)""",
                                (ioc_id, event_id, indicator.source_field, indicator.confidence))
                            summary["ioc_event_links_created"] += cursor.rowcount
                            if not cursor.rowcount:
                                connection.execute("""UPDATE ioc_events SET
                                    source_field=CASE WHEN ? > confidence THEN ? ELSE source_field END,
                                    confidence=MAX(confidence,?) WHERE ioc_id=? AND event_id=?""",
                                    (indicator.confidence, indicator.source_field, indicator.confidence, ioc_id, event_id))
                            self._refresh_occurrences(connection, ioc_id)
                        connection.execute("""INSERT INTO enrichment_state(event_id,enriched_at,status,ioc_count,error)
                            VALUES(?,?,'completed',?,'') ON CONFLICT(event_id) DO UPDATE SET
                            enriched_at=excluded.enriched_at,status='completed',ioc_count=excluded.ioc_count,error=''""",
                            (event_id, datetime.now(timezone.utc).isoformat(), len(indicators)))
                else:
                    for indicator in indicators:
                        key = (indicator.type, indicator.value)
                        ioc_id = existing.get(key) or stable_id("ioc", *key)
                        with self.db.read_session() as connection:
                            linked = connection.execute("SELECT 1 FROM ioc_events WHERE ioc_id=? AND event_id=?", (ioc_id, event_id)).fetchone()
                        if not linked:
                            summary["ioc_event_links_created"] += 1
                keys = {(ind.type, ind.value) for ind in indicators}
                for key in keys - seen_iocs:
                    if key in preexisting: summary["iocs_existing"] += 1
                    else: summary["iocs_created"] += 1
                    seen_iocs.add(key)
            except Exception as exc:
                summary["errors"] += 1
                warning = f"event {sanitize(event_id, 100)}: {sanitize(exc, 400)}"
                summary["warnings"].append(warning)
                logger.warning("IOC enrichment skipped %s", warning)
                if not dry_run:
                    try:
                        with self.db.session() as connection:
                            connection.execute("""INSERT INTO enrichment_state(event_id,enriched_at,status,ioc_count,error)
                                VALUES(?,?,'error',0,?) ON CONFLICT(event_id) DO UPDATE SET
                                enriched_at=excluded.enriched_at,status='error',error=excluded.error""",
                                (event_id, datetime.now(timezone.utc).isoformat(), sanitize(exc, 500)))
                    except Exception:
                        pass
        # Link IOC evidence to a detection only when the IOC's event is in that detection's evidence set.
        link_delta, mapping_delta, map_warnings = self._enrich_detections(dry_run=dry_run, preview_links=preview_links)
        summary["detection_links_created"] = link_delta
        summary["mappings_created"] = mapping_delta
        summary["warnings"].extend(map_warnings)
        summary["links_created"] = summary["ioc_event_links_created"] + link_delta
        return summary

    def _upsert_ioc(self, connection, indicator, event_time):
        ioc_type, value = indicator.type, indicator.value
        row = connection.execute("SELECT ioc_id,confidence,payload FROM iocs WHERE type=? AND normalized_value=? LIMIT 1", (ioc_type, value)).fetchone()
        if row is None:
            # Preserve a legacy row with the same canonical text/type, if one exists.
            row = connection.execute("SELECT ioc_id,confidence,payload FROM iocs WHERE type=? AND value=? LIMIT 1", (ioc_type, value)).fetchone()
        ioc_id = row["ioc_id"] if row else stable_id("ioc", ioc_type, value)
        payload_confidence = 0
        if row:
            try: payload_confidence = float(json.loads(row["payload"]).get("confidence") or 0)
            except (ValueError, TypeError, AttributeError): pass
        confidence = max(indicator.confidence, float(row["confidence"] or 0) if row else 0, payload_confidence)
        payload = {"ioc_id": ioc_id, "type": ioc_type, "value": value, "normalized_value": value,
                   "first_seen": event_time, "last_seen": event_time, "source": indicator.source_field,
                   "confidence": confidence, "classification": indicator.classification,
                   "occurrence_count": 0, "associated_alerts": [], "reputation": None}
        connection.execute("""INSERT INTO iocs(ioc_id,value,type,first_seen,last_seen,payload,normalized_value,classification,confidence,occurrence_count)
            VALUES(?,?,?,?,?,?,?,?,?,0) ON CONFLICT(ioc_id) DO UPDATE SET
            value=excluded.value,normalized_value=excluded.normalized_value,
            first_seen=MIN(COALESCE(iocs.first_seen,excluded.first_seen),excluded.first_seen),
            last_seen=MAX(COALESCE(iocs.last_seen,excluded.last_seen),excluded.last_seen),
            confidence=MAX(iocs.confidence,excluded.confidence),
            classification=COALESCE(excluded.classification,iocs.classification),payload=excluded.payload""",
            (ioc_id, value, ioc_type, event_time, event_time, json.dumps(payload, separators=(",", ":")),
             value, indicator.classification, confidence))
        return ioc_id

    @staticmethod
    def _refresh_occurrences(connection, ioc_id):
        connection.execute("""UPDATE iocs SET occurrence_count=(SELECT COUNT(*) FROM ioc_events WHERE ioc_id=?),
            first_seen=(SELECT MIN(e.timestamp) FROM ioc_events ie JOIN events e ON e.id=ie.event_id WHERE ie.ioc_id=?),
            last_seen=(SELECT MAX(e.timestamp) FROM ioc_events ie JOIN events e ON e.id=ie.event_id WHERE ie.ioc_id=?)
            WHERE ioc_id=?""", (ioc_id, ioc_id, ioc_id, ioc_id))
        row = connection.execute("SELECT payload,first_seen,last_seen,occurrence_count,confidence FROM iocs WHERE ioc_id=?", (ioc_id,)).fetchone()
        payload = json.loads(row["payload"])
        provenance = connection.execute("SELECT source_field FROM ioc_events WHERE ioc_id=? ORDER BY confidence DESC,source_field,event_id LIMIT 1", (ioc_id,)).fetchone()
        payload.update(first_seen=row["first_seen"], last_seen=row["last_seen"],
                       occurrence_count=row["occurrence_count"], confidence=row["confidence"])
        if provenance:
            payload["source"] = provenance["source_field"]
        connection.execute("UPDATE iocs SET payload=? WHERE ioc_id=?", (json.dumps(payload, separators=(",", ":")), ioc_id))

    def _enrich_detections(self, *, dry_run, preview_links=None):
        preview_links = preview_links or {}
        read_factory = self.db.read_session
        with read_factory() as connection:
            alerts = connection.execute("SELECT alert_id,payload FROM alerts ORDER BY alert_id").fetchall()
        created_links = created_maps = 0
        warnings = []
        techniques = self.mapping_data["techniques"]
        for alert_row in alerts:
            try:
                alert = json.loads(alert_row["payload"])
                detection_id = alert_row["alert_id"]
                rule_id = alert.get("rule_id")
                if not rule_id:
                    continue
                refs = set(alert.get("evidence_refs") or [])
                refs.update(alert.get("evidence") or [])
                with read_factory() as connection:
                    refs.update(r[0] for r in connection.execute("SELECT evidence_id FROM evidence_refs WHERE owner_type='ALERT' AND owner_id=? AND evidence_type='EVENT'", (detection_id,)))
                    evidence = {}
                    if refs:
                        placeholders = ",".join("?" for _ in refs)
                        rows = connection.execute(f"SELECT id,raw FROM events WHERE id IN ({placeholders})", tuple(sorted(refs))).fetchall()
                        for row in rows:
                            try: evidence[row["id"]] = json.loads(row["raw"])["event"]
                            except Exception: pass
                    ioc_rows = []
                    if evidence:
                        placeholders = ",".join("?" for _ in evidence)
                        ioc_rows = connection.execute(f"""SELECT DISTINCT ie.ioc_id,ie.source_field,e.src_ip,e.dst_ip,ie.event_id FROM ioc_events ie
                            JOIN events e ON e.id=ie.event_id WHERE ie.event_id IN ({placeholders})""", tuple(sorted(evidence))).fetchall()
                if dry_run:
                    current = {(r["ioc_id"], r["event_id"]) for r in ioc_rows}
                    by_pair = {(r["ioc_id"], r["event_id"]): r["source_field"] for r in ioc_rows}
                    for (event_id, ioc_id), field in preview_links.items():
                        if event_id in evidence and (ioc_id, event_id) not in current:
                            by_pair[(ioc_id, event_id)] = field
                    ioc_rows = [{"ioc_id": ioc_id, "event_id": event_id, "source_field": field}
                                for (ioc_id, event_id), field in by_pair.items()]
                missing = sorted(refs - set(evidence))
                if missing:
                    warning = f"detection {detection_id}: missing evidence events {','.join(missing[:10])}"
                    warnings.append(warning); logger.warning(warning)
                if not evidence:
                    warning = f"detection {detection_id}: no available event evidence; ATT&CK mapping skipped"
                    warnings.append(warning); logger.warning(warning)
                if ioc_rows:
                    with (self.db.read_session() if dry_run else self.db.session()) as connection:
                        for row in ioc_rows:
                            relation = "source_of" if row["source_field"] in {"source_ip", "src_ip"} else "destination_of" if row["source_field"] in {"destination_ip", "dst_ip"} else "observed_in"
                            if dry_run:
                                exists = connection.execute("SELECT 1 FROM ioc_detection_links WHERE ioc_id=? AND detection_id=? AND relationship_type=?", (row["ioc_id"], detection_id, relation)).fetchone()
                                created_links += int(exists is None)
                                continue
                            cursor = connection.execute("INSERT OR IGNORE INTO ioc_detection_links(ioc_id,detection_id,relationship_type) VALUES(?,?,?)", (row["ioc_id"], detection_id, relation))
                            created_links += cursor.rowcount
                proposed = self._supported_mappings(rule_id, list(evidence.values())) if evidence else []
                if not proposed and rule_id in {"R001", "R002", "R003", "R011", "R020", "R030", "R040"} and evidence:
                    warnings.append(f"detection {detection_id}: evidence did not validate a project ATT&CK mapping")
                baseline = set(alert.get("mitre_techniques") or [])
                if not baseline and alert.get("mitre"):
                    baseline.add(alert["mitre"] if isinstance(alert["mitre"], str) else "")
                for technique_id, confidence in proposed:
                    entry = techniques.get(technique_id)
                    if not entry or entry.get("status") != "active":
                        warnings.append(f"detection {detection_id}: unknown/inactive ATT&CK id {technique_id}")
                        continue
                    if baseline and technique_id not in baseline:
                        warning = f"detection {detection_id}: Phase 4 {technique_id} differs from Phase 3 baseline {','.join(sorted(baseline))}"
                        warnings.append(warning); logger.warning(warning)
                    if dry_run:
                        with self.db.read_session() as connection:
                            exists = connection.execute("SELECT 1 FROM attack_mappings WHERE detection_id=? AND technique_id=? AND mapping_source='phase4-evidence'", (detection_id, technique_id)).fetchone()
                        created_maps += int(exists is None)
                    else:
                        created_maps += int(self._save_mapping(detection_id, technique_id, entry, confidence, sorted(evidence), sorted(baseline)))
            except Exception as exc:
                warning = f"detection {alert_row['alert_id']}: {sanitize(exc, 400)}"
                warnings.append(warning); logger.warning(warning)
        return created_links, created_maps, warnings

    @staticmethod
    def _supported_mappings(rule_id, evidence):
        kinds = {event.get("event_type") for event in evidence}
        mappings = []
        if rule_id == "R001" and kinds == {"auth_failure"} and EnrichmentService._auth_burst_supported(evidence, 5): mappings.append(("T1110", 0.95))
        elif rule_id == "R002" and EnrichmentService._auth_burst_supported(evidence, 3): mappings.append(("T1110", 0.75))
        elif rule_id == "R003" and any(
            f.get("event_type") == "auth_failure" and s.get("event_type") == "auth_success"
            and f.get("source_ip") and f.get("username") and f.get("source_ip") == s.get("source_ip")
            and f.get("username") == s.get("username") and f.get("event_id") != s.get("event_id")
            and timedelta(0) <= datetime.fromisoformat(to_utc_iso(s["timestamp"])) - datetime.fromisoformat(to_utc_iso(f["timestamp"])) <= timedelta(seconds=300)
            for f in evidence for s in evidence
        ) and EnrichmentService._auth_burst_supported(evidence, 3): mappings.append(("T1110", 0.75))
        elif rule_id == "R011" and kinds & {"account_enabled", "account_disabled", "group_membership_change"}: mappings.append(("T1098", 0.8))
        elif rule_id == "R020" and "account_created" in kinds: mappings.append(("T1136", 0.7))
        elif rule_id == "R030" and any(e.get("event_type") == "audit_log_cleared" and e.get("source_type") == "windows_events" and str(e.get("original_event_type")) == "1102" for e in evidence): mappings.append(("T1685.005", 0.95))
        elif rule_id == "R040" and any(e.get("event_type") == "service_created" and e.get("source_type") == "windows_events" and str(e.get("original_event_type")) == "7045" for e in evidence): mappings.append(("T1543.003", 0.95))
        return mappings

    @staticmethod
    def _auth_burst_supported(evidence, threshold):
        failures = [e for e in evidence if e.get("event_type") == "auth_failure"]
        for field in ("source_ip", "username"):
            groups = {}
            for event in failures:
                if event.get(field): groups.setdefault(event[field], []).append(event)
            for events in groups.values():
                times = sorted(datetime.fromisoformat(to_utc_iso(e["timestamp"])) for e in events)
                for index, start in enumerate(times):
                    if sum(start <= point <= start + timedelta(seconds=300) for point in times[index:]) >= threshold:
                        return True
        return False

    def _save_mapping(self, detection_id, technique_id, entry, confidence, evidence_ids, baseline):
        mapping_id = stable_id("attackmap", detection_id, technique_id, "phase4-evidence")
        with self.db.session() as connection:
            row = connection.execute("SELECT id,evidence_ids,confidence,baseline_techniques FROM attack_mappings WHERE detection_id=? AND technique_id=? AND mapping_source='phase4-evidence'", (detection_id, technique_id)).fetchone()
            created = row is None
            merged_evidence = sorted(set(evidence_ids) | (set(json.loads(row["evidence_ids"])) if row else set()))
            merged_baseline = sorted(set(baseline) | (set(json.loads(row["baseline_techniques"])) if row else set()))
            confidence = max(float(confidence), float(row["confidence"]) if row else 0)
            disagreement = bool(merged_baseline and technique_id not in merged_baseline)
            connection.execute("""INSERT INTO attack_mappings(id,detection_id,technique_id,technique_name,tactic_ids,attack_version,mapping_source,confidence,evidence_ids,baseline_techniques,baseline_disagreement)
                VALUES(?,?,?,?,?,?,'phase4-evidence',?,?,?,?) ON CONFLICT(detection_id,technique_id,mapping_source) DO UPDATE SET
                evidence_ids=excluded.evidence_ids,confidence=MAX(attack_mappings.confidence,excluded.confidence),
                baseline_techniques=excluded.baseline_techniques,baseline_disagreement=excluded.baseline_disagreement""",
                (mapping_id,detection_id,technique_id,entry["name"],json.dumps(entry["tactic_ids"]),self.mapping_data["attack_version"],confidence,json.dumps(merged_evidence),json.dumps(merged_baseline),int(disagreement)))
        return created
