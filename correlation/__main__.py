"""CLI for deterministic incident correlation."""
import argparse
import json
import sys

from database.database import Database
from models.timestamps import to_utc_iso
from correlation.service import CorrelationService


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m correlation")
    parser.add_argument("--db", default=None, help="SQLite database path")
    parser.add_argument("--since", help="Only treat detections strictly after this timestamp as new candidates")
    parser.add_argument("command", nargs="?", choices=("incidents", "show"), default="incidents")
    parser.add_argument("incident_id", nargs="?")
    args = parser.parse_args(argv)
    if args.command == "show" and not args.incident_id:
        parser.error("show requires an incident_id")
    if args.since:
        try: to_utc_iso(args.since)
        except (TypeError, ValueError) as exc: parser.error(f"invalid --since timestamp: {exc}")
    from app.config import settings
    db = Database(args.db or settings.database_path)
    db.initialize()
    if args.command == "show":
        with db.read_session() as c:
            row = c.execute("SELECT payload FROM incidents WHERE incident_id=?", (args.incident_id,)).fetchone()
            if not row:
                print(f"Incident not found: {args.incident_id}")
                return 0
            payload = json.loads(row["payload"])
            for table, name, query, params in (
                ("incident_detections", "detections", "SELECT detection_id FROM incident_detections WHERE incident_id=? ORDER BY detection_id", (args.incident_id,)),
                ("incident_events", "events", "SELECT event_id FROM incident_events WHERE incident_id=? ORDER BY event_id", (args.incident_id,)),
                ("incident_iocs", "iocs", "SELECT ioc_id FROM incident_iocs WHERE incident_id=? ORDER BY ioc_id", (args.incident_id,)),
                ("incident_attack_mappings", "attack_mappings", "SELECT mapping_id FROM incident_attack_mappings WHERE incident_id=? ORDER BY mapping_id", (args.incident_id,)),
            ):
                payload[name] = [r[0] for r in c.execute(query, params)]
            payload["correlation_edges"] = [dict(r) for r in c.execute("SELECT rule_id,source_detection_id,target_detection_id,matched_at,explanation,rule_version,config_hash FROM correlation_edges WHERE source_detection_id IN (SELECT detection_id FROM incident_detections WHERE incident_id=?) AND target_detection_id IN (SELECT detection_id FROM incident_detections WHERE incident_id=?) ORDER BY matched_at,rule_id", (args.incident_id,args.incident_id))]
            payload["merge_history"] = [dict(r) for r in c.execute("SELECT * FROM incident_merge_history WHERE losing_incident_id=? OR surviving_incident_id=? ORDER BY merged_at", (args.incident_id,args.incident_id))]
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    result = CorrelationService(db).run(since=args.since)
    if args.since:
        print(json.dumps(result, indent=2, sort_keys=True))
    with db.read_session() as c:
        rows = c.execute("SELECT incident_id,payload FROM incidents WHERE COALESCE(json_extract(payload,'$.merged_into'),'')='' ORDER BY created_at,incident_id").fetchall()
    if not rows:
        print("No incidents found.")
        return 0
    for row in rows:
        p = json.loads(row["payload"])
        print("\t".join(str(v or "-") for v in (
            row["incident_id"], p.get("title", ""), p.get("status", "open"),
            f"{p.get('severity','-')}/{p.get('risk_level','-')}", p.get("risk_score", 0),
            p.get("confidence", "LOW"), p.get("primary_host"), p.get("primary_user"),
            p.get("primary_src_ip"), p.get("detection_count", 0), p.get("first_seen"), p.get("last_seen"))))
    if result["error_count"]:
        print(f"Correlation completed with {result['error_count']} error(s).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
