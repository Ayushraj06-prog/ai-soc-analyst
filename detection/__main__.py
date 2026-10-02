import argparse

from app.config import settings
from database.database import Database
from database.repositories import AlertRepository
from detection.engine import DetectionEngine
from models.timestamps import to_utc_iso


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run deterministic SOC detections")
    parser.add_argument("--db", default=str(settings.database_path))
    parser.add_argument("--since", help="ISO timestamp (inclusive)")
    parser.add_argument("--batch-id")
    args = parser.parse_args(argv)
    since = to_utc_iso(args.since) if args.since else None
    db = Database(args.db)
    db.initialize()
    results = DetectionEngine(db).run(since=since, batch_id=args.batch_id)
    if not results:
        print("No detections found.")
        return 0
    alerts = {a["alert_id"]: a for a in AlertRepository(db).list(1000)}
    for result in results:
        alert = alerts.get(result["id"], {})
        print(f"Detection ID: {result['id']}")
        print(f"Rule ID: {result['rule_id']}")
        print(f"Severity: {alert.get('severity', '')}")
        print(f"Confidence: {alert.get('confidence', '')}")
        print(f"Timestamp: {alert.get('timestamp', result['timestamp'])}")
        print(f"Title: {alert.get('title', result.get('title', ''))}")
        print(f"Grouping key: {result['grouping_key']}")
        print(f"MITRE techniques/tactics: {', '.join(alert.get('mitre_techniques', []))} / {', '.join(alert.get('mitre_tactics', []))}")
        print(f"Evidence count: {len(result['event_ids'])}")
        print(f"Status: {alert.get('status', 'NEW')}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
