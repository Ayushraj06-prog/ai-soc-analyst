"""CLI for Phase 4 local telemetry enrichment."""
import argparse
import os
from pathlib import Path

from app.config import settings
from database.database import Database
from enrichment.service import EnrichmentService
from models.timestamps import to_utc_iso


def main(argv=None):
    parser = argparse.ArgumentParser(description="Extract and link IOCs from local SOC telemetry")
    parser.add_argument("--db", default=str(settings.database_path), help="SOC SQLite database path")
    parser.add_argument("--since", help="Process events strictly after this ISO timestamp")
    parser.add_argument("--force", action="store_true", help="Reprocess previously enriched events idempotently")
    parser.add_argument("--dry-run", action="store_true", help="Preview counts using read-only database access")
    args = parser.parse_args(argv)
    try:
        since = to_utc_iso(args.since) if args.since else None
    except (TypeError, ValueError) as exc:
        parser.error(f"invalid --since timestamp: {exc}")
    database = Database(args.db)
    if args.dry_run:
        if not Path(args.db).is_file():
            parser.error("--dry-run requires an existing initialized database; it will not create or migrate one")
    else:
        database.initialize()
    extract_raw_paths = os.getenv("IOC_EXTRACT_RAW_PATHS", "false").strip().lower() in {"1", "true", "yes", "on"}
    include_non_global_ips = os.getenv("IOC_INCLUDE_NON_GLOBAL_IPS", "true").strip().lower() in {"1", "true", "yes", "on"}
    try:
        result = EnrichmentService(database, extract_raw_paths=extract_raw_paths,
            include_non_global_ips=include_non_global_ips).run(
            since=since, force=args.force, dry_run=args.dry_run)
    except Exception as exc:
        parser.error(f"enrichment failed: {exc}")
    if result["events_processed"] == 0:
        print("No events require enrichment." if not args.force else "No events matched the enrichment scope.")
    print(f"Events processed: {result['events_processed']}")
    print(f"IOCs created: {result['iocs_created']}")
    print(f"IOCs already existing: {result['iocs_existing']}")
    print(f"IOC-event links created: {result['ioc_event_links_created']}")
    print(f"Detection links created: {result['detection_links_created']}")
    print(f"ATT&CK mappings created: {result['mappings_created']}")
    print(f"Errors: {result['errors']}")
    if args.dry_run:
        print("Dry run: no database changes made.")
    for warning in result["warnings"]:
        print(f"Warning: {warning}")
    return 0 if result["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
