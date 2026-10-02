"""Command-line entry point for offline ingestion."""
import argparse
import json
from pathlib import Path

from app.config import settings
from database.database import Database
from ingestion.pipeline import DEFAULT_ADAPTER_ORDER, IngestionPipeline


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize local security telemetry into the SOC SQLite database.")
    parser.add_argument("path", help="Local log or exported metadata file")
    parser.add_argument("--adapter", choices=DEFAULT_ADAPTER_ORDER, help="Force a specific adapter")
    parser.add_argument("--max-errors", type=int, default=settings.ingest_error_limit,
                        help="Maximum parse diagnostics to retain")
    parser.add_argument("--chunk-size", type=int, default=settings.ingest_chunk_size,
                        help="Events per SQLite transaction")
    parser.add_argument("--db", type=Path, default=settings.database_path, help="SQLite database path")
    args = parser.parse_args(argv)
    result = IngestionPipeline(Database(args.db)).ingest(
        args.path, adapter_name=args.adapter, max_errors=args.max_errors, chunk_size=args.chunk_size)
    print(json.dumps(result, indent=2))
    return 1 if result["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
