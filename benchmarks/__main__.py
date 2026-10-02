"""Measured local benchmark command."""
import argparse
import json
import tempfile
import time
import tracemalloc
from pathlib import Path

from benchmarks.generate_events import generate
from database.database import Database
from detection.engine import DetectionEngine
from ingestion.pipeline import IngestionPipeline


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m benchmarks")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--events", type=int, default=1000)
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="soc-benchmark-") as directory:
        root = Path(directory)
        database = Database(root / "benchmark.db")
        database.initialize()
        fixture = generate(root / "events.jsonl", max(1, args.events))
        tracemalloc.start()
        started = time.perf_counter()
        ingestion = IngestionPipeline(database).ingest(fixture, adapter_name="json")
        ingestion_seconds = time.perf_counter() - started
        started = time.perf_counter()
        DetectionEngine(database).run()
        detection_seconds = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        result = {"events": args.events, "ingestion_seconds": ingestion_seconds, "detection_seconds": detection_seconds, "database_bytes": (root / "benchmark.db").stat().st_size, "peak_memory_bytes": peak}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if ingestion["status"] in {"completed", "completed_with_errors"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
