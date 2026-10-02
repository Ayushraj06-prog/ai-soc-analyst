"""Generate safe synthetic JSONL benchmark events."""
import json
from pathlib import Path


def generate(path: Path, count: int) -> Path:
    with path.open("w", encoding="utf-8") as output:
        for index in range(count):
            output.write(json.dumps({
                "timestamp": f"2026-10-01T00:{index // 60:02d}:{index % 60:02d}Z",
                "event_type": "auth_success",
                "hostname": "benchmark.example",
                "username": f"user{index % 100}",
                "source_ip": "192.0.2.10",
                "message": "synthetic benchmark event",
            }) + "\n")
    return path
