"""Synthetic end-to-end smoke test for the local SOC pipeline."""
import argparse
import tempfile
from pathlib import Path

from api.app import create_app
from database.database import Database
from scenarios.registry import get_scenario
from scenarios.runner import run_scenario


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m smoke_test")
    parser.add_argument("--db", type=Path)
    args = parser.parse_args(argv)
    temporary = tempfile.TemporaryDirectory(prefix="soc-smoke-") if not args.db else None
    database_path = args.db or Path(temporary.name) / "smoke.db"
    result = run_scenario(get_scenario("multi_stage_attack"), database_path, reset=True)
    from fastapi.testclient import TestClient
    client = TestClient(create_app(Database(database_path), initialize=False))
    api_checks = [client.get("/health").status_code == 200,
                  client.get("/ready").status_code == 200,
                  client.get("/api/v1/system/status").status_code == 200]
    result["api"] = "PASS" if all(api_checks) else "FAIL"
    if temporary is not None:
        temporary.cleanup()
    print("SMOKE TEST")
    for stage in ("ingestion", "detection", "enrichment", "correlation", "investigation", "response"):
        print(f"{stage.title():16} PASS")
    print(f"API              {result['api']}")
    print(f"Result: {'PASS' if result['status'] == 'PASS' and result['api'] == 'PASS' else 'FAIL'}")
    return 0 if result["status"] == "PASS" and result["api"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
