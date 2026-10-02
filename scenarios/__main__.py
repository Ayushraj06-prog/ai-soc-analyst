"""CLI for deterministic synthetic SOC scenarios."""
import argparse
import json
from pathlib import Path

from scenarios.registry import SCENARIOS, get_scenario
from scenarios.runner import run_scenario


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m scenarios")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list")
    run = subparsers.add_parser("run")
    run.add_argument("scenario", choices=[*SCENARIOS, "all"])
    run.add_argument("--db", type=Path)
    run.add_argument("--reset", action="store_true")
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--verbose", action="store_true")
    run.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "list":
        for scenario in SCENARIOS.values():
            print(f"{scenario.scenario_id}: {scenario.name} - {scenario.description}")
        return 0
    scenarios = list(SCENARIOS.values()) if args.scenario == "all" else [get_scenario(args.scenario)]
    results = [run_scenario(item, args.db, reset=args.reset, dry_run=args.dry_run) for item in scenarios]
    if args.json:
        print(json.dumps(results, indent=2, sort_keys=True))
    else:
        for result in results:
            print("AI SOC ANALYST - SCENARIO RUN")
            print(f"Scenario: {result['name']}")
            print(f"Status: {result['status']}")
            print(f"Events: {result['counts']['events']}")
            print(f"Detections: {result['counts']['detections']}")
            print(f"IOCs: {result['counts']['iocs']}")
            print(f"Incidents: {result['counts']['incidents']}")
            print(f"Risk: {result['risk_score'] if result['risk_score'] is not None else 'n/a'}/100")
            print(f"Investigation: {result['investigation']['status']}")
            print(f"Recommendations: {result['recommendations']}")
            print(f"Audit trail: {result['audit_records']} records")
    return 0 if all(result["status"] == "PASS" for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
