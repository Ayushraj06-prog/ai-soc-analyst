"""Run the deterministic synthetic SOC demo without Ollama or network access."""
import argparse
import json
from pathlib import Path

from scenarios.registry import SCENARIOS
from scenarios.runner import run_scenario


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m demo")
    parser.add_argument("--scenario", choices=[*SCENARIOS, "all"], default="multi_stage_attack")
    parser.add_argument("--db", type=Path)
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    selected = list(SCENARIOS.values()) if args.scenario == "all" else [SCENARIOS[args.scenario]]
    results = [run_scenario(scenario, args.db, reset=args.reset) for scenario in selected]
    if args.json:
        print(json.dumps(results, indent=2, sort_keys=True))
    else:
        print("AI SOC ANALYST - SYNTHETIC DEMO")
        print("SYNTHETIC DATA | SIMULATION ONLY | NO REAL ATTACK TRAFFIC")
        for result in results:
            print(f"{result['name']}: {result['status']} | events={result['counts']['events']} detections={result['counts']['detections']} incidents={result['counts']['incidents']} risk={result['risk_score']}")
            print(f"AI PROVIDER: {result['investigation'].get('provider', 'fallback/mock').upper()}")
    return 0 if all(result["status"] == "PASS" for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
