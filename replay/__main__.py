"""CLI for deterministic replay verification."""
import argparse

from replay.runner import replay_scenario


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m replay")
    parser.add_argument("command", choices=["scenario"])
    parser.add_argument("scenario")
    args = parser.parse_args(argv)
    result = replay_scenario(args.scenario)
    print("REPLAY VERIFICATION")
    for name, passed in result["checks"].items():
        print(f"{name.replace('_', ' ').title():24} {'PASS' if passed else 'FAIL'}")
    print(f"Deterministic replay: {'PASS' if result['passed'] else 'FAIL'}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
