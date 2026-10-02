"""Run two fresh scenario databases and compare deterministic entity state."""
import tempfile
from pathlib import Path

from replay.comparator import compare
from scenarios.registry import get_scenario
from scenarios.runner import run_scenario


def replay_scenario(scenario_id: str) -> dict:
    scenario = get_scenario(scenario_id)
    with tempfile.TemporaryDirectory(prefix="soc-replay-") as directory:
        left = Path(directory) / "a.db"
        right = Path(directory) / "b.db"
        run_scenario(scenario, left, reset=True)
        run_scenario(scenario, right, reset=True)
        checks = compare(left, right)
    return {"scenario_id": scenario_id, "checks": checks, "passed": all(checks.values())}
