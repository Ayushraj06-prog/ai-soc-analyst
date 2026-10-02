"""Expose the existing checked-in synthetic scenario fixtures."""
from pathlib import Path

from scenarios.registry import SCENARIOS


def fixture_paths() -> dict[str, Path]:
    return {scenario_id: scenario.fixture for scenario_id, scenario in SCENARIOS.items()}
