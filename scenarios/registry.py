"""Scenario registry backed by checked-in synthetic fixtures."""
import json
from pathlib import Path

from scenarios.base import Scenario

ROOT = Path(__file__).parent
FIXTURES = ROOT / "fixtures"
EXPECTED = ROOT / "expected"


def _scenario(scenario_id: str, name: str, description: str) -> Scenario:
    fixture = FIXTURES / f"{scenario_id}.jsonl"
    expected_path = EXPECTED / f"{scenario_id}.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8")) if expected_path.exists() else {}
    return Scenario(scenario_id, name, description, fixture, expected)


SCENARIOS = {
    "brute_force": _scenario("brute_force", "SSH brute force", "Repeated synthetic authentication failures followed by success."),
    "account_compromise": _scenario("account_compromise", "Suspicious account activity", "Synthetic account creation and privilege activity."),
    "suspicious_service": _scenario("suspicious_service", "Suspicious service creation", "Synthetic service creation and authentication activity."),
    "audit_log_clear": _scenario("audit_log_clear", "Audit log clearing", "Synthetic Windows audit log clearing event."),
    "multi_stage_attack": _scenario("multi_stage_attack", "Multi-stage attack", "Synthetic authentication, privilege, service, and audit stages."),
    "benign_activity": _scenario("benign_activity", "Benign activity", "Routine synthetic login, logout, and network activity."),
}


def get_scenario(scenario_id: str) -> Scenario:
    try:
        return SCENARIOS[scenario_id]
    except KeyError as exc:
        raise ValueError(f"unknown scenario: {scenario_id}") from exc
