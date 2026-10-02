"""Deterministic simulation action catalog; no entry can contact a target."""
from dataclasses import dataclass


@dataclass(frozen=True)
class ActionDefinition:
    action_type: str
    target_type: str | None
    reversible: bool
    rollback_action: str | None
    minimum_risk: str
    required_approval: bool
    allowed_roles: tuple[str, ...]
    policy_rule_id: str
    policy_version: str = "1"


CATALOG = {
    "simulate_block_ip": ActionDefinition("simulate_block_ip", "ip", True, "simulate_unblock_ip", "medium", True, ("analyst", "admin"), "RSP001"),
    "simulate_disable_account": ActionDefinition("simulate_disable_account", "account", True, "simulate_enable_account", "high", True, ("analyst", "admin"), "RSP002"),
    "collect_evidence": ActionDefinition("collect_evidence", None, False, None, "low", False, ("analyst", "admin"), "RSP003"),
    "increase_monitoring": ActionDefinition("increase_monitoring", None, True, "remove_monitoring_recommendation", "low", False, ("analyst", "admin"), "RSP004"),
    "create_case_note": ActionDefinition("create_case_note", None, False, None, "low", False, ("analyst", "admin"), "RSP005"),
    "mark_incident_reviewed": ActionDefinition("mark_incident_reviewed", None, False, None, "low", False, ("analyst", "admin"), "RSP006"),
}


def get_action(action_type: str) -> ActionDefinition:
    try:
        return CATALOG[action_type]
    except KeyError as exc:
        raise ValueError("unsupported response action type") from exc
