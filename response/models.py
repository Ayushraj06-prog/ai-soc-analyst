"""Typed vocabulary for response workflows."""
from dataclasses import dataclass
from enum import StrEnum
from datetime import datetime
from typing import Any


class ApprovalState(StrEnum):
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ExecutionState(StrEnum):
    NOT_STARTED = "not_started"
    EXECUTING = "executing"
    SIMULATED = "simulated"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    SUPERSEDED = "superseded"


class VerificationState(StrEnum):
    NOT_VERIFIED = "not_verified"
    SIMULATED = "simulated"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ResponseAction:
    action_id: str
    incident_id: str
    action_type: str
    target: str | None
    target_type: str | None
    parameters: dict[str, Any]
    evidence: tuple[tuple[str, str], ...]
    policy_rule_id: str
    policy_version: str
    playbook_id: str | None
    playbook_version: str | None
    approval_state: ApprovalState
    execution_state: ExecutionState
    verification_state: VerificationState
    execution_mode: str
    approval_binding_hash: str
    approval_required: bool
    requested_by: str
    approved_by: str | None
    approved_at: datetime | None
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None
    revision: int
    supersedes: str | None
    metadata: dict[str, Any]
    result: dict[str, Any]
