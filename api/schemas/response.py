"""Phase 9A API schemas. Execution mode and approval actor are intentionally absent from bodies."""
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field


class ResponseActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_type: Literal["simulate_block_ip","simulate_disable_account","collect_evidence","increase_monitoring","create_case_note","mark_incident_reviewed"]
    target: str | None = Field(default=None,max_length=255)
    target_type: Literal["ip","host","account","domain"] | None = None
    parameters: dict[str,Any] = Field(default_factory=dict)
    supersedes: str | None = Field(default=None,max_length=100)


class ResponseDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_status: Literal["pending"]


class ResponseRejectRequest(ResponseDecisionRequest):
    reason: str = Field(default="",max_length=1000)


class ResponseExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_status: Literal["not_started","rolled_back"]


class ResponseRollbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_status: Literal["simulated"]


class ResponseRecommendationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dry_run: bool = False


class ResponseActionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_id: str
    incident_id: str
    action_type: str
    target: str | None
    target_type: str | None
    parameters: dict[str,Any]
    policy_rule_id: str
    policy_version: str
    playbook_id: str | None
    playbook_version: str | None
    approval_state: str
    execution_state: str
    verification_state: str
    execution_mode: Literal["simulation"]
    approval_binding_hash: str
    approval_required: bool
    requested_by: str
    approved_by: str | None
    approved_at: str | None
    created_at: str
    updated_at: str
    expires_at: str | None
    revision: int
    supersedes: str | None
    metadata: dict[str,Any]
    result: dict[str,Any]
    evidence: list[dict[str,str]]
