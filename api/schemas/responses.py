"""OpenAPI response contracts; extensible payload fields preserve API compatibility."""
from typing import Any
from pydantic import BaseModel, ConfigDict, Field
from api.schemas.common import Page


class Extensible(BaseModel):
    model_config = ConfigDict(extra="allow")


class AlertResponse(Extensible):
    alert_id: str | None = None
    timestamp: str | None = None
    severity: str | None = None
    status: str | None = None
    rule_id: str | None = None
    title: str | None = None
    hostname: str | None = None
    username: str | None = None
    source_ip: str | None = None
    confidence: str | float | None = None
    evidence_refs: list[str] | None = None
    destination_ip: str | None = None
    event_type: str | None = None
    explanation: str | None = None
    mitre_technique: str | None = None
    incident_id: str | None = None
    events: list[dict[str, Any]] = Field(default_factory=list)
    iocs: list[dict[str, Any]] = Field(default_factory=list)
    attack_mappings: list[dict[str, Any]] = Field(default_factory=list)


class EventResponse(Extensible):
    id: str | None = None
    event_id: str | None = None
    timestamp: str | None = None
    source_type: str | None = None
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    event_type: str | None = None
    raw: Any = None


class IOCEventResponse(Extensible):
    event_id: str
    timestamp: str | None = None
    source_type: str | None = None
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    event_type: str | None = None


class IOCDetectionResponse(Extensible):
    alert_id: str
    timestamp: str | None = None
    severity: str | None = None
    status: str | None = None
    rule_id: str | None = None


class IOCIncidentResponse(Extensible):
    incident_id: str
    title: str | None = None
    status: str | None = None
    severity: str | None = None
    risk_score: int | None = None


class IOCResponse(Extensible):
    ioc_id: str | None = None
    value: str | None = None
    type: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    occurrence_count: int | None = None
    events: list[IOCEventResponse] = Field(default_factory=list)
    detections: list[IOCDetectionResponse] = Field(default_factory=list)
    incidents: list[IOCIncidentResponse] = Field(default_factory=list)


class IncidentResponse(Extensible):
    incident_id: str
    title: str | None = None
    description: str | None = None
    status: str | None = None
    severity: str | None = None
    risk_score: int | float | None = None
    risk_level: str | None = None
    confidence: str | float | None = None
    primary_host: str | None = None
    primary_user: str | None = None
    primary_src_ip: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    detection_count: int | None = None
    analyst_notes: str | None = None


class AttackMappingResponse(Extensible):
    id: str
    detection_id: str
    technique_id: str
    technique_name: str
    tactic_ids: list[str] = Field(default_factory=list)
    mapping_source: str | None = None
    confidence: float | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    baseline_techniques: list[str] = Field(default_factory=list)
    baseline_disagreement: bool | None = None


class IncidentDetailResponse(IncidentResponse):
    detection_ids: list[str] = Field(default_factory=list)
    events: list[EventResponse] = Field(default_factory=list)
    iocs: list[IOCResponse] = Field(default_factory=list)
    attack_mappings: list[AttackMappingResponse] = Field(default_factory=list)
    correlation_edges: list[dict[str, Any]] = Field(default_factory=list)
    merge_history: list[dict[str, Any]] = Field(default_factory=list)


class InvestigationResponse(Extensible):
    investigation_id: str
    incident_id: str
    status: str
    run_number: int | None = None
    provider: str | None = None
    model: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    ai_unavailable: bool | None = None
    deterministic_confidence: str | None = None
    ai_confidence: str | None = None
    confidence_warning: bool | None = None
    summary: str | None = None
    findings: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[dict[str, Any]] = Field(default_factory=list)
    attack_mappings: list[dict[str, Any]] = Field(default_factory=list)
    evidence_ids: list[dict[str, Any]] = Field(default_factory=list)


class AuditResponse(Extensible):
    audit_id: int | None = None
    timestamp: str
    actor: str | None = None
    action: str
    resource_type: str
    resource_id: str | None = None
    details: Any = None


class CorrelationExecutionResponse(Extensible):
    execution_id: str
    started_at: str
    completed_at: str | None = None
    status: str
    candidate_count: int | None = None
    edge_count: int | None = None
    errors: Any = None


class CorrelationRunResponse(Extensible):
    execution_id: str | None = None
    candidate_count: int = 0
    edge_count: int = 0
    incident_created: int = 0
    incident_updated: int = 0
    incident_merged: int = 0
    suppressed_count: int = 0
    error_count: int = 0
    errors: list[str] = Field(default_factory=list)


class DashboardSummary(BaseModel):
    active_incidents: int
    critical_incidents: int
    high_severity_alerts: int
    unresolved_alerts: int
    recent_investigations: int
    ioc_count: int
    detection_count: int


class DashboardTrends(BaseModel):
    days: int
    severity_distribution: list['TrendCount']
    alert_activity: list['TrendCount']
    incident_activity: list['TrendCount']
    top_sources: dict[str, list['TrendSource']]


class TrendCount(BaseModel):
    date: str | None = None
    severity: str | None = None
    count: int


class TrendSource(BaseModel):
    value: str
    count: int


class ActivityItem(BaseModel):
    id: str
    timestamp: str
    kind: str
    severity: str | None = None
    title: str | None = None


class DashboardActivity(Page[ActivityItem]):
    pass


class SearchResponse(BaseModel):
    query: str
    incidents: list['SearchIncident']
    alerts: list['SearchAlert']
    iocs: list['SearchIOC']


class SearchIncident(BaseModel):
    incident_id: str
    title: str | None = None
    status: str | None = None
    severity: str | None = None
    risk_score: int | None = None


class SearchAlert(BaseModel):
    alert_id: str
    timestamp: str | None = None
    severity: str | None = None
    status: str | None = None
    rule_id: str | None = None
    host: str | None = None
    user: str | None = None


class SearchIOC(BaseModel):
    ioc_id: str
    value: str
    type: str
    first_seen: str | None = None
    last_seen: str | None = None
