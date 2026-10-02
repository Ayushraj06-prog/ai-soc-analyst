"""FastAPI application exposing the existing SOC engine as /api/v1."""
import ipaddress
import logging
import uuid
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import Depends, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.dependencies import Analyst, get_service, require_auth
from api.errors import api_error
from api.schemas.common import IncidentPatch, InvestigateRequest, Page, Items, HealthResponse, ReadyResponse, SystemStatusResponse
from api.schemas.responses import (AlertResponse, EventResponse, IOCResponse, IncidentResponse,
    IncidentDetailResponse, InvestigationResponse, AuditResponse, CorrelationExecutionResponse,
    CorrelationRunResponse, DashboardSummary, DashboardTrends, DashboardActivity, SearchResponse,
    AttackMappingResponse)
from api.services.api_service import APIService
from app.config import settings, validate_production
from database.database import Database
from version import APP_NAME, __version__
from api.schemas.response import (ResponseActionRequest, ResponseDecisionRequest, ResponseRejectRequest,
    ResponseExecutionRequest, ResponseRollbackRequest, ResponseRecommendationRequest, ResponseActionResponse)
from api.schemas.assistant import AssistantChatRequest, AssistantChatResponse
from ai.assistant import ask as ask_assistant
from response.service import ResponseService, ResponseConflict, ResponseForbidden, ResponseNotFound

log = logging.getLogger("ai_soc.api")


def _ip(value):
    if value is None: return None
    try: return str(ipaddress.ip_address(value))
    except ValueError: api_error(400,"invalid_ip","IP address filter is invalid.")


def create_app(database=None, *, investigation_provider=None, initialize=True):
    db=database if isinstance(database,Database) else Database(database or settings.database_path)
    @asynccontextmanager
    async def lifespan(application):
        configuration_errors = validate_production(settings)
        if configuration_errors:
            raise RuntimeError("invalid production configuration: " + "; ".join(configuration_errors))
        if initialize and settings.api_auto_migrate:
            db.initialize()
        if db.current_version() > 9:
            raise RuntimeError("database schema is newer than this application supports")
        if settings.environment == "production" and db.current_version() != 9:
            raise RuntimeError("database schema must be migrated to version 9 before startup")
        log.info("AI SOC API starting")
        yield
        log.info("AI SOC API stopping")

    application=FastAPI(title=APP_NAME + " API",version=__version__,
        description="Versioned read and analyst workflow API for the AI SOC Analyst engine.",
        docs_url="/docs" if settings.api_docs_enabled else None,
        redoc_url="/redoc" if settings.api_docs_enabled else None,
        openapi_url="/openapi.json" if settings.api_docs_enabled else None,
        lifespan=lifespan)
    application.state.api_service=APIService(db,investigation_provider=investigation_provider)
    application.state.response_service=ResponseService(db)
    application.add_middleware(CORSMiddleware,allow_origins=list(settings.api_cors_origins),
        allow_credentials=False,allow_methods=["GET","POST","PATCH"],allow_headers=["Authorization","Content-Type","X-Request-ID"])

    @application.middleware("http")
    async def request_context(request, call_next):
        request_id=request.headers.get("x-request-id")
        if not request_id or len(request_id)>100: request_id=uuid.uuid4().hex
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > settings.api_max_body_bytes:
            return JSONResponse(status_code=413,content={"error":{"code":"request_too_large","message":"Request body exceeds the configured limit."},"request_id":request_id})
        if any(len(key)>100 or len(value)>4096 for key,value in request.query_params.multi_items()):
            return JSONResponse(status_code=400,content={"error":{"code":"invalid_filter","message":"Query parameter is too long."},"request_id":request_id})
        try:
            response=await call_next(request)
            response.headers["X-Request-ID"]=request_id
            response.headers["X-Content-Type-Options"]="nosniff"
            response.headers["Cache-Control"]="no-store"
            return response
        except Exception:
            log.exception("Unhandled API request failure request_id=%s path=%s",request_id,request.url.path)
            return JSONResponse(status_code=500,content={"error":{"code":"internal_error","message":"An unexpected error occurred."},"request_id":request_id})

    @application.get("/health", tags=["Health"], response_model=HealthResponse)
    def public_health():
        return {"status": "ok", "service": APP_NAME.lower().replace(" ", "-")}

    @application.get("/version", tags=["Health"])
    def public_version():
        return {"name": APP_NAME, "version": __version__}

    @application.get("/ready", tags=["Health"], response_model=ReadyResponse)
    def public_ready():
        result = application.state.api_service.ready()
        if result["status"] != "ready":
            return JSONResponse(status_code=503, content=result)
        return result

    @application.get("/liveness", tags=["Health"], response_model=HealthResponse)
    def public_liveness():
        return {"status": "ok", "service": APP_NAME.lower().replace(" ", "-")}

    @application.get("/readiness", tags=["Health"], response_model=ReadyResponse)
    def public_readiness():
        return public_ready()

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(request, exc):
        log.info("API input validation failed path=%s",request.url.path)
        return JSONResponse(status_code=422,content={"error":{"code":"validation_error","message":"Request parameters are invalid."}})

    from fastapi import HTTPException
    @application.exception_handler(HTTPException)
    async def http_error_handler(request, exc):
        detail=exc.detail
        if isinstance(detail,dict) and "code" in detail:
            error=detail
        else:
            error={"code":"request_error","message":str(detail) if isinstance(detail,str) else "The request could not be completed."}
        return JSONResponse(status_code=exc.status_code,content={"error":error},headers=exc.headers)

    @application.get("/api/v1/health",tags=["Health"],summary="Check API process health",response_model=HealthResponse)
    def health(service=Depends(get_service), _auth=Depends(require_auth)):
        return service.health()

    @application.get("/api/v1/ready",tags=["Health"],summary="Check database and schema readiness",response_model=ReadyResponse)
    def ready(service=Depends(get_service), _auth=Depends(require_auth)):
        result=service.ready()
        if result["status"]!="ready":
            return JSONResponse(status_code=503,content=result)
        return result

    @application.get("/api/v1/system/status", tags=["System"], summary="Read authenticated system status", response_model=SystemStatusResponse)
    def system_status(service=Depends(get_service), _auth=Depends(require_auth)):
        return service.system_status()

    @application.post("/api/v1/assistant/chat", tags=["Assistant"], summary="Ask the bounded SOC assistant", response_model=AssistantChatResponse)
    def assistant_chat(body: AssistantChatRequest, _auth=Depends(require_auth)):
        try:
            return ask_assistant(body.question, context=body.context)
        except ValueError as exc:
            api_error(422, "invalid_assistant_question", str(exc))

    @application.get("/api/v1/dashboard/summary",tags=["Dashboard"],summary="Read exact SOC dashboard counts",response_model=DashboardSummary)
    def dashboard_summary(service=Depends(get_service),_auth=Depends(require_auth)):
        return service.dashboard_summary()

    @application.get("/api/v1/dashboard/trends",tags=["Dashboard"],summary="Read bounded alert and incident trends",response_model=DashboardTrends)
    def dashboard_trends(days:int=Query(14,ge=1,le=90),service=Depends(get_service),_auth=Depends(require_auth)):
        return service.dashboard_trends(days=days)

    @application.get("/api/v1/dashboard/activity",tags=["Dashboard"],summary="List recent bounded SOC activity",response_model=DashboardActivity)
    def dashboard_activity(kind:Literal["detection","incident","investigation"]|None=Query(None),severity:str|None=Query(None,max_length=32),since:str|None=Query(None,max_length=64),limit:int=Query(50,ge=1,le=200),offset:int=Query(0,ge=0,le=1000000),service=Depends(get_service),_auth=Depends(require_auth)):
        try:return service.dashboard_activity(kind=kind,severity=severity,since=since,limit=limit,offset=offset)
        except ValueError as exc:api_error(400,"invalid_filter",str(exc))

    @application.get("/api/v1/search",tags=["Search"],summary="Search incidents, alerts, and IOCs",response_model=SearchResponse)
    def search(q:str=Query(...,min_length=2,max_length=120),limit:int=Query(10,ge=1,le=20),service=Depends(get_service),_auth=Depends(require_auth)):
        try:return service.search(q,limit=limit)
        except ValueError as exc:api_error(400,"invalid_query",str(exc))

    @application.get("/api/v1/alerts",tags=["Alerts"],summary="List persisted alerts and detections",response_model=Page[AlertResponse])
    def alerts(severity:str|None=Query(None,max_length=32),status:str|None=Query(None,max_length=32),rule_id:str|None=Query(None,max_length=100),mitre_technique:str|None=Query(None,max_length=32),host:str|None=Query(None,max_length=255),user:str|None=Query(None,max_length=255),source_ip:str|None=Query(None,max_length=64),since:str|None=Query(None,max_length=64),until:str|None=Query(None,max_length=64),search:str|None=Query(None,max_length=120),sort:Literal["timestamp_desc","timestamp_asc","severity_desc"]="timestamp_desc",limit:int=Query(50,ge=1,le=200),offset:int=Query(0,ge=0,le=1000000),service=Depends(get_service),_auth=Depends(require_auth)):
        try:return service.list_alerts(severity=severity,status=status,rule_id=rule_id,mitre_technique=mitre_technique,host=host,user=user,source_ip=_ip(source_ip),since=since,until=until,search=search,sort=sort,limit=limit,offset=offset)
        except ValueError as exc:api_error(400,"invalid_filter",str(exc))

    @application.get("/api/v1/alerts/{alert_id}",tags=["Alerts"],summary="Get an alert",response_model=AlertResponse)
    def alert_detail(alert_id:str,service=Depends(get_service),_auth=Depends(require_auth)):
        row=service.alert_detail(alert_id)
        if row is None:api_error(404,"alert_not_found","Alert was not found.")
        return row

    @application.get("/api/v1/events",tags=["Events"],summary="List normalized events",response_model=Page[EventResponse])
    def events(event_type:str|None=Query(None,max_length=100),source_type:str|None=Query(None,max_length=100),host:str|None=Query(None,max_length=255),user:str|None=Query(None,max_length=255),src_ip:str|None=Query(None,max_length=64),dst_ip:str|None=Query(None,max_length=64),since:str|None=Query(None,max_length=64),until:str|None=Query(None,max_length=64),limit:int=Query(50,ge=1,le=200),offset:int=Query(0,ge=0,le=1000000),service=Depends(get_service),_auth=Depends(require_auth)):
        try:return service.list_events(event_type=event_type,source_type=source_type,host=host,user=user,src_ip=_ip(src_ip),dst_ip=_ip(dst_ip),since=since,until=until,limit=limit,offset=offset)
        except ValueError as exc:api_error(400,"invalid_filter",str(exc))

    @application.get("/api/v1/events/{event_id}",tags=["Events"],summary="Get a normalized event",response_model=EventResponse)
    def event_detail(event_id:str,service=Depends(get_service),_auth=Depends(require_auth)):
        row=service.get_record("events","id",event_id)
        if row is None:api_error(404,"event_not_found","Event was not found.")
        return row

    @application.get("/api/v1/iocs",tags=["IOCs"],summary="List persisted indicators",response_model=Page[IOCResponse])
    def iocs(type:str|None=Query(None,max_length=40),value:str|None=Query(None,max_length=2048),first_seen:str|None=Query(None,max_length=64),last_seen:str|None=Query(None,max_length=64),limit:int=Query(50,ge=1,le=200),offset:int=Query(0,ge=0,le=1000000),service=Depends(get_service),_auth=Depends(require_auth)):
        try:return service.list_iocs(type=type,value=value,first_seen=first_seen,last_seen=last_seen,limit=limit,offset=offset)
        except ValueError as exc:api_error(400,"invalid_filter",str(exc))

    @application.get("/api/v1/iocs/{ioc_id}",tags=["IOCs"],summary="Get a persisted indicator",response_model=IOCResponse)
    def ioc_detail(ioc_id:str,service=Depends(get_service),_auth=Depends(require_auth)):
        row=service.ioc_detail(ioc_id)
        if row is None:api_error(404,"ioc_not_found","IOC was not found.")
        return row

    @application.get("/api/v1/attack/mappings",tags=["ATT&CK"],summary="List evidence-backed ATT&CK mappings",response_model=Page[AttackMappingResponse])
    def attack_mappings(technique_id:str|None=Query(None,max_length=32),limit:int=Query(50,ge=1,le=200),offset:int=Query(0,ge=0,le=1000000),service=Depends(get_service),_auth=Depends(require_auth)):
        return service.list_attack_mappings(technique_id=technique_id,limit=limit,offset=offset)

    @application.get("/api/v1/incidents",tags=["Incidents"],summary="List incidents",response_model=Page[IncidentResponse])
    def incidents(status:str|None=Query(None,max_length=32),severity:str|None=Query(None,max_length=32),risk_level:str|None=Query(None,max_length=32),min_risk_score:int|None=Query(None,ge=0,le=100),max_risk_score:int|None=Query(None,ge=0,le=100),primary_host:str|None=Query(None,max_length=255),primary_user:str|None=Query(None,max_length=255),primary_src_ip:str|None=Query(None,max_length=64),confidence:str|None=Query(None,max_length=32),since:str|None=Query(None,max_length=64),until:str|None=Query(None,max_length=64),sort:Literal["created_desc","created_asc","risk_desc","risk_asc"]="created_desc",limit:int=Query(50,ge=1,le=200),offset:int=Query(0,ge=0,le=1000000),service=Depends(get_service),_auth=Depends(require_auth)):
        if min_risk_score is not None and max_risk_score is not None and min_risk_score>max_risk_score:api_error(400,"invalid_filter","min_risk_score must not exceed max_risk_score")
        try:return service.list_incidents(status=status,severity=severity,risk_level=risk_level,min_risk_score=min_risk_score,max_risk_score=max_risk_score,primary_host=primary_host,primary_user=primary_user,primary_src_ip=_ip(primary_src_ip),confidence=confidence,since=since,until=until,limit=limit,offset=offset,sort=sort)
        except ValueError as exc:api_error(400,"invalid_filter",str(exc))

    @application.get("/api/v1/incidents/{incident_id}",tags=["Incidents"],summary="Get incident and bounded evidence detail",response_model=IncidentDetailResponse)
    def incident_detail(incident_id:str,service=Depends(get_service),_auth=Depends(require_auth)):
        result=service.incident_detail(incident_id)
        if result is None:api_error(404,"incident_not_found","Incident was not found.")
        return result

    @application.patch("/api/v1/incidents/{incident_id}",tags=["Incidents"],summary="Update analyst-owned incident fields",response_model=IncidentDetailResponse)
    def update_incident(incident_id:str,body:IncidentPatch,actor=Analyst,service=Depends(get_service)):
        try:result=service.update_incident(incident_id,body.model_dump(exclude_unset=True),actor)
        except ValueError as exc:api_error(400,"invalid_update",str(exc))
        if result is None:api_error(404,"incident_not_found","Incident was not found.")
        return result

    @application.post("/api/v1/incidents/{incident_id}/investigate",tags=["Investigations"],summary="Run the existing Phase 6 investigation workflow",response_model=InvestigationResponse)
    def investigate(incident_id:str,body:InvestigateRequest=InvestigateRequest(),actor=Analyst,service=Depends(get_service)):
        if service.incident_detail(incident_id) is None:api_error(404,"incident_not_found","Incident was not found.")
        try:result=service.investigate(incident_id,force=body.force,actor=actor)
        except ValueError as exc:api_error(409,"investigation_conflict",str(exc))
        if result is None:api_error(404,"incident_not_found","Incident was not found.")
        if result.get("status") in {"already_running","retry_limit"}:api_error(409,result["status"],"Investigation cannot start in the current state.")
        log.info("Investigation request finished incident_id=%s status=%s",incident_id,result.get("status"))
        return result

    @application.get("/api/v1/incidents/{incident_id}/investigations",tags=["Investigations"],summary="List investigations for an incident",response_model=Items[InvestigationResponse])
    def incident_investigations(incident_id:str,service=Depends(get_service),_auth=Depends(require_auth)):
        result=service.investigations(incident_id)
        if result is None:api_error(404,"incident_not_found","Incident was not found.")
        return {"items":result,"total":len(result)}

    @application.get("/api/v1/investigations",tags=["Investigations"],summary="List recent investigation runs",response_model=Page[InvestigationResponse])
    def investigations(limit:int=Query(50,ge=1,le=200),offset:int=Query(0,ge=0,le=1000000),service=Depends(get_service),_auth=Depends(require_auth)):
        return service.list_investigations(limit=limit,offset=offset)

    @application.get("/api/v1/investigations/{investigation_id}",tags=["Investigations"],summary="Get a completed or in-progress investigation",response_model=InvestigationResponse)
    def investigation_detail(investigation_id:str,service=Depends(get_service),_auth=Depends(require_auth)):
        result=service.investigation(investigation_id)
        if result is None:api_error(404,"investigation_not_found","Investigation was not found.")
        return result

    @application.get("/api/v1/correlation/executions",tags=["Correlation"],summary="List persisted correlation executions",response_model=Page[CorrelationExecutionResponse])
    def correlation_executions(limit:int=Query(50,ge=1,le=200),offset:int=Query(0,ge=0,le=1000000),service=Depends(get_service),_auth=Depends(require_auth)):
        page=service.correlation_executions(limit=limit,offset=offset)
        for item in page["items"]:
            try:item["errors"]=__import__("json").loads(item["errors"] or "[]")
            except ValueError:item["errors"]=[]
        return page

    @application.post("/api/v1/correlation/run",tags=["Correlation"],summary="Explicitly run the existing Phase 5 correlation service",response_model=CorrelationRunResponse)
    def run_correlation(since:str|None=Query(None,max_length=64),actor=Analyst,service=Depends(get_service)):
        try:return service.run_correlation(since=since,actor=actor)
        except ValueError as exc:api_error(400,"invalid_timestamp",str(exc))

    @application.get("/api/v1/audit",tags=["Audit"],summary="List read-only audit records",response_model=Page[AuditResponse])
    def audit(action:str|None=Query(None,max_length=100),actor:str|None=Query(None,max_length=100),resource_type:str|None=Query(None,max_length=100),resource_id:str|None=Query(None,max_length=255),since:str|None=Query(None,max_length=64),until:str|None=Query(None,max_length=64),limit:int=Query(50,ge=1,le=200),offset:int=Query(0,ge=0,le=1000000),service=Depends(get_service),_auth=Depends(require_auth)):
        try:return service.list_audit(action=action,actor=actor,resource_type=resource_type,resource_id=resource_id,since=since,until=until,limit=limit,offset=offset)
        except ValueError as exc:api_error(400,"invalid_filter",str(exc))

    def _response_call(function, *args, **kwargs):
        try:return function(*args, **kwargs)
        except ResponseNotFound as exc:api_error(404,"response_not_found",str(exc))
        except ResponseConflict as exc:api_error(409,"response_conflict",str(exc))
        except ResponseForbidden as exc:api_error(403,"response_blocked",str(exc))
        except ValueError as exc:api_error(422,"invalid_response_action",str(exc))

    @application.post("/api/v1/incidents/{incident_id}/response/recommend",tags=["Response"],summary="Create deterministic simulation-only action proposals",response_model=list[ResponseActionResponse])
    def response_recommend(incident_id:str,body:ResponseRecommendationRequest=ResponseRecommendationRequest(),actor=Analyst,request:Request=None):
        service=request.app.state.response_service
        return _response_call(service.recommend,incident_id,actor=actor,via="api",dry_run=body.dry_run)

    @application.post("/api/v1/incidents/{incident_id}/response/actions",tags=["Response"],summary="Propose one evidence-bound simulation-only response action",response_model=ResponseActionResponse)
    def response_propose(incident_id:str,body:ResponseActionRequest,actor=Analyst,request:Request=None):
        service=request.app.state.response_service
        return _response_call(service.propose,incident_id,body.action_type,target=body.target,target_type=body.target_type,
            parameters=body.parameters,actor=actor,via="api",supersedes=body.supersedes)

    @application.get("/api/v1/incidents/{incident_id}/response/actions",tags=["Response"],summary="List response actions for an incident",response_model=list[ResponseActionResponse])
    def response_list(incident_id:str,request:Request, _auth=Depends(require_auth)):
        service=request.app.state.response_service
        with service.db.read_session() as c:
            if c.execute("SELECT 1 FROM incidents WHERE incident_id=?",(incident_id,)).fetchone() is None:
                api_error(404,"incident_not_found","Incident was not found.")
        return service.list_for_incident(incident_id)

    @application.get("/api/v1/response/actions/{action_id}",tags=["Response"],summary="Read a response action",response_model=ResponseActionResponse)
    def response_get(action_id:str,request:Request,_auth=Depends(require_auth)):
        return _response_call(request.app.state.response_service.get,action_id)

    @application.post("/api/v1/response/actions/{action_id}/approve",tags=["Response"],summary="Approve a pending response proposal",response_model=ResponseActionResponse)
    def response_approve(action_id:str,body:ResponseDecisionRequest,actor=Analyst,request:Request=None):
        return _response_call(request.app.state.response_service.approve,action_id,expected_status=body.expected_status,actor=actor,via="api")

    @application.post("/api/v1/response/actions/{action_id}/reject",tags=["Response"],summary="Reject a pending response proposal",response_model=ResponseActionResponse)
    def response_reject(action_id:str,body:ResponseRejectRequest,actor=Analyst,request:Request=None):
        return _response_call(request.app.state.response_service.reject,action_id,expected_status=body.expected_status,actor=actor,reason=body.reason,via="api")

    @application.post("/api/v1/response/actions/{action_id}/execute",tags=["Response"],summary="Execute a simulation only",response_model=ResponseActionResponse)
    def response_execute(action_id:str,body:ResponseExecutionRequest,actor=Analyst,request:Request=None):
        return _response_call(request.app.state.response_service.execute,action_id,expected_status=body.expected_status,actor=actor,via="api")

    @application.post("/api/v1/response/actions/{action_id}/rollback",tags=["Response"],summary="Roll back simulated state only",response_model=ResponseActionResponse)
    def response_rollback(action_id:str,body:ResponseRollbackRequest,actor=Analyst,request:Request=None):
        return _response_call(request.app.state.response_service.rollback,action_id,expected_status=body.expected_status,actor=actor,via="api")

    return application


app=create_app()
