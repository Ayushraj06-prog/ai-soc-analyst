# AI SOC Analyst API (Phase 7)

## Architecture

The API is a versioned presentation and workflow layer. It queries the existing SQLite schema through read-only connections for reads and uses transactions for analyst edits. Explicit correlation calls `CorrelationService`; investigation calls the persisted Phase 6 `InvestigationService`. The API does not implement detection, enrichment, correlation, or LLM reasoning a second time. Schema migration 9 adds the Phase 9A simulation-only response foundation; the earlier Phase 7–8 tables and APIs remain compatible.

## Start locally

Install project dependencies with `python -m pip install -r requirements.txt`, then run:

```powershell
python -m api
```

The default bind is `127.0.0.1:8000`. Set `API_HOST` and `API_PORT` to override it. OpenAPI documents are at `/docs`, `/redoc`, and `/openapi.json`; application endpoints are under `/api/v1/`.

## Configuration

| Setting | Default | Purpose |
| --- | --- | --- |
| `API_HOST` | `127.0.0.1` | Local API bind address |
| `API_PORT` | `8000` | Local API port |
| `API_AUTH_ENABLED` | `false` | Enables the configured bearer-token boundary |
| `API_AUTH_TOKEN` | empty | Secret bearer token; required when auth is enabled |
| `API_CORS_ORIGINS` | `http://localhost:3000` | Comma-separated exact origins |

Unauthenticated mode is for local/lab use only. It is not a production security boundary. When enabled, requests must provide `Authorization: Bearer <API_AUTH_TOKEN>`. Configure a secret outside source control; this API does not create credentials or user identities. CORS uses explicit origins, and credentials are disabled.

## Endpoints

All collection routes accept `limit` (default 50, maximum 200) and `offset` (maximum 1,000,000) and return `{ "items": [], "total": 0, "limit": 50, "offset": 0 }`. Collection ordering is stable. Timestamp filters accept ISO-8601 and are normalized to UTC.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/health` | Process liveness |
| GET | `/api/v1/ready` | SQLite/schema readiness |
| GET | `/api/v1/alerts`, `/api/v1/alerts/{alert_id}` | Alert listing with exact filters, bounded text search and allowlisted sort; detail includes linked evidence/IOC/mapping context |
| GET | `/api/v1/events`, `/api/v1/events/{event_id}` | Normalized event listing and detail |
| GET | `/api/v1/iocs`, `/api/v1/iocs/{ioc_id}` | Stored IOC listing and detail with at most 100 related events, detections, and incidents; no external lookups |
| GET | `/api/v1/incidents`, `/api/v1/incidents/{incident_id}` | Incident listing, confidence/risk/date filters, detection count, and bounded detail; list `sort` accepts `created_desc`, `created_asc`, `risk_desc`, or `risk_asc` |
| GET | `/api/v1/dashboard/summary` | Exact persisted incident, alert, IOC, detection, and investigation counts |
| GET | `/api/v1/dashboard/trends?days=14` | Bounded daily alert/incident trends, severity counts, top observed sources |
| GET | `/api/v1/dashboard/activity` | Bounded activity page; optional `kind`, `severity`, and `since` filters |
| GET | `/api/v1/search?q=...` | Bounded grouped search across incidents, alerts, and IOCs |
| GET | `/api/v1/attack/mappings` | Paginated stored ATT&CK mappings and baseline-disagreement evidence |
| PATCH | `/api/v1/incidents/{incident_id}` | Analyst-owned `status` and `notes`; writes audit record |
| POST | `/api/v1/incidents/{incident_id}/investigate` | Phase 6 investigation; body `{ "force": false }` |
| GET | `/api/v1/incidents/{incident_id}/investigations` | Incident run history |
| GET | `/api/v1/investigations` | Paginated global run history, newest first |
| GET | `/api/v1/investigations/{investigation_id}` | Investigation result and evidence IDs |
| GET | `/api/v1/correlation/executions` | Read persisted executions only |
| POST | `/api/v1/correlation/run` | Explicit Phase 5 correlation call; optional `since` query |
| GET | `/api/v1/audit` | Read-only audit records and filters |

### Examples

```text
GET /api/v1/incidents?severity=HIGH&min_risk_score=50&limit=20
GET /api/v1/events?event_type=auth_failure&since=2026-01-01T00:00:00Z
PATCH /api/v1/incidents/INC-123
Content-Type: application/json

{ "status": "investigating", "notes": "Analyst review started." }
```

The incident patch rejects extra fields, so derived scores, evidence, identity, mappings, and correlation data cannot be set by clients. Update timestamps are generated server-side. Audit records are read-only through this API.

## Errors and security

Errors use `{ "error": { "code": "...", "message": "..." } }`. Input validation errors return 422; malformed filters return 400; missing resources return 404; conflicts return 409; readiness failure returns 503; unexpected failures return a generic 500 without traceback or SQL details. Request IDs are returned in `X-Request-ID`.

SQL is parameterized; only fixed, internal table and expression names are composed. Event raw data is treated as untrusted, bounded, and redacted for common credential fields. Secrets in payloads are omitted. No raw filesystem paths, prompts, or API keys are exposed. API responses are JSON and do not render log content as HTML. No endpoint performs external IOC enrichment or executes AI-provided commands.

This API does not include a distributed rate limiter. Production deployments should put it behind an authenticated reverse proxy/API gateway with rate limits and TLS. Keep unauthenticated mode on loopback and in a trusted lab only.

## Dashboard integration

A future dashboard should consume only `/api/v1` resources, honor pagination, handle 404/409/503 responses, and submit analyst-owned changes through the incident PATCH endpoint. Configure its exact origin in `API_CORS_ORIGINS`; do not rely on browser-side credentials stored in source code.

## Compatibility and limitations

Schema versions 1–8 retain their prior migration behavior, and version 9 adds response proposal/attempt storage and append-only response audit guards. Existing CLI commands remain separate and unchanged. Authentication is a single configured bearer token, not role-based identity; rate limiting is delegated to the deployment gateway. Incident and raw event detail is bounded (maximum 500 linked events; raw excerpt 2,000 characters). Correlation execution is explicit; GET endpoints never trigger it.

Phase 9A simulation-only response routes and CLI are documented in [response.md](response.md). Response audit rows reuse the existing `/api/v1/audit` endpoint.
