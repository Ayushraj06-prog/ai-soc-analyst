# Phase 8B + 8C dashboard

## Architecture

The browser client is a React/TypeScript single-page application under `frontend/src`. `api/client.ts` owns request construction, generated OpenAPI types, bearer authentication, cancellation, query encoding, and error normalization. `src/api/generated.ts` is produced from FastAPI OpenAPI with `npm run generate:api`; `tests/test_phase8_openapi_contract.py` checks the embedded schema digest.

The UI uses bounded backend pages for alerts, incidents, IOCs, investigation runs, ATT&CK mappings, and audit records. The dashboard summary and trend endpoints aggregate counts in SQLite rather than deriving totals from partial browser pages. Dashboard activity is a bounded, paginated union of persisted alerts, incidents, and investigations. Global search returns at most 20 matches per group for incidents, alerts, and IOCs.

## Page structure

- `/` shows exact KPIs, severity distribution, 14-day alert and incident creation trends, top observed alert sources, and filtered recent activity.
- `/alerts` and `/alerts/:alertId` support exact filters, text search, fixed sort choices, paging, linked incident navigation, ATT&CK data, IOC relationships, and bounded evidence.
- `/incidents` and `/incidents/:incidentId` show server-side filters/sort, a chronological linked-event timeline, detection/IOC/ATT&CK relationships, analyst-owned status/notes, investigation history/comparison, and incident audit history.
- `/iocs` and `/iocs/:iocId` show observed indicators and bounded related events, detections, and incidents.
- `/investigations` and `/investigations/:investigationId` show Phase 6 runs, evidence links, findings, and advisory recommendations.
- `/attack`, `/audit`, `/search`, and `/events/:eventId` provide evidence-backed mapping review, audit browsing, grouped bounded search, and safe event inspection.

## API dependencies

Phase 8B adds authenticated read-only `GET /api/v1/dashboard/summary`, `/dashboard/trends`, `/dashboard/activity`, `/search`, `/attack/mappings`, and `/investigations` routes. Existing alert listing gains search and allowlisted sorting; incident listing gains confidence filtering and detection counts; IOC detail includes bounded occurrence and relation data. Existing Phase 6 investigation execution and Phase 7 incident PATCH routes are reused. No new database schema or migration is required.

## Authentication and security

The shared Phase 7 bearer token is entered at login, stored in `sessionStorage` by default, and stored in `localStorage` only after explicit opt-in. It never appears in URLs, generated build configuration, or rendered text. HTTP 401 clears the token; HTTP 403 has a separate permission state. Security event values, IOC values, summaries, audit details, and AI text are rendered as inert React text, sanitized for control/bidirectional characters, and bounded. IOC links route only to local IOC detail pages; values are never used as external hrefs. Server search binds user input as escaped SQL parameters and uses fixed query shapes. API error responses do not disclose 500-level internals.

## Analyst and investigation workflow

Analysts can update only the backend-owned incident `status` and `notes` fields. Updates use PATCH and are refetched after save; 409 conflicts require explicit reload. “Run AI Investigation” invokes the existing Phase 6 endpoint only after an analyst click. Run output, findings, and recommendations are labeled AI-generated/advisory and are never executed by the dashboard. Evidence IDs and model/provider metadata are shown when the backend provides them.

## Known limitations

Dashboard activity is limited to detections, incident creation, and investigation runs because those sources have reliable persisted timestamps in the current API. Search groups incidents, alerts, and IOCs; event/user/host/rule matches are returned through those records rather than a separate event result group. Trends are daily aggregate counts for alerts and incident creation. No automated response, remediation, or Phase 9 workflow is present.
