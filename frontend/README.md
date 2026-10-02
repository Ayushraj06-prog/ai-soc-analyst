# Phase 8A dashboard

## Local setup

1. Install backend/API requirements in the Python environment.
2. Start the API from the project root: `python -m api`.
3. Copy `.env.example` to `.env.local` and set `VITE_API_AUTH_ENABLED=true` only when the backend uses `API_AUTH_ENABLED=true`. Set `API_PROXY_TARGET` for the Vite development proxy if the API is not on `127.0.0.1:8000`.
4. Run `npm ci`, then `npm run dev`.

For remote API access, set `VITE_API_BASE_URL` to the API base ending in `/api/v1` and use HTTPS. Never place the bearer token in a `VITE_*` variable. The login screen holds it in sessionStorage unless the user explicitly selects localStorage.

## OpenAPI types

Generate the committed client types from the FastAPI schema with `npm run generate:api`. The script imports the backend app, feeds the live schema to `openapi-typescript`, and embeds a SHA-256 digest. `python -m unittest discover` checks the current backend OpenAPI digest against that generated file; a schema change requires regeneration.

## Checks

Run `npm run typecheck`, `npm run lint`, `npm test`, and `npm run build`. The backend suite remains `python -m unittest discover`.

The app bundles its JavaScript and CSS locally; it does not use CDN assets or external fonts. For production, serve same-origin assets with a strict CSP such as `default-src 'self'; connect-src 'self' <API_ORIGIN>; frame-ancestors 'none';`, plus `object-src 'none'` and appropriate security headers. Keep API CORS restricted to exact dashboard origins.

This phase contains no response automation. Aggregate metrics and timeline visualization remain deferred until Phase 8C; investigation and audit navigation remains marked unavailable until Phase 8B.
# Phase 8B + 8C analyst workspaces

See [docs/dashboard.md](../docs/dashboard.md) for page structure, API dependencies, authentication, analyst workflow, investigation design, security handling, and limitations.

The dashboard includes bounded SOC summary/trend/activity views, alert triage, incident timelines and linked evidence, IOC and ATT&CK exploration, global search, investigation runs/history, analyst audit history, and browser-local API/time settings. All AI recommendations are advisory and no defensive actions are automated.

