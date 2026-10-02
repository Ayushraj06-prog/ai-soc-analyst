# Demo

The existing project supports deterministic local workflows through its ingestion, detection, enrichment, correlation, investigation, and response commands. Phase 10 deployment verification does not contact real targets.

Use a separate database path for demonstrations:

```powershell
$env:SOC_ENVIRONMENT = 'demo'
$env:SOC_DATABASE_PATH = 'demo.db'
python -m ingestion --help
python -m detection --help
python -m enrichment --help
python -m correlation --help
python -m investigation --help
```

Use documentation-only addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, or `2001:db8::/32`) and `.example` or `.test` domains in synthetic fixtures. Do not use production data, credentials, real public targets, or real company domains.

No screenshots or benchmark numbers are claimed here. Capture screenshots from the running dashboard after starting the backend and frontend locally.
