# Phase Map

Phases 1-9 provide the core defensive SOC workflow: typed models and SQLite persistence, ingestion, deterministic detection, IOC/ATT&CK enrichment, correlation, bounded AI investigation, FastAPI, React dashboard, and simulation-only response/playbooks.

Phase 10 adds production-readiness tooling without changing those semantics:

- deterministic synthetic scenarios in `scenarios/`
- replay comparison in `replay/`
- static security checks in `security/`
- local measurements in `benchmarks/`
- container and CI configuration
- frontend system status backed by authenticated API data
- synthetic end-to-end smoke validation

The current SQLite schema version is 9. Phase 9 playbook execution tables are created lazily by the response service to preserve the established migration contract.
