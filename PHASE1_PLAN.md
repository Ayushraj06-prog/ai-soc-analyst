# Repository review and Phase 1 plan

## Existing functionality

- `tools/url_checker.py`: heuristic URL risk checks.
- `tools/log_analyzer.py`: authentication log parsing and failed-login thresholds.
- `tools/port_scanner.py`: lab-oriented common-port scanner.
- `orchestrator.py`: runs modules, correlates a few findings, and exports reports.
- `models/alert.py`: shared alert object consumed by the existing tools.
- `ai/`: prompt construction, classification, ATT&CK mapping, Ollama reasoning, and report formatting.
- `main.py`: interactive CLI/demo entry point.

## Reuse and refactoring

Keep the independent URL, log, and scanner modules, their menu workflows, and the AI/report modules. Refactor around their outputs incrementally: standardize UTC timestamps and stable IDs, enrich the existing alert shape compatibly, replace string-based correlation with normalized events and explicit rules, and move state/configuration behind services and repositories. The current scanner should remain explicitly scoped to authorized labs.

## New work by phase

1. **Foundation (implemented here):** typed shared models, env-backed settings, SQLite schema/connection management, and repositories.
2. Ingestion and normalization adapters for text, JSON, syslog, Windows events, and PCAP metadata.
3. Externalized rule definitions and deterministic rule engine.
4. IOC extraction/deduplication and explainable ATT&CK mapping.
5. Temporal correlation, incident building, and risk scoring.
6. Evidence-bounded AI investigation and validated outputs.
7. FastAPI services and lifecycle/audit endpoints.
8. SOC dashboard connected to the API.
9. Safe simulated response playbooks and recommendations.
10. Synthetic attack scenarios, integration coverage, Docker, and documentation.

## Exact Phase 1 scope

- Add dependency-free data models for normalized events, incidents, IOCs, assets, and analyst identities.
- Preserve the legacy `Alert(...)` constructor while adding UTC ISO timestamps, unique IDs, confidence, status, rule, and MITRE fields.
- Add environment-backed settings and a local SQLite schema for alerts, incidents, IOCs, assets, analysts, and audit records.
- Add parameterized persistence repositories for alerts, incidents, and deduplicated IOCs.
- Keep all persistence opt-in until later phases call `initialize_storage()`; existing menu workflows remain independent.

The environment currently has no Pydantic installation. Phase 1 therefore uses standard-library dataclasses and SQLite, avoiding an undeclared runtime dependency; API schemas can add Pydantic when the API dependency set is introduced.
