# Dependency Audit

## Python

Runtime dependencies are declared in `requirements.txt`: FastAPI, Pydantic, and Uvicorn. The project uses the standard library for SQLite, backup, replay, scenario, and benchmark tooling.

Ruff and Bandit are included in CI/security workflows when available. They were not installed in the local verification environment, so local results are reported as `SKIPPED`, not as passes.

## Frontend

Frontend dependencies and versions are declared in `frontend/package.json` and `frontend/package-lock.json`. The local npm audit command completed successfully during the final verification pass. No dependency was upgraded solely to manufacture a clean result.

Dependency results are environment-dependent and should be rerun in CI with `npm audit`, Ruff, and Bandit. Backups remain unencrypted and must be protected by the deployment environment.
