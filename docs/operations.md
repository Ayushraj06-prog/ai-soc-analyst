# Operations

## Configuration

Run `python -m config` to print effective configuration with secrets redacted. Production startup rejects development authentication, short or placeholder tokens, wildcard/empty CORS, enabled docs, and automatic API migration.

## Verification

Run `python -m tests.verify`. Each stage reports `PASS`, `FAIL`, or `SKIPPED`; use `--require-all` when optional frontend tools must be present.

## Backups

Create a verified SQLite backup with `python -m backup create`. Restore with `python -m backup restore <backup>`. See [backup and restore](backup-restore.md).

## Logs and health

Application logs are intended for stdout. Use `/health` for container liveness, `/ready` for database readiness, and authenticated API status endpoints for detailed operational information. Do not use readiness as a Docker liveness check.
