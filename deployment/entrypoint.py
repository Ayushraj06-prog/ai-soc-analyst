"""Container startup: validate config, migrate explicitly, then start one worker."""
import os
import subprocess
import sys

from app.config import settings, validate_production
from database.database import Database, MIGRATIONS


def main() -> int:
    errors = validate_production(settings)
    if errors:
        print("configuration rejected: " + "; ".join(errors), file=sys.stderr)
        return 78
    database = Database(settings.database_path)
    current = database.current_version()
    latest = max(MIGRATIONS)
    if current > latest:
        print(f"database schema {current} is newer than supported schema {latest}", file=sys.stderr)
        return 78
    database.migrate()
    if database.current_version() != latest:
        print("database migration did not reach the supported schema", file=sys.stderr)
        return 78
    command = [sys.executable, "-m", "uvicorn", "api.app:app", "--host", settings.api_host, "--port", str(settings.api_port), "--workers", "1"]
    os.execv(command[0], command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
