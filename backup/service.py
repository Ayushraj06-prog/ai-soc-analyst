"""Validated SQLite backup and restore operations."""
import hashlib
import json
import os
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from app.config import settings
from database.database import Database, MIGRATIONS
from version import __version__


class BackupError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _schema_version(connection: sqlite3.Connection) -> int:
    row = connection.execute("SELECT COALESCE(MAX(version), 0) FROM schema_version").fetchone()
    return int(row[0]) if row else 0


def _verify(connection: sqlite3.Connection) -> None:
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity != "ok":
        raise BackupError(f"SQLite integrity check failed: {integrity}")
    foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    if foreign_keys:
        raise BackupError("SQLite foreign-key check failed")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_backup(source: Path | None = None, destination: Path | None = None) -> Path:
    source = Path(source or settings.database_path)
    if not source.exists() or source.is_symlink():
        raise BackupError("active database does not exist or is a symlink")
    destination = Path(destination or settings.data_dir / "backups" / f"soc-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.db")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(source)) as source_connection:
        source_connection.execute("PRAGMA foreign_keys=ON")
        with tempfile.NamedTemporaryFile(prefix="backup-", suffix=".db", dir=destination.parent, delete=False) as temporary:
            temporary_path = Path(temporary.name)
        try:
            with closing(sqlite3.connect(temporary_path)) as target_connection:
                source_connection.backup(target_connection)
                target_connection.execute("PRAGMA foreign_keys=ON")
                _verify(target_connection)
                target_connection.commit()
            os.chmod(temporary_path, 0o600)
            temporary_path.replace(destination)
        finally:
            temporary_path.unlink(missing_ok=True)
    manifest = destination.with_suffix(destination.suffix + ".manifest.json")
    with closing(sqlite3.connect(destination)) as connection:
        schema_version = _schema_version(connection)
    manifest.write_text(json.dumps({
        "schema_version": schema_version,
        "application_version": __version__,
        "created_at": _utc_now(),
        "sha256": _sha256(destination),
        "database_size": destination.stat().st_size,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(destination, 0o600)
    os.chmod(manifest, 0o600)
    return destination


def restore_backup(backup: Path, target: Path | None = None) -> Path:
    backup = Path(backup)
    target = Path(target or settings.database_path)
    if backup.is_symlink() or not backup.is_file():
        raise BackupError("backup must be a regular file and symlinks are not accepted")
    with closing(sqlite3.connect(backup)) as backup_connection:
        backup_connection.execute("PRAGMA foreign_keys=ON")
        _verify(backup_connection)
        schema_version = _schema_version(backup_connection)
    latest = max(MIGRATIONS)
    if schema_version > latest:
        raise BackupError("backup schema is newer than this application supports")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix="restore-", suffix=".db", dir=target.parent, delete=False) as temporary:
        temporary_path = Path(temporary.name)
    try:
        with closing(sqlite3.connect(backup)) as source_connection, closing(sqlite3.connect(temporary_path)) as target_connection:
            source_connection.backup(target_connection)
            target_connection.execute("PRAGMA foreign_keys=ON")
            _verify(target_connection)
            target_connection.commit()
        os.chmod(temporary_path, 0o600)
        if target.exists() and target.is_symlink():
            raise BackupError("active database cannot be a symlink")
        if target.exists():
            pre_restore = target.with_name(target.name + ".pre-restore")
            create_backup(target, pre_restore)
        temporary_path.replace(target)
        os.chmod(target, 0o600)
        with Database(target).session() as connection:
            connection.execute(
                "INSERT INTO audit_log(timestamp,actor,action,entity_type,entity_id,details) VALUES(?,?,?,?,?,?)",
                (_utc_now(), "system", "database.restored", "database", str(target.name), json.dumps({"schema_version": schema_version})),
            )
        return target
    finally:
        temporary_path.unlink(missing_ok=True)
