"""Database maintenance commands."""
import argparse
import sqlite3
from pathlib import Path

from backup.service import BackupError, create_backup, restore_backup
from database.database import Database


def verify_database(path: Path) -> dict[str, str | int]:
    with sqlite3.connect(path) as connection:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        version = connection.execute("SELECT COALESCE(MAX(version), 0) FROM schema_version").fetchone()[0]
    if integrity != "ok" or foreign_keys:
        raise BackupError("database verification failed")
    return {"schema_version": version, "integrity": integrity, "foreign_keys": "ok"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m database")
    subparsers = parser.add_subparsers(dest="command", required=True)
    backup = subparsers.add_parser("backup")
    backup.add_argument("path", type=Path)
    verify = subparsers.add_parser("verify")
    verify.add_argument("path", type=Path)
    restore = subparsers.add_parser("restore")
    restore.add_argument("path", type=Path)
    restore.add_argument("--target", type=Path)
    args = parser.parse_args(argv)
    if args.command == "backup":
        print(create_backup(destination=args.path))
    elif args.command == "restore":
        print(restore_backup(args.path, args.target))
    else:
        print(verify_database(args.path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
