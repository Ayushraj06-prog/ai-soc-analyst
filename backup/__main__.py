"""CLI: python -m backup create|restore."""
import argparse
from pathlib import Path

from backup.service import BackupError, create_backup, restore_backup


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m backup")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--source", type=Path)
    create.add_argument("--destination", type=Path)
    restore = subparsers.add_parser("restore")
    restore.add_argument("backup", type=Path)
    restore.add_argument("--target", type=Path)
    args = parser.parse_args(argv)
    try:
        path = create_backup(args.source, args.destination) if args.command == "create" else restore_backup(args.backup, args.target)
    except BackupError as exc:
        parser.error(str(exc))
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
