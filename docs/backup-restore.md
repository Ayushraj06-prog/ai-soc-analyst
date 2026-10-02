# Backup and Restore

Create a backup using:

```powershell
python -m backup create --destination backups/soc.db
```

The command uses `sqlite3.Connection.backup()`, validates `PRAGMA integrity_check` and `PRAGMA foreign_key_check`, and writes a JSON manifest containing schema version, application version, UTC creation time, SHA-256, and database size. Backup and manifest files request mode `0600` on Unix systems.

Restore using:

```powershell
python -m backup restore backups/soc.db --target data/soc.db
```

Restore validation occurs in a temporary database before replacement. An existing database receives a `.pre-restore` backup, and the restored database receives a `database.restored` audit record. Symlinks and backups with newer schemas are rejected.

Backups are currently unencrypted and must be protected by the deployment environment.
