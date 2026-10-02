import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from backup.service import create_backup, restore_backup
from app.config import Secret, Settings, effective_config, validate_production
from database.database import Database
from api.app import create_app
from version import __version__


class Phase10HardeningTests(unittest.TestCase):
    def test_secret_is_masked_and_production_rejects_unsafe_defaults(self):
        self.assertEqual(repr(Secret("PHASE10_SECRET_CANARY")), "Secret('********')")
        self.assertNotIn("PHASE10_SECRET_CANARY", repr(effective_config()))
        development_errors = validate_production(Settings(environment="production"))
        self.assertTrue(any("API_AUTH_ENABLED" in error for error in development_errors))
        errors = validate_production(Settings(
            environment="production",
            api_auth_enabled=True,
            api_auth_token=Secret("change-me"),
            api_docs_enabled=False,
            api_auto_migrate=False,
        ))
        self.assertTrue(any("API_AUTH_TOKEN" in error for error in errors))

    def test_backup_and_restore_verify_database(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "soc.db"
            backup = root / "backup.db"
            restored = root / "restored.db"
            Database(source).initialize()
            created = create_backup(source, backup)
            self.assertEqual(created, backup)
            if os.name != "nt":
                self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            manifest = json.loads((root / "backup.db.manifest.json").read_text())
            self.assertEqual(manifest["schema_version"], 9)
            restore_backup(backup, restored)
            self.assertTrue(restored.exists())
            with Database(restored).read_session() as connection:
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_public_operational_endpoints_and_version(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "soc.db")
            database.initialize()
            with patch("api.dependencies.settings", SimpleNamespace(api_auth_enabled=False)):
                from fastapi.testclient import TestClient
                client = TestClient(create_app(database))
                self.assertEqual(client.get("/health").status_code, 200)
                self.assertEqual(client.get("/version").json()["version"], __version__)
                self.assertEqual(client.get("/ready").status_code, 200)
                self.assertEqual(client.get("/health").headers["x-content-type-options"], "nosniff")


if __name__ == "__main__":
    unittest.main()
