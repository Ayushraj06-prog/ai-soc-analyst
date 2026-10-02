import unittest

from api.app import create_app
from database.database import Database


PUBLIC_PATHS = {"/health", "/ready", "/version"}


class Phase10RouteInventoryTests(unittest.TestCase):
    def test_non_public_routes_have_auth_dependency_and_contract_metadata(self):
        database = Database(":memory:")
        app = create_app(database, initialize=False)
        for route in app.routes:
            if not hasattr(route, "path") or route.path in PUBLIC_PATHS:
                continue
            if not route.path.startswith("/api/"):
                continue
            self.assertTrue(route.tags, route.path)
            self.assertTrue(route.summary, route.path)
            self.assertTrue(route.response_model, route.path)
            dependencies = getattr(route.dependant, "dependencies", [])
            dependency_names = {getattr(item.call, "__name__", "") for item in dependencies}
            self.assertIn("require_auth", dependency_names, route.path)

    def test_public_surface_is_minimal(self):
        app = create_app(Database(":memory:"), initialize=False)
        paths = {route.path for route in app.routes if hasattr(route, "path")}
        self.assertTrue(PUBLIC_PATHS.issubset(paths))
        self.assertNotIn("/metrics", paths)


if __name__ == "__main__":
    unittest.main()
