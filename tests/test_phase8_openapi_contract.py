"""Detect stale generated TypeScript when FastAPI's OpenAPI schema changes."""
import hashlib
import json
import re
import unittest
from pathlib import Path

from api.app import app


class OpenAPIFrontendContractTests(unittest.TestCase):
    def test_generated_types_match_current_openapi_digest(self):
        project = Path(__file__).resolve().parents[1]
        generated = project / "frontend" / "src" / "api" / "generated.ts"
        self.assertTrue(generated.exists(), "Run `npm run generate:api` in frontend/")
        source = generated.read_text(encoding="utf-8")
        match = re.match(r"// OpenAPI-SHA256: ([0-9a-f]{64})\n", source)
        self.assertIsNotNone(match, "Generated file is missing its OpenAPI contract digest")
        canonical = json.dumps(app.openapi(), sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.assertEqual(match.group(1), expected, "OpenAPI changed; regenerate frontend/src/api/generated.ts")

    def test_dashboard_contracts_have_typed_responses_and_server_sort(self):
        schema = app.openapi()
        for path in ("/api/v1/alerts", "/api/v1/incidents", "/api/v1/incidents/{incident_id}"):
            body = schema["paths"][path]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
            self.assertIn("$ref", body)
        sort = next(p for p in schema["paths"]["/api/v1/incidents"]["get"]["parameters"] if p["name"] == "sort")
        self.assertEqual(sort["schema"]["enum"], ["created_desc", "created_asc", "risk_desc", "risk_asc"])


if __name__ == "__main__":
    unittest.main()
