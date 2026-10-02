"""Run synthetic scenarios through the existing SOC pipeline."""
import json
import shutil
import tempfile
from pathlib import Path

from app.config import settings
from correlation.service import CorrelationService
from database.database import Database
from detection.engine import DetectionEngine
from enrichment.service import EnrichmentService
from ingestion.pipeline import IngestionPipeline
from investigation.service import InvestigationService
from response.service import ResponseService
from scenarios.base import MockInvestigationProvider, Scenario


def _reset_database(path: Path) -> None:
    for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        candidate.unlink(missing_ok=True)


def run_scenario(scenario: Scenario, database_path: str | Path | None = None, *, reset=False, dry_run=False) -> dict:
    temporary = None
    if database_path is None:
        temporary = tempfile.TemporaryDirectory(prefix="soc-scenario-")
        database_path = Path(temporary.name) / "scenario.db"
    path = Path(database_path)
    if reset:
        _reset_database(path)
    database = Database(path)
    database.initialize()
    ingestion = IngestionPipeline(database)
    ingestion_result = ingestion.ingest(scenario.fixture, adapter_name="json")
    detection_result = DetectionEngine(database).run()
    enrichment_result = EnrichmentService(database, include_non_global_ips=True).run()
    correlation_result = CorrelationService(database).run()
    with database.read_session() as connection:
        incident_row = connection.execute("SELECT incident_id,risk_score FROM incidents ORDER BY created_at,incident_id LIMIT 1").fetchone()
        counts = {
            "events": connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "detections": connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
            "iocs": connection.execute("SELECT COUNT(*) FROM iocs").fetchone()[0],
            "incidents": connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
        }
    investigation = {"status": "not_run"}
    recommendations = []
    if incident_row:
        investigation = InvestigationService(database, provider=MockInvestigationProvider()).investigate(incident_row[0], created_by="scenario")
        recommendations = ResponseService(database).recommend(incident_row[0], actor="scenario") if not dry_run else ResponseService(database).recommend(incident_row[0], actor="scenario", dry_run=True)
    with database.read_session() as connection:
        audit_count = connection.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    result = {
        "scenario_id": scenario.scenario_id,
        "name": scenario.name,
        "status": "PASS",
        "database": str(path),
        "ingestion": ingestion_result,
        "detection": {"detections": len(detection_result)},
        "enrichment": enrichment_result,
        "correlation": correlation_result,
        "counts": counts,
        "risk_score": incident_row[1] if incident_row else None,
        "investigation": {"status": investigation.get("status"), "provider": investigation.get("provider", "mock")},
        "recommendations": len(recommendations),
        "simulated_actions": 0,
        "audit_records": audit_count,
    }
    expected = scenario.expected
    if expected:
        if counts["events"] != expected.get("events", counts["events"]): result["status"] = "FAIL"
        if counts["incidents"] not in expected.get("incident_counts", [counts["incidents"]]): result["status"] = "FAIL"
    if temporary is not None:
        temporary.cleanup()
    return result
