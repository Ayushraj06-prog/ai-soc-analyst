"""Shared application dependencies."""
from app.config import settings
from database.database import Database
from database.repositories import (AlertRepository, AnalystRepository, AssetRepository,
    EventRepository, IncidentRepository, IOCRepository)

database = Database(settings.database_path)
alert_repository = AlertRepository(database)
incident_repository = IncidentRepository(database)
ioc_repository = IOCRepository(database)
event_repository = EventRepository(database)
asset_repository = AssetRepository(database)
analyst_repository = AnalystRepository(database)


def initialize_storage() -> None:
    database.initialize()
