"""Ingestion validation and adapter errors."""


class IngestionError(Exception):
    """Fatal file- or batch-level ingestion failure."""


class NoAdapterError(IngestionError):
    """No configured adapter recognized a source."""


class RecordParseError(ValueError):
    """One source record could not be parsed; ingestion may continue."""


class UnsafeSourceError(IngestionError):
    """Source path or content violates an ingestion safety limit."""
