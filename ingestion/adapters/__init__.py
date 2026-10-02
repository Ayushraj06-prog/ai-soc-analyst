"""Offline event adapters, ordered from specific to general by the pipeline."""
from ingestion.adapters.auth_log import AuthLogAdapter
from ingestion.adapters.windows_events import WindowsEventsAdapter
from ingestion.adapters.json_adapter import JsonAdapter
from ingestion.adapters.syslog import SyslogAdapter
from ingestion.adapters.pcap_metadata import PcapMetadataAdapter

__all__ = ["AuthLogAdapter", "WindowsEventsAdapter", "JsonAdapter", "SyslogAdapter", "PcapMetadataAdapter"]
