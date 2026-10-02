# Phase 2 ingestion and normalization

## Adapter architecture

`IngestionPipeline` validates a local regular file, hashes its bytes, checks the batch ledger, selects the first matching adapter, streams records, validates normalized fields, assigns stable IDs, and inserts in bounded chunks. Adapters implement `can_handle(source)` and `parse(source) -> Iterator[NormalizedEvent]`. JSON accepts JSON Lines and top-level arrays of event objects; Windows XML accepts multi-line documents containing `<Event>` records.

Automatic detection order is `auth_log`, `windows_events`, `json`, `syslog`, then `pcap_metadata`. Detection reads only the configured first `INGEST_DETECTION_LINES` records. `--adapter` bypasses detection and selects a named adapter directly.

## Normalized event fields

Normalized events use UTC `timestamp`, a controlled `event_type`, optional `source_type`, `hostname`, `username`, validated source/destination IPs, ports, protocol, `raw_event`, `raw_ref`, and `ingest_batch_id`. Missing optional values remain `None`. The raw source location is saved as the resolved path plus a line or row number.

Unrecognized source event names map to `unknown` and remain in `original_event_type`. The controlled vocabulary is documented in [data-model.md](data-model.md).

## Timestamp assumptions

ISO-8601 timestamps retain their supplied timezone and are converted to UTC. Naive datetimes use `INGEST_ASSUME_TZ` (default `UTC`). Epoch seconds and practical epoch milliseconds are supported. RFC3164 syslog timestamps without year use `INGEST_ASSUME_YEAR` when set, otherwise the processing year and configured timezone; a timestamp far ahead across a year boundary is assigned to the preceding year to avoid future-dating December records processed in January.

## Idempotency and batch lifecycle

The file SHA-256 plus resolved source path makes a deterministic batch ID. A previously completed file is not parsed again; a subsequent attempt records `skipped_duplicate_file`. Event IDs are `stable_id("evt", source_type, normalized_timestamp, raw_line, occurrence_index)`, where occurrence indices distinguish identical rows in the same file. SQLite uniqueness plus `INSERT OR IGNORE` prevents duplicate events.

Batch states are `running`, `completed`, `completed_with_errors`, `failed`, and `skipped_duplicate_file`. Batch rows track created, duplicate, invalid, and error counts separately. Events commit in configurable chunks, so a malformed row does not roll back earlier chunks. Recoverable record errors are skipped, counted, and only the first `INGEST_MAX_PARSE_ERRORS` diagnostics are retained. A configurable invalid-record percentage threshold can fail a batch after parsing.

## Security boundaries and resource limits

Ingestion is offline and never executes log contents or contacts extracted addresses. Symlink inputs are rejected; files must be regular and within `INGEST_MAX_FILE_BYTES`. Records are streamed with a configured line limit; invalid UTF-8 is decoded with replacement and recorded data is stripped of control characters. Raw event data is capped at `INGEST_MAX_RAW_BYTES`, while `raw_ref` points to the complete source location. SQL is parameterized. Windows XML containing `DOCTYPE` or `ENTITY` declarations is rejected before XML parsing. Binary `.pcap` and `.pcapng` files are deliberately rejected: the adapter accepts only exported metadata such as CSV, Zeek connection logs, or JSON.

## CLI

```bash
python -m ingestion tests/fixtures/auth.log
python -m ingestion tests/fixtures/security.json --adapter json
python -m ingestion tests/fixtures/windows_events.json --adapter windows_events --max-errors 20 --chunk-size 500
```

The command prints a JSON summary and returns a nonzero exit code for failed batches. Existing `python main.py` workflows are unchanged.
