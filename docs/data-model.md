# Data model

## Entities and relationships

| Entity | Purpose | Key relationships |
|---|---|---|
| `NormalizedEvent` | A normalized security telemetry record | Belongs to an ingestion batch; may later link to incidents/evidence |
| `IngestBatch` | One import attempt for a local source file | Has many events; keyed by deterministic source path and content hash |
| `Alert` | Existing detector finding | Backward-compatible legacy model |
| `Incident` | Existing correlated case | `evidence_links` can associate events; typed `evidence_refs` supports future entity kinds |
| `IOC`, `Asset`, `Analyst` | Existing Phase 1 models | Stored independently in SQLite |

## Normalized event field mapping

| Source field(s) | `NormalizedEvent` field | Notes |
|---|---|---|
| `timestamp`, `time`, `event_time`, RFC3164 timestamp, Windows `TimeCreated`, Zeek `ts` | `timestamp` | Required; stored in UTC ISO-8601 |
| `source_type` (adapter-assigned) | `source_type` | `auth_log`, `syslog`, `json`, `windows_events`, or `pcap_metadata` |
| `host`, `hostname`, `computer` | `hostname` | Optional; unavailable values are `None` |
| `user`, `username`, `account`, Windows account fields | `username` | Optional |
| `source_ip`, `src_ip`, `client_ip`, Windows `IpAddress`, Zeek `id.orig_h`, tshark `ip.src` | `source_ip` | Validated by `ipaddress`; malformed addresses invalidate a record |
| `destination_ip`, `dst_ip`, `server_ip`, Zeek `id.resp_h`, tshark `ip.dst` | `destination_ip` | Validated by `ipaddress` |
| `event_type`, `event`, `type`, Windows Event ID | `event_type` | Mapped to controlled vocabulary; unknown values stay `unknown` |
| original source record | `raw_event` | Sanitized and capped; `raw_ref` points to full source location |
| source file and record index | `raw_ref` | Resolved path plus line/row number or XML event index |
| source file and file hash | `ingest_batch_id` | Every repository-persisted event must reference its batch |
| tshark/Zeek packet count fields | `packet_count` | Optional non-negative integer |

Source-specific mapping is implemented by the adapters in `ingestion/adapters/`. JSON supports `timestamp/time/event_time`, `source_ip/src_ip/client_ip`, `destination_ip/dst_ip/server_ip`, `username/user/account`, `hostname/host/computer`, and `event_type/event/type`.

## Controlled event type vocabulary

`auth_failure`, `auth_success`, `logoff`, `account_created`, `account_enabled`, `account_disabled`, `account_deleted`, `account_lockout`, `password_change`, `privilege_assigned`, `group_membership_change`, `audit_log_cleared`, `service_created`, `network_connection`, and `unknown`.

Windows Event ID mapping: 4624→`auth_success`, 4625→`auth_failure`, 4634/4647→`logoff`, 4648→`auth_success`, 4672→`privilege_assigned`, 4720→`account_created`, 4722→`account_enabled`, 4724→`password_change`, 4725→`account_disabled`, 4726→`account_deleted`, 4732→`group_membership_change`, 4740→`account_lockout`, 4768/4769/4776→`auth_success`, 4771→`auth_failure`, 1102→`audit_log_cleared`, and 7045→`service_created`. Unmapped IDs produce `unknown` and remain in `original_event_type`.

## Timestamp and ID rules

Timestamps with an offset are converted to UTC. Naive values use `INGEST_ASSUME_TZ` (default `UTC`); epoch seconds and practical milliseconds are accepted. RFC3164 timestamps use `INGEST_ASSUME_YEAR` when explicitly set, otherwise the processing year with year-rollover correction for dates far in the future.

`stable_id(prefix, *parts)` joins stringified identity parts with `|`, hashes with SHA-256, and uses the first 16 hexadecimal characters. Batch IDs use resolved source path and file SHA-256. Ingestion event IDs use adapter source type, normalized timestamp, raw source record, and its occurrence index in that file. Thus identical records at the same time have distinct IDs within one file, and re-importing the same source is skipped at the batch level. IOC IDs use normalized type/value; legacy alert IDs use module, source, severity, attack type, and evidence.

## Ingestion and persistence

Adapters stream a bounded source file and produce normalized events. The pipeline validates timestamps, IP addresses, ports, vocabulary, and resource limits, then writes event chunks with `INSERT OR IGNORE`. Malformed records are skipped, counted, and retained as a bounded diagnostic sample. Batch statuses are `running`, `completed`, `completed_with_errors`, `failed`, and `skipped_duplicate_file`.

SQLite migration version 4 adds detailed batch counters and error summaries while preserving earlier batch columns and data. Event table indexes cover timestamp, source IP, and user. Foreign keys and WAL are enabled on every connection.

`evidence_links(incident_id,event_id)` has incident/event foreign keys and a uniqueness constraint. `evidence_refs(owner_type,owner_id,evidence_type,evidence_id)` offers a typed registry for linking additional evidence kinds without changing the incident-event relation.
