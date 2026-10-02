# Phase 4 IOC enrichment

## Architecture

`python -m enrichment` reads events already stored in SQLite. Extraction and mapping are deterministic, local-only operations: there are no reputation API calls, DNS lookups, or other network enrichment. IOC records live in the Phase 1 `iocs` table, extended by migration 6; `ioc_events` records event provenance, `ioc_detection_links` records detection relationships, `enrichment_state` tracks per-event processing, and `attack_mappings` stores Phase 4 evidence-validated mappings. Every event is processed in its own transaction so one malformed row does not roll back its neighbors.

## IOC types and normalization

Supported types are IPv4, IPv6, domains, URLs (HTTP, HTTPS, FTP), email addresses, MD5, SHA1, SHA256, and optionally structured file paths. Usernames are not extracted as IOCs. Defanged forms such as `hxxp://` and `example[.]com` are **not supported** and are not silently repaired.

| Type | Normalization |
| --- | --- |
| IP | `ipaddress` canonical form; IPv4-mapped IPv6 collapses to IPv4. IPv6 zone suffixes (for example `%eth0`) are discarded because they are interface-local metadata. Classification is stored as `private`, `loopback`, `link_local`, `multicast`, or `global`. |
| Domain | Lowercase IDNA ASCII, validated labels and TLD syntax; `.local` and common file extensions are excluded. |
| URL | Lowercase scheme and host only; preserve path case, query, and fragment; remove default HTTP/HTTPS/FTP ports. URLs do not emit a second domain IOC for their host. URLs with user-info are rejected. |
| Email | Preserve local-part case; lowercase and validate the domain. |
| Hash | Lowercase hexadecimal; longest-first word-bounded recognition prevents a SHA256 from also becoming an MD5. |
| File path | Structured fields only by default (`image`, `target_filename`, `file_path`, `executable_path`, and command-line path tokens). |

Private and internal IPs remain IOCs by default. Set `IOC_INCLUDE_NON_GLOBAL_IPS=false` to filter non-global addresses for an installation that does not want them stored. Raw path extraction is off by default; `IOC_EXTRACT_RAW_PATHS=true` enables it.

All scanned free text is capped at 262,144 characters per event, URLs at 2,048 characters, domains at 255 characters, and paths at 1,024 characters. Control characters and ANSI escape sequences are stripped. Regexes are bounded and linear/simple; no input is executed.

## Confidence and deduplication

Confidence is fixed per extraction source: structured field **0.95 (HIGH)**, strong hash keyword context **0.70 (MEDIUM)**, and raw text regex **0.40 (LOW)**. On repeated observation, the highest confidence is retained and the strongest source field is retained. IOC identity is a stable hash of normalized type and value; processing time is never part of identity.

`ioc_events` is unique on `(ioc_id, event_id)`. If multiple sources in one event identify the same value, the row retains the highest-confidence source instead of adding redundant provenance rows. `occurrence_count` is the count of unique event relationships, not raw regex hits or enrichment runs. `first_seen` and `last_seen` are derived from the minimum/maximum linked event timestamps.

Enrichment state is recorded for successful and failed event processing. Ordinary runs skip any event already in the state table; `--force` retries all matching events. A failed event is therefore retried explicitly with `--force` after remediation. Relationships and mappings remain idempotent.

## IOC and detection relationships

`ioc_events` uses foreign keys to IOCs and events. `ioc_detection_links` is unique on `(ioc_id, detection_id, relationship_type)` and permits `source_of`, `destination_of`, and `observed_in`. A detection link is only made if the IOC's event is in that detection's own evidence set. Phase 4 does not correlate events across detections.

## ATT&CK mapping ownership and evidence

Phase 3's `Alert.mitre_techniques` remains the baseline and is never rewritten. Phase 4 stores separately sourced records in `attack_mappings`, with event evidence IDs, fixed confidence, static technique metadata, and a baseline-disagreement flag. Evidence IDs are merged by set union; mapping identity does not depend on their order. Missing event evidence generates a warning and no mapping. If no technique is supported, no mapping row is written.

The versioned offline catalog is [`attack_mappings.json`](../enrichment/attack_mappings.json), marked Enterprise ATT&CK **v19.2** and verified against the official [ATT&CK version history](https://attack.mitre.org/resources/versions/) and technique pages: [T1110](https://attack.mitre.org/techniques/T1110/), [T1098](https://attack.mitre.org/techniques/T1098/), [T1136](https://attack.mitre.org/techniques/T1136/), [T1543.003](https://attack.mitre.org/techniques/T1543/003/), and [T1685.005](https://attack.mitre.org/techniques/T1685/005/). The Phase 3 baseline still uses T1070.001 for log clearing; the current catalog moved Clear Windows Event Logs to T1685.005. For Windows Event ID 1102, Phase 4 records T1685.005 separately and marks the baseline disagreement. No Phase 4 mapping is emitted for generic log-clear events without that evidence.

Mappings currently supported by evidence:

| Detection evidence | Mapping | Confidence |
| --- | --- | --- |
| R001 authentication failures | T1110 | 0.95 HIGH |
| R002 authentication failures | T1110 | 0.75 MEDIUM |
| R003 matching authentication failure and success | T1110 | 0.75 MEDIUM |
| R011 account/group change events | T1098 | 0.80 MEDIUM |
| R020 account creation | T1136 | 0.70 MEDIUM |
| R030 Windows Event ID 1102 | T1685.005 | 0.95 HIGH |
| R040 Windows Event ID 7045 | T1543.003 | 0.95 HIGH |

R010 and R021 currently produce no Phase 4 technique mapping. Confidence values describe evidence specificity; they do not assert malicious intent. ATT&CK names, sub-technique names, and tactic relationships in this project artifact must be double-checked by a human against the official ATT&CK matrix before production use.

## CLI

```powershell
python -m enrichment --db data/soc.db
python -m enrichment --db data/soc.db --since 2026-09-30T00:00:00Z
python -m enrichment --db data/soc.db --force
python -m enrichment --db data/soc.db --dry-run
python -m enrichment --db data/soc.db --since 2026-09-30T00:00:00Z --force --dry-run
```

`--since` is exclusive: only events strictly after the UTC-normalized timestamp are selected. Invalid values exit non-zero with an error. `--dry-run` uses read-only SQLite access, makes no migrations, and requires an existing initialized database. The summary reports events processed, new/existing distinct IOCs, event/detection links, mappings, and errors.

## Limitations and false positives

- IOC extraction is syntactic; a domain or URL can be benign. Local telemetry is not treated as proof of threat.
- The domain filter rejects common file suffixes and `.local`, but it does not use a live public suffix or registration database.
- Raw regex matches are intentionally low confidence. Private IPs are retained by default for correlation.
- Only structured path fields are scanned by default; enabling raw path extraction can be noisy.
- IOC-type relationships are simple field provenance, not semantic threat attribution.
- The static ATT&CK catalog is deliberately small and may lag future ATT&CK releases.
- No IOC reputation, geolocation, WHOIS, DNS, or threat-feed lookup is performed.

## Security controls

All values are treated as untrusted. Text is bounded and sanitized, `ipaddress` validates IP/CIDR values, SQL values are parameterized, and arbitrary event content is never executed. Enrichment never mutates event payloads or Phase 3 alert payloads.
