# Phase 5: deterministic incident correlation

## Architecture and data model

Phase 3 detections are rows in `alerts` (their identifiers normally begin with `det_`). Correlation treats those rows as graph nodes, and uses Phase 2 `events`, Phase 4 `ioc_detection_links`, and Phase 4 `attack_mappings` as evidence sources. Migration 7 adds detection key indexes and incident relationship, edge, execution, suppression, merge-history, and watermark tables. It does not duplicate detections or ATT&CK mappings.

`incident_detections`, `incident_events`, `incident_iocs`, and `incident_attack_mappings` are rebuildable materialized relationships. Correlation edges preserve the rule, configuration hash, execution, match timestamp, and explanation that produced each relationship. Relationships have uniqueness constraints and correlation reruns are safe.

## Rules and graph construction

Each detection is a node. Candidate pairs are retrieved by indexed key and only considered when their timestamps are at most 300 seconds apart by default. The boundary is inclusive. Time alone never makes an edge. Components are formed deterministically; each attempted union must keep the component span within the default 24 hours.

Rule meanings for this implementation:

| Rule | Relationship |
| --- | --- |
| C001 | Same source IP within the window, subject to the high-frequency/NAT guard |
| C002 | Same user within the window |
| C003 | Shared persisted evidence event |
| C004 | Shared qualifying IOC |
| C005 | Same host and shared persisted evidence event |

All rules matching a pair are recorded, while the graph still creates one incident per connected component. C005 requires both conditions. Rules C001–C004 are transparent defaults because the project brief named those identifiers without defining their semantics; projects can revise the mapping in this module with a rule-version change.

Shared IOC correlation excludes tags `private`, `loopback`, `link_local`, `multicast`, `system`, and `high_frequency`. Defaults cap an IOC at 100 detections and 500 candidate edges, and flag IOC and source-IP suppressions in `correlation_suppressions`. High-frequency source IP edges additionally require shared user, host, event, or IOC context, preventing unrelated NAT users from forming a large incident. `CorrelationService` accepts overrides for all thresholds.

## Incident identity and merging

The component anchor is its earliest detection by `(timestamp, detection_id)`. The incident ID is `stable_id("inc", anchor_detection_id)` and does not depend on primary fields. When a bridge joins prior incidents, the earliest anchored ID survives. Other incident rows remain queryable with status `merged` and `merged_into` pointing to the survivor. Merge history is retained. Materialized relations are rebuilt on the survivor and deduplicated.

Late detections are correlated against the full persisted detection set, including historical detections and evidence; `--since` marks the new-candidate boundary and does not hide historical context. Recalculation therefore converges to the same component state regardless of arrival order. A watermark stores the newest detection timestamp seen.

## Derived and analyst-controlled fields

Correlation derives title, description, severity, risk score/level, confidence, primary host/user/source IP, detection count, time bounds, and MITRE summaries. Analyst status, notes, assignment, and resolution fields are preserved on an existing incident. New correlation incidents start as `open`. A resolved survivor receiving new related detections reopens to `open` and appends an explicit status-history record. Losing incidents use `merged` as a system lifecycle state.

Primary fields use the most frequent value. Ties go to earliest first-seen time and then lexical value. Titles and descriptions use bounded, sanitized structured fields only; raw event content is never copied.

## Confidence and risk

Confidence is deterministic: HIGH requires at least two detections connected by shared event or qualifying IOC; MEDIUM denotes a shared event or source-IP relationship; other valid graph relationships are LOW. No edge means standalone confidence LOW.

Risk starts from the highest detection severity: informational defaults to 5 (configurable within 0–10), LOW 25, MEDIUM 50, HIGH 70, CRITICAL 90. Add 10 for successful authentication after failures, 10 for privileged account/group context, 5 per additional distinct technique up to 15, 5 per additional tactic after the first, and 5 when there are more than three detections. The result is clamped to 0–100 and the structured breakdown sums exactly to the final score, including a clamp adjustment if needed. Levels are LOW 0–24, MEDIUM 25–49, HIGH 50–74, CRITICAL 75–100. One HIGH detection therefore produces score 70 / HIGH. Informational severity produces a LOW incident risk absent modifiers.

## CLI

```text
python -m correlation incidents [--db PATH]
python -m correlation show INCIDENT_ID [--db PATH]
python -m correlation --since 2026-01-01T00:00:00Z [--db PATH]
```

`incidents` runs correlation and lists active incidents. An empty database prints `No incidents found.` and exits successfully. `show` prints incident metadata, risk breakdown, rules/edges, detections, evidence, IOCs, ATT&CK mappings, and merge history. Unknown IDs print a clear message and exit successfully.

## Audit, performance, and limitations

Every run records timestamps, counters, config hash, rule version, errors, and status in `correlation_executions`. Malformed detection payloads are isolated and counted. Component writes use savepoints, so a failed component can be reported without rolling back successful components. Candidate keys use `detection_keys(key_type,key_value,timestamp)` and bounded sliding windows rather than comparing all detections pairwise. Per-key caps and suppressions bound common-key fanout.

The first implementation's C001–C004 meanings are project-local defaults because only C005 was semantically specified. Correlation uses evidence attached to alerts and IOC links available in the existing schema; it does not infer evidence from raw log text. No AI investigation or active response is performed.
