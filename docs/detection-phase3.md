# Phase 3 detection

Run the deterministic detection engine after ingestion with:

```powershell
python -m detection --db data/soc.db
python -m detection --db data/soc.db --since 2026-10-01T00:00:00Z
python -m detection --db data/soc.db --batch-id <batch-id>
```

Set `RULES_CONFIG` to a JSON file to override the bundled defaults. All nine supported rule IDs must be present. `threshold`, `window_seconds`, `severity`, `confidence`, and `enabled` are validated at load time. Window endpoints are inclusive. Each fixed burst is anchored to its first event so re-running evaluation updates the same Alert and evidence.

## Default rules

| Rule | Meaning | Threshold/window | Severity / confidence | ATT&CK |
| --- | --- | --- | --- | --- |
| R001 | Brute-force burst | 5 failures / 300 s | HIGH / 0.90 | T1110, Credential Access |
| R002 | Repeated authentication failures | 3 failures / 300 s | MEDIUM / 0.80 | T1110, Credential Access |
| R003 | Failure followed by success for same source IP and username | 1 matching success / 300 s | HIGH / 0.90 | T1110, Credential Access |
| R010 | Privilege assigned | 1 / 300 s | MEDIUM / 0.75 | Unset |
| R011 | Account or group manipulation | 1 / 300 s | MEDIUM / 0.80 | T1098, Persistence / Privilege Escalation |
| R020 | Account created | 1 / 300 s | MEDIUM / 0.85 | T1136, Persistence |
| R021 | Repeated account lockouts | 3 for host+user / 300 s | MEDIUM / 0.85 | Unset |
| R030 | Audit/security log cleared | 1 / 300 s | HIGH / 0.95 | T1070.001, Defense Evasion |
| R040 | Service created | 1 / 300 s | MEDIUM / 0.85 | T1543.003, Persistence / Privilege Escalation |

R001/R002 consider source-IP and username groups independently. R001 supersedes overlapping R002 activity. Evidence is persisted in the generic `evidence_refs` registry as `ALERT -> EVENT`; the Phase 1 `evidence_links` table remains incident-only because its incident foreign key is part of the existing schema contract. Suppression precedence is trusted user, trusted source IP/CIDR, then trusted host. Suppressed results are retained in `suppressed_detections`, and every run writes one `rule_executions` row per rule.

Phase 2 compatibility adjustment: `NormalizedEvent` now has optional `target_user`, `group_name`, `service_name`, and `attributes` fields. Windows adapters preserve the target separately and keep the subject/actor in `username` and `attributes.actor_user`; JSON adapters map matching aliases. Existing event fields and database serialization remain compatible.
