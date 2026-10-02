# Phase 9A — Safe simulated response foundation

Phase 9A adds proposals, approvals, execution-attempt history, rollback records, and an API/CLI foundation for response workflows.

**Phase 9A cannot modify external systems.** The only execution mode is the literal `simulation`, enforced by SQLite `CHECK` constraints and by fixed application code. Request bodies do not accept an execution mode. Configuration and CLI arguments cannot enable real execution. Firewall, identity, and endpoint real-executor stubs always raise `RealExecutionNotImplemented`. No network client, socket, subprocess, shell, or file-writing path exists in `response/`.

## Architecture and data

`ResponseService` is the domain boundary. It uses the existing `Database` connection manager and Phase 7 `audit_log`; response audit entries use `entity_type=response_action`, so they appear in the existing `/api/v1/audit` results. A migration creates `response_actions`, `response_action_evidence`, and `execution_attempts`. Proposal/evidence rows reference parents with `ON DELETE RESTRICT`; SQLite triggers validate the polymorphic evidence references and prevent source evidence deletion while referenced.

Proposals store immutable action fields. A proposal fingerprint includes incident, action type, canonical target, canonical parameters, policy version, and sorted evidence identities. Repeating the same active proposal is idempotent. A changed or rejected proposal is a new revision with `supersedes`; the previous proposal is marked superseded when its execution state permits that transition. Evidence is held in a separate relation, never as a JSON array in the proposal.

Migration **9** is additive and numbered after the repository's current schema version 8. Fresh initialization and repeat migration are supported. No production `data/soc.db` existed in this checkout; migration tests build a representative version-8 database and check retained rows.

## State machines

Approval, execution, and verification are independent SQLite-checked enums. `ResponseService._transition` is the centralized compare-and-set transition method; a stale expected status returns a conflict, mapped to HTTP 409. API mutations require `expected_status`. Stale `executing` attempts older than 15 minutes are marked failed and audited before the caller receives a conflict.

| Dimension | States |
|---|---|
| Approval | `not_required`, `pending`, `approved`, `rejected`, `expired` |
| Execution | `not_started`, `executing`, `simulated`, `failed`, `rolled_back`, `cancelled`, `blocked_by_policy`, `superseded` |
| Verification | `not_verified`, `simulated`, `failed`, `unknown` |

Approval-required catalog actions start pending. Approvals expire after `SOC_RESPONSE_APPROVAL_TTL_SECONDS` (default 3600 seconds). The optional `SOC_RESPONSE_REQUIRE_DIFFERENT_APPROVER` setting defaults to false because the current API has one shared bearer principal; deployments can require separation when they have distinct identities. Approval is bound to action type, canonical target/type, canonical parameters, evidence IDs, and policy version. A mismatch or evidence detached from the incident is audited and refused. Proposals are immutable; revised parameters, targets, policies, or evidence require a new revision and approval.

Phase 7 currently attributes an authenticated API request to `api-user` (or `local-user` when auth is disabled). This means approvals are attributable only to the authenticated shared-token holder unless Phase 9 later adds named credentials. The API never accepts `approved_by` or requester identity from a body. CLI mutation commands require `--actor`, record `via=cli`, and document that the supplied actor is asserted, not authenticated.

## Action catalog and simulation meaning

The deterministic catalog contains `simulate_block_ip`, `simulate_disable_account`, `collect_evidence`, `increase_monitoring`, `create_case_note`, and `mark_incident_reviewed`. Each entry declares reversibility, rollback label, minimum risk, approval requirement, allowed roles, and policy rule/version. There is no LLM ranking or free-form LLM target generation.

Simulation means persisting a proposal, approval/decision, a result describing the simulated action, and an attempt record. It does not call or configure an external control. `collect_evidence` records the incident's linked event IDs and a canonical hash in SQLite; it writes no file. `increase_monitoring` records a recommendation only. `create_case_note` and `mark_incident_reviewed` remain response records and do not mutate incident fields or bypass the analyst incident service. Simulation rollback updates only response records and audits the rollback. Reversible catalog entries can be rolled back idempotently; a later execute creates the next numbered attempt. Completed execution returns its original result without creating another attempt.

## Target and policy safety

Targets are canonicalized and must match incident-linked event, detection, or IOC evidence. IP validation rejects zone IDs, loopback, link-local, multicast, reserved, unspecified, and non-global special-use addresses; IPv4-mapped IPv6 is canonicalized to IPv4. RFC1918 and IPv6 ULA targets need a sanitized, non-empty policy justification. Hostnames use RFC 1123/NetBIOS label and length rules; accounts accept `DOMAIN\\user`, UPN, and machine-account forms; domains use Phase 4 IDNA normalization. Control and bidi characters are rejected. Protected IP/CIDR, host, and account settings are available through `SOC_RESPONSE_PROTECTED_IPS`, `SOC_RESPONSE_PROTECTED_HOSTS`, and `SOC_RESPONSE_PROTECTED_ACCOUNTS`; protected targets are recorded as `blocked_by_policy` and cannot execute.

NAT and proxy addresses can represent many unrelated users. An observed source IP alone does not establish which user or endpoint should be contained; analysts must review linked evidence and policy context before approving a simulation proposal.

## Audit, API, and CLI

Every state-changing service operation inserts the matching Phase 7 audit row in the same transaction. Audit insert failure rolls back the state change. SQLite triggers reject `UPDATE` and `DELETE` for `response_action` audit entries. There is no hash chain in Phase 9A; database append-only triggers are an application integrity control, not proof against a privileged database-file editor.

Authenticated additive API routes are:

- `POST /api/v1/incidents/{incident_id}/response/recommend` (`dry_run` supported)
- `GET /api/v1/incidents/{incident_id}/response/actions`
- `POST /api/v1/incidents/{incident_id}/response/actions`
- `GET /api/v1/response/actions/{action_id}`
- `POST /api/v1/response/actions/{action_id}/approve`
- `POST /api/v1/response/actions/{action_id}/reject`
- `POST /api/v1/response/actions/{action_id}/execute`
- `POST /api/v1/response/actions/{action_id}/rollback`

Examples:

```powershell
python -m response recommend --incident INC_ID --actor analyst
python -m response recommend --incident INC_ID --dry-run
python -m response approve ACTION_ID --expected-status pending --actor analyst
python -m response execute ACTION_ID --expected-status not_started --actor analyst
python -m response rollback ACTION_ID --expected-status simulated --actor analyst
python -m response show ACTION_ID
```

CLI dry-run requires an already migrated database, opens it read-only, and creates no response or audit rows. The `expected-status` values in examples refer to their relevant workflow dimension: approval uses `pending`; execution accepts `not_started` or `rolled_back`; rollback uses `simulated`.

## Threat model and limitations

The boundary protects against attacker-controlled event/IOC/LLM text becoming arbitrary targets, request attempts to choose real execution or impersonate approvers, stale concurrent UI mutations, and accidental code paths into external controls. It assumes the Python process and SQLite file are not controlled by a privileged local attacker. The shared bearer token is not individual identity. Role names are recorded from the deterministic action catalog; current API authentication does not distinguish user roles. No real action adapter, dashboard response control, playbook recommendation engine, external integration, autonomous execution, hash-chained audit, or Phase 9B/9C behavior is present.
