# Phase 6: evidence-bounded investigation

## Use

```text
python -m investigation INCIDENT_ID [--db PATH] [--force]
python -m investigation INCIDENT_ID --dry-run [--db PATH]
python -m investigation INCIDENT_ID --show-prompt [--db PATH]
```

The interactive menu's AI investigation option asks for a persisted Phase 5 incident ID. In-memory demo alerts are not sent to an LLM. A merged incident is rejected with its survivor ID; users must explicitly investigate the survivor.

## Identity, runs, and retries

Schema migration 8 adds `investigations`, `investigation_attempts`, and `investigation_evidence`. The investigation key includes incident ID, final evidence hash, prompt-template hash, provider, model, generation-configuration hash, and prompt-schema version. A separate sequential `run_number` is unique within that key. Normal execution reuses the latest completed result. Failed and invalid runs can be retried, up to three provider calls in aggregate per key; `--force` creates the next run number and explicitly starts a fresh bounded attempt budget. Prior runs and attempts remain stored.

SQLite `BEGIN IMMEDIATE` reservation plus `(investigation_key, run_number)` uniqueness prevents concurrent duplicate reservations. A running row older than `LLM_STALE_TIMEOUT_SECONDS` is marked stale and can be retried. Each provider call has its own row. A validation failure gets one bounded second call with JSON-serialized validation diagnostics; invalid output is never edited into a valid response. Validation errors are capped.

## Evidence packet and aliases

The packet is canonical sorted-key JSON. It contains only aliases (`D1`, `E1`, `I1`, `M1`) sorted by their underlying IDs; the alias-to-real-ID map is stored internally alongside the packet and never sent to the model. Output validation checks both alias existence and evidence type, rejects duplicates, and persists real IDs in `investigation_evidence`.

The evidence hash covers the final model packet, including packet schema version, limits, aliases, sanitized text, and truncation metadata. It excludes processing timestamps and request-random delimiters. The `packet_json` field preserves both the exact model packet and the internal alias map. Packet ordering is: earliest linked event per detection, then incident-wide earliest and latest events, then remaining events by `(timestamp,event_id)`. Detection identities are always retained. Raw excerpts and category counts are bounded and truncation is recorded.

Timeline text is generated from event type, user, and source IP using a fixed template; raw log lines are never used as timeline descriptions. Raw excerpts, when included, are separately bounded and secret-like key/value content is redacted.

## Prompt and output security

The prompt serializes packet evidence as JSON and chooses a fresh random delimiter absent from that serialized packet. It explicitly treats evidence as data, not instructions. The delimiter is excluded from the evidence hash. **Delimiters reduce prompt-injection risk but do not eliminate it. The primary security controls are evidence isolation, strict output validation, no arbitrary tools, and deterministic claim validation.**

Ollama uses JSON Schema output where available and JSON mode as a compatibility fallback. Every response is parsed and checked locally for exact fields, types, enum values, bounds, evidence aliases, and duplicate references. `observed` needs evidence; `inferred` needs at least two distinct references; `unknown` may have none. Recommendations use a fixed `action_type` enum and shell-like commands are rejected. Stored/displayed strings have ANSI/control/HTML markup removed and URLs defanged.

The deterministic high-risk claim guard checks privilege escalation, persistence, exfiltration, successful exploitation, and credential compromise against configurable event types and detection rule IDs. This is a heuristic and cannot prove semantic correctness; unsupported high-risk claims are rejected. The model has no arbitrary tools or active-response capability.

## Provider privacy and limits

`ALLOW_REMOTE_LLM=false` by default. Only `localhost`, `127.0.0.1`, and `::1` endpoints are accepted unless remote use is explicitly enabled. The current adapter is Ollama; no other provider is implemented. The Ollama call fixes the configured context size, temperature (default 0), seed, output token cap, timeout, and structured JSON output. Prompt token use is estimated before sending; packets are deterministically reduced until they fit or the request is rejected without calling the model.

Settings are listed in `.env.example`: `LLM_NUM_CTX`, `LLM_TIMEOUT_SECONDS`, `LLM_MAX_OUTPUT_TOKENS`, `LLM_TEMPERATURE`, `LLM_SEED`, packet/event/IOC/mapping limits, stale timeout, retry cap, and validation-error cap. CLI investigations use `created_by=cli`; service calls default to configured `LLM_CREATED_BY` (normally `system`), never the OS username.

## Dry-run and empty evidence

`--dry-run` and `--show-prompt` use SQLite read-only mode, do not initialize or migrate, do not enable WAL, do not write metadata, and never call a provider. Preview output includes incident title/ID, evidence counts, hash, packet bytes, estimated tokens, and truncation counts. `--show-prompt` prints the prompt separately.

An incident with no usable linked detection, event, IOC, or ATT&CK evidence is stored as a completed `provider=none` investigation with low AI confidence and summary `Insufficient evidence for AI investigation.`. `ai_unavailable=false` distinguishes an evidence limitation from a provider failure.

## Confidence, output, and audit

Phase 5 deterministic confidence and Phase 6 AI confidence are stored separately. AI confidence never changes Phase 5 risk. If AI confidence is higher, the result records a warning. Completed investigations retain validated structured output and only a hash of raw output. Failed/invalid attempts keep a sanitized bounded excerpt and hash for debugging.

Output uses the complete schema defined by `investigation/output_schema.py`; finding, uncertainty, limitation, recommendation, IOC assessment, and ATT&CK assessment evidence links retain their category and relevant basis, confidence, priority, and action type. Investigations are advisory. No remediation, dashboard, external intelligence, or Phase 7 behavior is included.
