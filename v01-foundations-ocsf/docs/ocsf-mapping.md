# OCSF mapping reference

This document is the source of truth for how `proto/telemetry.proto` maps onto
OCSF (Open Cybersecurity Schema Framework). **Pin the OCSF schema version at
write time** by checking [schema.ocsf.io](https://schema.ocsf.io) / the
[ocsf-schema releases](https://github.com/ocsf/ocsf-schema/releases) — do not
treat a version number in prose as eternal. This file was last verified
against **OCSF 1.8.0** (released March 2026).

Every future module that touches telemetry — the detection engine (Module 7),
the correlation layer (Module 9), the AI copilot (Module 12) — reads events
assuming this mapping holds. Change it once here, and update every field
comment in the proto to match.

## Why OCSF instead of a homegrown schema

Three reasons, in order of how much they'll matter to you later:

1. **Sigma conversion, not “rules already speak OCSF.”** Public SigmaHQ rules
   still use classic fields (`Image`, `CommandLine`, `ParentImage`, …). What
   OCSF buys us is a **single storage vocabulary** so a conversion pipeline
   (e.g. pySigma + an OCSF/ClickHouse backend) can target one field set
   instead of per-OS Sysmon/WEF dialects. Module 7 teaches that pipeline;
   importing rules is a translation project, not a drop-in.
2. **Vendor / lake interoperability where OCSF is actually used.** AWS
   Security Lake is OCSF-native. Several vendors expose OCSF *exports* or
   *ingest* paths (e.g. for lakes/SIEM). That is not the same as “every EDR
   agent wire format is OCSF.” Elastic’s native gravity remains ECS. We
   normalize *our* greenfield pipeline to OCSF so lake-style interchange and
   one query language are possible — not because Falcon’s sensor speaks it.
3. **Stable vocabulary for tools and humans.** Detection CI fixtures,
   correlation joins, and the Module 12 copilot’s **constrained** query tools
   all need one field dictionary. OCSF is the dictionary we commit to;
   deterministic tool schemas matter more than “the LLM saw OCSF in training.”

## OCSF identifiers used in this module

Classification attributes are **top-level Base Event fields**, not nested
under `metadata`.

| Concept | Value | Meaning |
|---|---|---|
| `category_uid` | 1 | System Activity |
| `class_uid` | 1007 | Process Activity |
| `activity_id` | 1 | Launch |
| `activity_id` | 2 | Terminate |
| `type_uid` | `class_uid * 100 + activity_id` | e.g. Launch → 100701 |
| `severity_id` | 1 | Informational (typical for raw telemetry) |

`metadata` holds product identity and the OCSF schema version string
(`metadata.version`), not `class_uid`.

Future modules add: `class_uid` 1001 (File System Activity, Module 6),
`class_uid` 4001 (Network Activity, Module 6), `class_uid` 3002
(Authentication, Module 9.5), plus container profile fields (Module 6.5).

## Field mapping table (Issue 01 scope: process_activity only)

| Our proto field | OCSF attribute | Notes |
|---|---|---|
| `schema_version` | *(wire only)* | Our protobuf contract version; not OCSF |
| `class_uid` | `class_uid` | Top-level Base Event |
| `category_uid` | `category_uid` | Top-level Base Event |
| `activity_id` | `activity_id` | Top-level Base Event |
| `type_uid` | `type_uid` | Required: `class_uid * 100 + activity_id` |
| `severity_id` | `severity_id` | Required Base Event field |
| `metadata.product_name` | `metadata.product.name` | |
| `metadata.product_vendor_name` | `metadata.product.vendor_name` | |
| `metadata.product_version` | `metadata.product.version` | Agent build |
| `metadata.ocsf_version` | `metadata.version` | OCSF schema version string |
| `ProcessActivity.uid` | `process.uid` | Durable process id — **do not use pid alone** |
| `ProcessActivity.pid` | `process.pid` | |
| `ProcessActivity.start_time_unix_ms` | `process.created_time` | Epoch millis |
| `ProcessActivity.name` | `process.name` | |
| `ProcessActivity.cmd_line` | `process.cmd_line` | |
| `ProcessActivity.file.path` | `process.file.path` | |
| `ProcessActivity.file.sha256` | `process.file.hashes[]` | Flattened; see below |
| `ProcessActivity.parent_process.*` | `process.parent_process.*` | Include parent `uid` + `cmd_line` |
| `Actor.user.name` / `uid` | `actor.user.name` / `actor.user.uid` | |
| `Actor.process.*` | `actor.process.*` | Launching process (often = parent on Launch) |
| `Device.hostname` | `device.hostname` | |
| `Device.os_type` | `device.os.type` | Caption; keep aligned with `os_type_id` |
| `Device.os_type_id` | `device.os.type_id` | OCSF enum — verify values at schema.ocsf.io |
| `Device.tenant_id` | *(extension)* | Reserved; single-tenant lab may use a const |
| `Device.agent_id` | *(extension)* | Fleet enrollment id |
| `time_unix_ms` | `time` | Epoch millis |

## What's deliberately NOT OCSF-exact yet

1. **Hashes.** OCSF's `process.file.hashes` is a repeated object
   (`[{algorithm, value}]`), not a single string. Flattened to `sha256` until
   Module 6. (TIER 2 — will change.)
2. **No `unmapped` bag yet.** OS-specific extras will need an extensibility
   field before Module 6 depth work; track as TIER 2.
3. **`parent_pid` denorm** duplicates `parent_process.pid`. Agents must keep
   them identical; prefer `parent_process` in new code.
4. **Caption vs enum for OS.** We emit both `os_type` and `os_type_id`;
   validators should prefer `os_type_id` once agents set it reliably.

## Detection field contract (forward-looking)

Before Module 7, every rule/fixture may only reference OCSF paths listed in
this doc (plus paths added by Modules 6 / 6.5 / 9.5). CI should reject Sigma
rules that reference fields outside the contract after conversion.

Minimum identity fields agents must populate from Issue 02 onward:

- `process.uid` (and parent `uid`)
- `process.pid` / `process.cmd_line` / `process.name`
- `type_uid`, `class_uid`, `activity_id`, `severity_id`
- `metadata.product.*` and `metadata.version`

### Issue 02 agent notes (`linux-agent`)

- Emits **OCSF-shaped JSON** on stdout (protobuf ingest arrives in Phase B). Field names follow this table.
- `process.uid` format: `{boot_id}:{pid}:{start_time_ns}` (string). Replay fixtures supply synthetic start times; live mode may leave `start_time_ns` 0 until `/proc` enrichment (still non-empty uid string).
- `device.os.type_id` **200** = Linux (OCSF OS type enum — verify at schema.ocsf.io if the enum shifts).
- Noise filtering is agent-local; it does not change the schema.

### Issue 03 agent notes (`windows-agent`)

- Same Launch contract as Issue 02 (`type_uid` **100701**) plus Terminate (`activity_id` 2 → **100702`).
- `device.os.type_id` **100** = Windows.
- `process.cmd_line` must be populated from the **system logger / dual-provider** path in live mode — not from Kernel-Process alone.
- `process.file.sha256` remains flattened (Issue 01 TIER 2) when hashing succeeds.
- Image-load events use an OCSF-shaped envelope with `unmapped.event_kind = "image_load"` until Module 6 finalizes a module/file class mapping (TIER 2).
- Hash cache is agent-local; it does not change the schema.

### Issue 04 agent notes (`macos-agent`) — Phase A complete

- Same Launch contract (`type_uid` **100701**).
- `device.os.type_id` **300** = macOS.
- Live source is Endpoint Security `ES_EVENT_TYPE_NOTIFY_EXEC` via System Extension + entitlement `com.apple.developer.endpoint-security.client`.
- Mock/replay is an accepted schema path when entitlement/hardware is unavailable — document in README; do not claim live kernel telemetry.
- Freeze these Launch field names before Issue 05 transport work (`scripts/phase-a-checkpoint.sh`).

### Issue 05 transport notes

- Agents still emit OCSF-shaped JSON; `edr-shipper` wraps frames with `event_id`, `tenant_id`, and `schema_version` (`1.0.0` wire).
- Dedup key for Issue 06: `(tenant_id, event_id)` — see ADR 002.
- Ingest contract: `proto/ingest.proto`. Lab stub uses mTLS HTTPS JSON with the same field names.

### Issue 06 pipeline notes

- Topic `raw.telemetry` carries header `schema_version` (plus `tenant_id`, `agent_id`).
- Consumer projects agent JSON into `ocsf_process_activity` columns (ADR 008) — SQLite mirror in CI, ClickHouse DDL in `backend/sql/`.
- Prefer delay over silent drop (ADR 007); load-test enforces published == stored.

## Where to verify this yourself

Inspect `process_activity` at [schema.ocsf.io](https://schema.ocsf.io/classes/process_activity).
If a future OCSF version renames or restructures an attribute we depend on,
that is a breaking change for this project and should be caught by Module 5
schema versioning — not by a broken query in Module 9.


## File / network / persistence (Issues 07–09)

| Our proto / JSON | OCSF attribute | Notes |
|---|---|---|
| `FileActivity.file_path` / `file.path` | `file.path` | class_uid **1001** |
| `FileActivity.process.uid` / `process.uid` | correlating process | Join key |
| `NetworkActivity.src_ip` / `src_endpoint.ip` | `src_endpoint.ip` | class_uid **4001** |
| `NetworkActivity.dst_*` / `dst_endpoint.*` | `dst_endpoint.*` | |
| Persistence `unmapped.event_kind=persistence` | thin-slice marker | Promote to dedicated class when ready |

Pipeline: `project_file_activity` / `project_network_activity` / `project_persistence_activity` in `backend/pipeline-common`. ClickHouse DDL: `backend/sql/clickhouse_ocsf_{file,network,persistence}.sql`. Live OS hooks remain Reader VM; CI uses `scripts/deep-telemetry-fixtures.py`.

macOS network: **Network Extension**, not Endpoint Security.

## Container context (Issue 10)

| Field | Meaning |
|---|---|
| `container.pod_name` / `namespace` / `container_id` | K8s enrichment on TelemetryEvent |

## Authentication (Issue 14)

Auth fixtures use `class_uid` **3002** lab shape with `unmapped.travel` / `user_upn` for the impossible-travel detector. OS user ≠ IdP UPN — map explicitly in correlation.
