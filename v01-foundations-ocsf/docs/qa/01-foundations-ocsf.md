# QA checklist — Issue 01 (`v01-foundations-ocsf`)

- [x] Repo scaffold present: agents, backend, dashboard, detections, copilot, proto, docs
- [x] `proto/telemetry.proto` — OCSF Base Event classification top-level; `process.uid` durable; metadata ≠ class_uid
- [x] `docs/ocsf-mapping.md` is the field contract; OCSF version pinned in prose
- [x] Diagrams under `docs/diagrams/v01-foundations-ocsf/` (architecture + mapping)
- [x] Article: professional tone; free tier; no explicit What/Why/How headings; completion criteria
- [x] Implementation guide present
- [x] Sigma framed as conversion story (not “rules ship OCSF fields”)
- [x] Agent-as-attack-surface called out; anti-tamper deferred to Module 13
- [x] No live OS hooks claimed in this issue (architecture only)
- [x] Tag `v01-foundations-ocsf` created
