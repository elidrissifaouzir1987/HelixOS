---
type: "implementation-result"
date: "2026-07-18T13:50:51.937149+00:00"
question: "What did PLAN-006 US1 root authority issuance T025-T038 establish?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["kernel/helix-task-authority/src/request.rs", "kernel/helix-task-authority-sqlite/src/lease.rs", "specs/006-durable-signed-task-authority/evidence/us1-request.md"]
---

# Q: What did PLAN-006 US1 root authority issuance T025-T038 establish?

## Answer

Local conformance on 2026-07-18 established that one current canonical HumanRequestGrant can atomically retain one issuer-scoped claim, signed root TaskLease, initial usage, attempt, generations, and redacted event. Exact stable retries return the original retained lease bytes without new persistence; changed stable input retains only a conflict tombstone/event; current trust, scope, time, and revocation are rechecked; lost acknowledgement transfers one fresh readback without re-signing. Contract/core/SQLite suites and strict Clippy passed. Controlled contention profiles passed at 10,000 sequential retries, 100 rounds x 64 threads, and 20 rounds x 8 processes. Full immutable, cross-platform, process-kill, and all-operation durability claims remain pending.

## Outcome

- Signal: useful

## Source Nodes

- kernel/helix-task-authority/src/request.rs
- kernel/helix-task-authority-sqlite/src/lease.rs
- specs/006-durable-signed-task-authority/evidence/us1-request.md