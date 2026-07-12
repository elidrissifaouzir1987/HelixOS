---
type: "query"
date: "2026-07-12T11:55:56.171681+00:00"
question: "Why can the Windows PLAN-004 64-thread same-operation contention test return 64 Busy results after eleven seconds despite a thirty-second busy cap?"
contributor: "graphify"
outcome: "corrected"
correction: "The 60-second test deadline and 30-second busy cap did not correct the intermittent Windows failure; stabilize the cold WAL/shm fixture lifecycle with a retained idle anchor connection while keeping production and SC-010 unchanged."
source_nodes: ["contention.rs", "commit_synthetic_preparation_until_v1()", "provision_synthetic_budget_scope_v1()", "deadline.rs"]
---

# Q: Why can the Windows PLAN-004 64-thread same-operation contention test return 64 Busy results after eleven seconds despite a thirty-second busy cap?

## Answer

Expanded from graph vocabulary: contention, busy, sqlite, deadline, coordinator, reservation, operation, commit, thread, clock, barrier, observation. The barrier releases all 64 workers before Connection::open and BEGIN IMMEDIATE, while the provisioning helper closes the last SQLite connection. This creates a synchronized cold WAL/wal-index shared-memory first-access race. The bundled SQLite Windows WAL path can return BUSY during shared-memory initialization and internally retries for less than ten seconds before SQLITE_PROTOCOL; the synthetic helper collapses every BEGIN error to Busy, so the extended result is hidden. The unchanged approximately eleven-second failure under both five-second and thirty-second busy caps corroborates that this is not the configured busy timeout. Retain one sequentially opened, table-touched, idle anchor connection from database initialization through budget provisioning, all worker joins, and durable observation; drop it before the full reopen assertion. Apply it to thread, shared-allowance, and process rounds without changing production limits, deadline.rs, SC-010, or accepted outcome classes.

## Outcome

- Signal: corrected
- Correction: The 60-second test deadline and 30-second busy cap did not correct the intermittent Windows failure; stabilize the cold WAL/shm fixture lifecycle with a retained idle anchor connection while keeping production and SC-010 unchanged.

## Source Nodes

- contention.rs
- commit_synthetic_preparation_until_v1()
- provision_synthetic_budget_scope_v1()
- deadline.rs
