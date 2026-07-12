---
type: "implementation"
date: "2026-07-11T23:27:02.076522+00:00"
question: "How should T074 carry coordinator fault selection through commit, readback, and known-failure transactions?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["FaultProbeV1", "SqliteCoordinatorStoreV1", "prepare.rs", "readback.rs", "failure.rs"]
---

# Q: How should T074 carry coordinator fault selection through commit, readback, and known-failure transactions?

## Answer

Use one store-owned opaque probe that defaults disabled. In test-fault builds the probe shares a caller-selected FaultSession through Arc<Mutex>, removes the one-shot Send callback while holding the mutex, then invokes it only after releasing the lock. The hidden selection facade installs the probe for the 26 coordinator transaction boundaries; prepare emits 10 boundary variants including eight member occurrences, readback emits 7 classifications/handoffs, and known-failure emits 9 durable action boundaries. Source-included integrations reach by frozen boundary ID through the crate wrapper. This plumbing does not itself run a workflow: the process harness must select the store probe and execute the real operation. Verified by fmt, all-target checks with/without feature, strict clippy, 123 lib tests, 64 preparation tests, 27 cancellation tests, and 25 conformance-execution tests.

## Outcome

- Signal: useful

## Source Nodes

- FaultProbeV1
- SqliteCoordinatorStoreV1
- prepare.rs
- readback.rs
- failure.rs