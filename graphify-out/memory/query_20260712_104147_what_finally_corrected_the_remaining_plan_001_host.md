---
type: "query"
date: "2026-07-12T10:41:47.033283+00:00"
question: "What finally corrected the remaining PLAN-001 hosted macOS timing failure and Windows byte-identical file-swap test failure?"
contributor: "graphify"
outcome: "corrected"
correction: "Treat the wall-clock test as a PLAN-004 controlled-target oracle, not a hosted PLAN-001 portability gate; keep the Windows lease until after the identity assertion and release it only for the final marker read."
source_nodes: ["connection.rs", "CoordinatorRootLeaseV1", "held_writer_returns_by_absolute_injected_deadline_and_never_mutates_later"]
---

# Q: What finally corrected the remaining PLAN-001 hosted macOS timing failure and Windows byte-identical file-swap test failure?

## Answer

Expanded from original query via graph vocab: [lease, root, role, marker, held, writer, deadline, windows, identity, custody, test, clock]. Serial workspace execution alone did not make the strict PLAN-004 wall-clock oracle reliable on hosted runners. PLAN-001 now exact-skips only held_writer_returns_by_absolute_injected_deadline_and_never_mutates_later and records PLAN-004 T043/SC-010 as its controlled-target owner; all other workspace tests remain in scope. In connection.rs, the exclusive coordinator root lease remains held through the byte-identical swap and fail-closed fingerprint check, then is released only before the final path-based marker read because Windows rejects that read while the lock handle is exclusive.

## Outcome

- Signal: corrected
- Correction: Treat the wall-clock test as a PLAN-004 controlled-target oracle, not a hosted PLAN-001 portability gate; keep the Windows lease until after the identity assertion and release it only for the final marker read.

## Source Nodes

- connection.rs
- CoordinatorRootLeaseV1
- held_writer_returns_by_absolute_injected_deadline_and_never_mutates_later