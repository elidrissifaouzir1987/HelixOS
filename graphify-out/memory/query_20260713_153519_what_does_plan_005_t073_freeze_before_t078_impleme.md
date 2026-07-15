---
type: "implementation"
date: "2026-07-13T15:35:19.437694+00:00"
question: "What does PLAN-005 T073 freeze before T078 implements cross-store corruption quarantine?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["dispatch_corruption.rs", "corruption.rs", "dispatch_quarantine.rs", "quarantine.rs"]
---

# Q: What does PLAN-005 T073 freeze before T078 implements cross-store corruption quarantine?

## Answer

T073 adds compile-safe coordinator and adapter RED suites. Exact strict reopen rejects structurally orphan coordinator grants/receipts and adapter inbox/receipts with INVARIANT_FAILED before returning a store. Closed matrices require orphan, digest/generation conflict, store/root/generation rollback, history truncation, generation reuse, and cross-store disagreement to retain Quarantined custody and Refused execution, with no activation surface. One source-contract test per crate remains intentionally RED on the absent T078 verifier/quarantine extension.

## Outcome

- Signal: useful

## Source Nodes

- dispatch_corruption.rs
- corruption.rs
- dispatch_quarantine.rs
- quarantine.rs