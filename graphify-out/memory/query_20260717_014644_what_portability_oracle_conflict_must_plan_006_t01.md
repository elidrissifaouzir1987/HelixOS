---
type: "correction"
date: "2026-07-17T01:46:44.883805+00:00"
question: "What portability-oracle conflict must PLAN-006 T014 correct when wiring the contract foundation?"
contributor: "graphify"
outcome: "corrected"
correction: "Narrow the T010 source oracle at T014 instead of changing the required canonical JSON parser."
source_nodes: ["canonical.rs", "portability.rs", "lib.rs"]
---

# Q: What portability-oracle conflict must PLAN-006 T014 correct when wiring the contract foundation?

## Answer

The T010 portability source guard currently bans the literal f64 across all foundation source, while canonical.rs legitimately implements serde Visitor::visit_f64 to parse JSON numbers before RFC 8785 exact-byte rejection. Once lib.rs wiring lets that guard proceed, it will report a false positive. T014 must narrow the oracle to floating-point authority fields or exempt the duplicate-aware JSON visitor; it must not remove float parsing or weaken canonical-number rejection.

## Outcome

- Signal: corrected
- Correction: Narrow the T010 source oracle at T014 instead of changing the required canonical JSON parser.

## Source Nodes

- canonical.rs
- portability.rs
- lib.rs