---
type: "implementation"
date: "2026-07-11T10:50:01.611118+00:00"
question: "How must PLAN-004 comparison digests and exact absence remain stable across lifecycle transitions?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["comparison_digest.rs", "schema.rs", "readback.rs", "CoordinatorReadbackInputV1"]
---

# Q: How must PLAN-004 comparison digests and exact absence remain stable across lifecycle transitions?

## Answer

Hash an explicit allow-listed immutable SQL projection shared by writer and verifier. Exclude mutable scope held vectors, current operation/reservation state, current transition/event pointers, and recovery retirement lifecycle fields. For definite absence, include the uncertain COMMIT custody's exact prepared event ID and initial transition generation in the live writer-excluded key footprint; any occupant or partial row stays Ambiguous.

## Outcome

- Signal: useful

## Source Nodes

- comparison_digest.rs
- schema.rs
- readback.rs
- CoordinatorReadbackInputV1