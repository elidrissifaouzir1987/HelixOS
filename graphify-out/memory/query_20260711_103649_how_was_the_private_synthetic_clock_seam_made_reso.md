---
type: "implementation"
date: "2026-07-11T10:36:49.833344+00:00"
question: "How was the private synthetic clock seam made resolvable in both the real coordinator crate and source-included integration tests?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["lib.rs", "commit_synthetic_preparation_until_v1", "CoordinatorMonotonicClockV1"]
---

# Q: How was the private synthetic clock seam made resolvable in both the real coordinator crate and source-included integration tests?

## Answer

The crate now aliases itself as helix_coordinator_sqlite immediately after its crate docs. The private cfg-test seam can therefore use one absolute trait path in the real lib-test and every source-included integration test. Coordinator lib (34), preparation (15), contention normal (12), and deadline normal (12) all pass.

## Outcome

- Signal: useful

## Source Nodes

- lib.rs
- commit_synthetic_preparation_until_v1
- CoordinatorMonotonicClockV1