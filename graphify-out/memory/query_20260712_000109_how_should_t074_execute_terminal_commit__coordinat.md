---
type: "implementation"
date: "2026-07-12T00:01:09.715646+00:00"
question: "How should T074 execute terminal commit, coordinator readback, and known-failure process barriers without ambient or simulated hooks?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["CoordinatorFaultProbeV1", "readback.rs", "failure.rs", "commit_gate.rs", "t074_transactions.rs"]
---

# Q: How should T074 execute terminal commit, coordinator readback, and known-failure process barriers without ambient or simulated hooks?

## Answer

Use a feature-only opaque coordinator probe selected from the closed transactional partition; keep ordinary wrappers disabled. Seed deterministic real SQLite fixtures before READY: uncertain committed/rolled-back and exact/conflicting candidates for all five readback classes, and a committed PREPARING compensation row for known failure. Carry separate coordinator and portable caller-owned probes through probe-aware wrappers, release the same synthetic no-dispatch guard through the portable helper, and drive aborted/ambiguous through FaultProbedFinalCommitPermitV1 with ConfirmedRollback/Unclassified. The isolated 21-ID runner tests pass 5/5; plan-preparation lib passes 22/22 and coordinator lib passes 123/123.

## Outcome

- Signal: useful

## Source Nodes

- CoordinatorFaultProbeV1
- readback.rs
- failure.rs
- commit_gate.rs
- t074_transactions.rs