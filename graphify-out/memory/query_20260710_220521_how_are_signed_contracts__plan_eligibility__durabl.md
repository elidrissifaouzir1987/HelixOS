---
type: "query"
date: "2026-07-10T22:05:21.345344+00:00"
question: "How are signed contracts, plan eligibility, durable replay, and the runnable kernel connected before baseline tests?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["AuthenticPlanEnvelopeV1", "EligiblePlanV1", "ReplayClaimReceiptV1", "SqliteReplayClaimantV1", "Kernel"]
---

# Q: How are signed contracts, plan eligibility, durable replay, and the runnable kernel connected before baseline tests?

## Answer

Expanded from the original query via graph vocabulary: contracts, signed, plan, eligibility, eligible, replay, claimant, sqlite, kernel, runtime, pipeline. Structural traversal found AuthenticPlanEnvelopeV1 directly referenced by EligiblePlanV1; EligiblePlanV1 connects through ReplayClaimReceiptV1 and test readback to SqliteReplayClaimantV1; the shortest surfaced route from SqliteReplayClaimantV1 to the legacy Kernel is seven indirect hops through generic and test symbols, with no direct production integration edge in this graph. Treat the three trust crates as an integrated trust chain but the runnable legacy Kernel as not directly wired to that chain.

## Outcome

- Signal: useful

## Source Nodes

- AuthenticPlanEnvelopeV1
- EligiblePlanV1
- ReplayClaimReceiptV1
- SqliteReplayClaimantV1
- Kernel