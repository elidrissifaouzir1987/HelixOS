---
type: "query"
date: "2026-07-10T16:48:49.151606+00:00"
question: "What authority does the durable replay store grant?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["SqliteReplayClaimantV1", "ReplayClaimantV1", "EligiblePlanV1"]
---

# Q: What authority does the durable replay store grant?

## Answer

It grants no execution or adapter authority. It is a removable ReplayClaimantV1 provider whose receipt is only a point-in-time eligibility prerequisite; approval, preparation, budgets, grants, dispatch and effects remain later typed boundaries.

## Outcome

- Signal: useful

## Source Nodes

- SqliteReplayClaimantV1
- ReplayClaimantV1
- EligiblePlanV1