---
type: "query"
date: "2026-07-11T01:04:45.902989+00:00"
question: "What is the final PLAN-004 durable preparation design?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["EligiblePlanV1", "ReplayClaimReceiptV1", "PlanEligibilityBudgetClaimsV1", "SqliteReplayClaimantV1"]
---

# Q: What is the final PLAN-004 durable preparation design?

## Answer

PLAN-004 uses a portable preparation protocol plus a separate SQLite coordinator store. It verifies replay before any budget or recovery work, preflights operation and budget authority, publishes guarded recovery evidence, repeats the full comparison under ordered guards, and holds a supervisor-owned bounded commit permit across the atomic PREPARING, transition, budget and event commit. Owner loss becomes ambiguous PAUSE with exact readback. Recovery retirement is tombstoned, backups use a sorted multi-provider inventory, restored work never reactivates, and v1 has no pruning or dispatch authority.

## Outcome

- Signal: useful

## Source Nodes

- EligiblePlanV1
- ReplayClaimReceiptV1
- PlanEligibilityBudgetClaimsV1
- SqliteReplayClaimantV1