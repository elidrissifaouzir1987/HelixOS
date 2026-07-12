---
type: "query"
date: "2026-07-10T23:52:24.139138+00:00"
question: "What is the closed PLAN-004 durable preparation boundary?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["EligiblePlanV1", "PlanEligibilityBudgetClaimsV1", "ReplayClaimReceiptV1"]
---

# Q: What is the closed PLAN-004 durable preparation boundary?

## Answer

PLAN-004 consumes one EligiblePlanV1, performs complete preliminary and final transaction-or-guard comparison without reclaiming replay, verifies an environment-approved recovery receipt, and commits PREPARING with the exact plan-v1 cost, action, egress and recovery-byte reservations plus one preparation event. Independent supervisor, recovery and coordinator stores remain separate receipt-and-guard domains. Synthetic recovery proves protocol conformance only, restored old preparation can never reactivate, and the feature ends before DISPATCHING, ExecutionGrant, adapter input or host effects.

## Outcome

- Signal: useful

## Source Nodes

- EligiblePlanV1
- PlanEligibilityBudgetClaimsV1
- ReplayClaimReceiptV1