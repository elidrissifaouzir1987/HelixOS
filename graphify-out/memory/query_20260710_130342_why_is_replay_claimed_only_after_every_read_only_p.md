---
type: "architecture"
date: "2026-07-10T13:03:42.211735+00:00"
question: "Why is replay claimed only after every read-only plan-eligibility gate, and what authority does success carry?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["evaluate_and_claim_plan_v1", "ReplayClaimantV1", "EligiblePlanV1", "0006-current-plan-eligibility.md"]
---

# Q: Why is replay claimed only after every read-only plan-eligibility gate, and what authority does success carry?

## Answer

Feature 002 evaluates the explicit core-owned snapshot in frozen fail-closed order, then calls ReplayClaimantV1::claim_once exactly once as the final external operation. Pre-claim denials consume no replay state. EligiblePlanV1 owns the authentic plan, evaluated bounds, comparison vector, and matching receipt, but remains only a point-in-time prerequisite: it is not approval, durable preparation, an ExecutionGrant, an adapter input, or host-effect authority.

## Outcome

- Signal: useful

## Source Nodes

- evaluate_and_claim_plan_v1
- ReplayClaimantV1
- EligiblePlanV1
- 0006-current-plan-eligibility.md