---
type: "query"
date: "2026-07-10T16:48:49.309895+00:00"
question: "How must a replay claim attempt identity be generated and interpreted?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["ClaimAttemptV1", "ClaimIoV1", "ReplayClaimReceiptV1"]
---

# Q: How must a replay claim attempt identity be generated and interpreted?

## Answer

Generate a fresh OS-random 32-byte value for every mutation attempt, domain-hash it into claim_id, and never derive it only from the binding. Exact readback is positive only when both uniqueness keys, binding digest, generation and this candidate claim_id agree in one healthy fresh view; uncertainty is never retried blindly.

## Outcome

- Signal: useful

## Source Nodes

- ClaimAttemptV1
- ClaimIoV1
- ReplayClaimReceiptV1