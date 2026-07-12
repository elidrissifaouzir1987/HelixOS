---
type: "implementation"
date: "2026-07-11T04:30:16.083448+00:00"
question: "How did Feature 004 add exact replay verification without widening replay claim authority?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["ReplayClaimVerificationViewV1", "ReplayClaimVerifierV1", "ReplayClaimantV1", "EligiblePlanV1"]
---

# Q: How did Feature 004 add exact replay verification without widening replay claim authority?

## Answer

T010 first failed as expected with E0432 because the verification view, five-class outcome, and verifier trait were absent. T012 then added an opaque borrowed ReplayClaimVerificationViewV1 created only by EligiblePlanV1, including the direct nonce namespace key plus exact operation, claim, generation, and binding getters; a read-only one-method ReplayClaimVerifierV1; and the closed Exact/Missing/Conflict/Unavailable/Unhealthy outcome. The eligibility T014 gate proves the verifier is separate from claim_once, has no mutation/release surface, and the existing ReplayClaimantV1 still has exactly one method. Locked check, strict clippy, targeted tests, and the full eligibility suite pass.

## Outcome

- Signal: useful

## Source Nodes

- ReplayClaimVerificationViewV1
- ReplayClaimVerifierV1
- ReplayClaimantV1
- EligiblePlanV1