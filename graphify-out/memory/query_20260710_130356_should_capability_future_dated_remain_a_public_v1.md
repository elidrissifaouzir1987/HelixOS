---
type: "contract-audit"
date: "2026-07-10T13:03:56.584331+00:00"
question: "Should CAPABILITY_FUTURE_DATED remain a public v1 eligibility denial?"
contributor: "graphify"
outcome: "dead_end"
source_nodes: ["EligibilityDenialV1", "PlanEligibilityClaimsV1", "policy_and_capabilities.rs", "conformance_cases.rs"]
---

# Q: Should CAPABILITY_FUTURE_DATED remain a public v1 eligibility denial?

## Answer

No. Feature 001 proves capability_observed_at is at or before plan issuance; feature 002 proves issuance is at or before evaluation and requires the current observation to equal the protected value. A future protected observation is therefore unreachable. A context-only future timestamp already denies as CAPABILITY_OBSERVATION_MISMATCH. The dead code was removed, leaving 100 reachable runtime denials and an exhaustive 106-case corpus.

## Outcome

- Signal: dead_end

## Source Nodes

- EligibilityDenialV1
- PlanEligibilityClaimsV1
- policy_and_capabilities.rs
- conformance_cases.rs