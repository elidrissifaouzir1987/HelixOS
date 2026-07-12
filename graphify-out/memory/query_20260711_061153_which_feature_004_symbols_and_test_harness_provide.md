---
type: "query"
date: "2026-07-11T06:11:53.653224+00:00"
question: "Which Feature 004 symbols and test harness providers govern preliminary and final authority freshness comparison for T028?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["ReadyPreparationContextV1", "SyntheticPreparationAuthorityV1", "SyntheticAuthorityGuardSetV1", "DeterministicPreparationClockV1", "build_ready_context_v1()", "EligiblePlanV1"]
---

# Q: Which Feature 004 symbols and test harness providers govern preliminary and final authority freshness comparison for T028?

## Answer

T028 is centered on ReadyPreparationContextV1 in context.rs and the deterministic harness in tests/common/mod.rs: SyntheticPreparationAuthorityV1 captures preliminary and final snapshots, SyntheticAuthorityGuardSetV1 holds final guards, DeterministicPreparationClockV1 supplies injected time, and build_ready_context_v1 constructs coherent inputs. Exact replay remains an independent eligibility verification seam.

## Outcome

- Signal: useful

## Source Nodes

- ReadyPreparationContextV1
- SyntheticPreparationAuthorityV1
- SyntheticAuthorityGuardSetV1
- DeterministicPreparationClockV1
- build_ready_context_v1()
- EligiblePlanV1