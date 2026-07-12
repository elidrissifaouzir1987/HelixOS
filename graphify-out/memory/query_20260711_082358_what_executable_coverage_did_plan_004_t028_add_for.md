---
type: "implementation"
date: "2026-07-11T08:23:58.997381+00:00"
question: "What executable coverage did PLAN-004 T028 add for freshness ordering?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["freshness.rs", "SyntheticPreparationAuthorityV1", "ScriptedPreparationStore", "ScriptedReplayVerifier", "SyntheticConformanceRecoveryProviderV1"]
---

# Q: What executable coverage did PLAN-004 T028 add for freshness ordering?

## Answer

The public prepare_plan_v1 seam now has a table-driven injectable harness covering all normative rows 1-45 at least once, preliminary/final cases wherever the phase exists, 23 independently injectable adjacent dual-fault pairs selected by production ordering, exact replay identity across an unrelated global-generation advance, exclusive UTC/monotonic equality with bound-minus-one positives, exact ambiguous variants, call counts, recovery publication counts, generation deltas, permit state, and non-retry behavior. Targeted freshness, harness, revocation, fault-injection, fmt, and Clippy -D warnings checks pass. Mutually exclusive provider/store classification variants and malformed validating-constructor versions remain adapter/corpus gaps rather than being faked in the mock.

## Outcome

- Signal: useful

## Source Nodes

- freshness.rs
- SyntheticPreparationAuthorityV1
- ScriptedPreparationStore
- ScriptedReplayVerifier
- SyntheticConformanceRecoveryProviderV1