---
type: "implementation"
date: "2026-07-11T11:40:32.770855+00:00"
question: "How does PLAN-004 T060 retain recovery publication custody across commit and explicit uncertain readback?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["prepare_plan_v1", "RecoveryCustodyV1"]
---

# Q: How does PLAN-004 T060 retain recovery publication custody across commit and explicit uncertain readback?

## Answer

The portable coordinator owns a material publication guard inside RecoveryCustodyV1 from successful manifest-last publication through final binding/material revalidation, commit_preparing, and the single explicit UNCERTAIN readback classification. It releases authority guards in reverse order and then the recovery guard before prepare_plan_v1 returns. Irreversible authenticated L2 uses no-material evidence and makes zero provider calls. Rows 34-38 remain ordered as profile, definite provider failure, binding conflict, unverified material, then ambiguous publication. T050 remains 17/17 and now probes live custody at commit/readback, including unavailable readback leading to Ambiguous; freshness is 22/22, package tests and strict Clippy pass. The public PreparationOutcomeV1 intentionally cannot retain a guard after return; durable quarantine/reconciliation is the post-return custody mechanism.

## Outcome

- Signal: useful

## Source Nodes

- prepare_plan_v1
- RecoveryCustodyV1