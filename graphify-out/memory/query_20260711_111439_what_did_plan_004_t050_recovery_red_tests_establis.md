---
type: "implementation"
date: "2026-07-11T11:14:39.696589+00:00"
question: "What did PLAN-004 T050 recovery RED tests establish?"
contributor: "graphify"
outcome: "useful"
source_nodes: ["recovery.rs", "RecoveryProviderV1", "RecoveryMaterialReceiptV1", "IrreversibilityEvidenceV1"]
---

# Q: What did PLAN-004 T050 recovery RED tests establish?

## Answer

The portable recovery corpus now executes manifest-last ordering and interruption cases, exact/minus/plus receipt capacity, signed L2 irreversibility with zero material-provider calls, and adjacent recovery first-failure ordering. Fifteen tests pass. The two intentional RED gaps are the absent RecoveryProviderProfileInputV1/RecoveryProviderProfileV1 contract and failure to classify target/precondition/boot receipt binding before material verification (row 36 must beat row 37).

## Outcome

- Signal: useful

## Source Nodes

- recovery.rs
- RecoveryProviderV1
- RecoveryMaterialReceiptV1
- IrreversibilityEvidenceV1