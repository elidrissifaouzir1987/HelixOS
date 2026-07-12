---
type: "correction"
date: "2026-07-11T05:26:05.444726+00:00"
question: "Feature 004 T026 downstream harness dependency boundary"
contributor: "graphify"
outcome: "corrected"
correction: "Do not add helix-plan-eligibility to coordinator dev-dependencies or source-include the upstream common module; that violates the reviewed consumer allowlist. Keep downstream fixtures self-contained and non-authoritative."
source_nodes: ["SyntheticCoordinatorRootV1", "SyntheticCoordinatorClockV1", "SyntheticHistoricalPlanKeyResolverV1", "BudgetVectorV1"]
---

# Q: Feature 004 T026 downstream harness dependency boundary

## Answer

The coordinator SQLite test harness is autonomous: it does not source-include the upstream preparation harness and has no direct helix-plan-eligibility dependency. It uses frozen public-synthetic budget values, a local injected coordinator clock, fixed public-synthetic historical verification bytes, SQLite/recovery roots and provenance fixtures. Coordinator harness passes 4/4, coordinator check and all-tests no-run pass, and the eligibility portability allowlist passes 6/6.

## Outcome

- Signal: corrected
- Correction: Do not add helix-plan-eligibility to coordinator dev-dependencies or source-include the upstream common module; that violates the reviewed consumer allowlist. Keep downstream fixtures self-contained and non-authoritative.

## Source Nodes

- SyntheticCoordinatorRootV1
- SyntheticCoordinatorClockV1
- SyntheticHistoricalPlanKeyResolverV1
- BudgetVectorV1