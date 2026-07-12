---
type: "query"
date: "2026-07-11T00:11:03.733663+00:00"
question: "Phase 0 technical context and project structure for PLAN-004 durable preparation"
contributor: "graphify"
outcome: "useful"
source_nodes: ["EligiblePlanV1", "ReadyEligibilityContextV1", "PlanEligibilityBudgetClaimsV1", "ReplayClaimReceiptV1", "SqliteReplayClaimantV1", "ReplayStoreConfigV1", "BackupManifestV1"]
---

# Q: Phase 0 technical context and project structure for PLAN-004 durable preparation

## Answer

Expanded from graph vocabulary: [workspace, crate, rust, toolchain, storage, sqlite, test, testing, platform, source, preparation, recovery]. Recommend one synchronous Rust 2021 coordinator-storage leaf, preferably helix-coordinator-sqlite, on exact Rust 1.96.1 with no lower MSRV claim. Reuse helix-contracts and helix-plan-eligibility APIs; use exact rusqlite 0.40.1 bundled+backup, libsqlite3-sys 0.38.1/SQLite 3.53.2, getrandom 0.4.3, serde 1.0.228, serde_json 1.0.150 and sha2 0.10.9. Keep the replay SQLite store and legacy kernel out of the production dependency graph. Use a separate coordinator database/root with WAL/FULL and atomic operation+budget+preparation-event rows; external recovery and supervisor remain receipt/guard domains. Missing decisions are budget-account provisioning, read-only durable replay receipt verification, exact-repeat positive-marker semantics, quarantine representation, protected plan-data storage/backup, and cross-domain recovery manifest linkage.

## Outcome

- Signal: useful

## Source Nodes

- EligiblePlanV1
- ReadyEligibilityContextV1
- PlanEligibilityBudgetClaimsV1
- ReplayClaimReceiptV1
- SqliteReplayClaimantV1
- ReplayStoreConfigV1
- BackupManifestV1